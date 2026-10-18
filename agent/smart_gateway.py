"""Opt-in same-control-host Smart DNS TLS passthrough gateway."""

import argparse
import asyncio
import ipaddress
import os
import signal
import uuid

from fastapi import HTTPException

from app import smart_dns
from app.db import database, initialize
from app.dns_service import canonical_address
from app.smart_wire import close, connect_exit, read_hello


class Gateway:
    def __init__(self, *, proxy_protocol=False, limit=128):
        self.proxy_protocol = proxy_protocol
        self.slots = asyncio.Semaphore(limit)
        self.tasks = set()

    async def source(self, reader, writer):
        source = str(canonical_address(writer.get_extra_info("peername")[0]))
        if not self.proxy_protocol:
            return source
        if not ipaddress.ip_address(source).is_loopback:
            raise ValueError("PROXY metadata is trusted only from a local frontend")
        line = bytearray()
        async with asyncio.timeout(3):
            while not line.endswith(b"\r\n"):
                line += await reader.readexactly(1)
                if len(line) > 108:
                    raise ValueError("PROXY header too large")
        parts = line.decode("ascii").strip().split()
        if len(parts) != 6 or parts[:2] not in (["PROXY", "TCP4"], ["PROXY", "TCP6"]):
            raise ValueError("Strict PROXY v1 is required")
        ip = ipaddress.ip_address(parts[2])
        target = ipaddress.ip_address(parts[3])
        version = 4 if parts[1] == "TCP4" else 6
        if (
            ip.version != version
            or target.version != version
            or not all(1 <= int(p) <= 65535 for p in parts[4:])
        ):
            raise ValueError("Invalid PROXY address family or port")
        return str(canonical_address(str(ip)))

    async def handle(self, reader, writer):
        if self.slots.locked():
            await close(writer)
            return
        task = asyncio.current_task()
        self.tasks.add(task)
        session, remote, flows, error = None, None, [], None
        try:
            async with self.slots:
                source = await self.source(reader, writer)

                def authorized():
                    with database() as db:
                        smart_dns._account(db, source)

                await asyncio.to_thread(authorized)
                host, initial = await read_hello(reader)
                session = await asyncio.to_thread(smart_dns.admit, source, host)
                # Only fail over before any customer TLS bytes are forwarded.
                for node in session["exits"]:
                    await asyncio.to_thread(smart_dns.connecting, session)
                    started = asyncio.get_running_loop().time()
                    try:
                        config = await asyncio.to_thread(smart_dns.private_exit, node)
                        upstream, remote = await connect_exit(
                            config, host, os.environ.get("DONINO_SMART_DNS_CA") or None
                        )
                        await asyncio.to_thread(
                            smart_dns.selected, session, node["id"], node["revision"]
                        )
                        session["exit_revision"] = node["revision"]
                        await asyncio.to_thread(
                            smart_dns.health,
                            node["id"],
                            node["revision"],
                            True,
                            (asyncio.get_running_loop().time() - started) * 1000,
                        )
                        break
                    except (
                        OSError,
                        ValueError,
                        TimeoutError,
                        asyncio.IncompleteReadError,
                        HTTPException,
                    ):
                        await close(remote)
                        remote = None
                        await asyncio.to_thread(
                            smart_dns.health, node["id"], node["revision"], False
                        )
                if remote is None:
                    raise ValueError("All configured exits failed")
                await asyncio.to_thread(smart_dns.charge, session, "up", len(initial))
                remote.write(initial)
                await asyncio.wait_for(remote.drain(), 5)

                async def pump(incoming, outgoing, direction):
                    while data := await asyncio.wait_for(incoming.read(16384), 90):
                        await asyncio.to_thread(
                            smart_dns.charge, session, direction, len(data)
                        )
                        outgoing.write(data)
                        await asyncio.wait_for(outgoing.drain(), 5)

                async def watch():
                    while True:
                        await asyncio.sleep(1)
                        await asyncio.to_thread(smart_dns.charge, session, "up", 0)

                flows = [
                    asyncio.create_task(pump(reader, remote, "up")),
                    asyncio.create_task(pump(upstream, writer, "down")),
                    asyncio.create_task(watch()),
                ]
                async with asyncio.timeout(86400):
                    done, _ = await asyncio.wait(
                        flows, return_when=asyncio.FIRST_COMPLETED
                    )
                    for flow in done:
                        flow.result()
        except HTTPException:
            error = "access_or_quota_revoked"
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
            error = "connection_failed"
        except Exception:
            error = "internal_error"
        finally:
            for flow in flows:
                flow.cancel()
            await asyncio.gather(*flows, return_exceptions=True)
            await close(remote)
            await close(writer)
            if session:
                try:
                    await asyncio.to_thread(smart_dns.finish, session, error)
                except Exception:
                    pass  # A DB outage cannot leave an authorized open stream.
            self.tasks.discard(task)

    async def stop(self):
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


async def serve(args):
    if not smart_dns.enabled() or not smart_dns.front_addresses():
        raise ValueError(
            "Explicit Smart DNS activation and front addresses are required"
        )
    if args.proxy_protocol and not ipaddress.ip_address(args.listen).is_loopback:
        raise ValueError("PROXY protocol requires a loopback listener")
    gateway = Gateway(proxy_protocol=args.proxy_protocol)
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    server = await asyncio.start_server(gateway.handle, args.listen, args.port)
    instance = uuid.uuid4().hex
    try:
        while True:
            await asyncio.to_thread(smart_dns.heartbeat, instance)
            await asyncio.sleep(3)
    finally:
        server.close()
        await server.wait_closed()
        await gateway.stop()
        with database() as db:
            db.execute("DELETE FROM smart_gateway WHERE instance_id=?", (instance,))
        loop.remove_signal_handler(signal.SIGTERM)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", type=ipaddress.ip_address, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--proxy-protocol", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Invalid listen port")
    args.listen = str(args.listen)
    initialize()
    try:
        asyncio.run(serve(args))
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    main()
