"""Optional authenticated TLS SOCKS exit for the Smart DNS gateway.

Only CONNECT to port 443 and configured public domain suffixes is accepted.
Provision this role explicitly; this command never changes routes/firewalls.
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import ssl
from pathlib import Path

import dns.name

from app.dns_policy import rule_for
from app.smart_wire import close, domain, public_destination


class ExitServer:
    def __init__(
        self, config, resolve=public_destination, dial=asyncio.open_connection
    ):
        self.config, self.resolve, self.dial = config, resolve, dial
        self.tasks = set()
        self.slots = asyncio.Semaphore(128)
        self.rules = [{"domain": domain(d)} for d in config["domains"]]
        if not self.rules or len(self.rules) > 2000:
            raise ValueError("Explicit allowed domains are required")

    async def handle(self, reader, writer):
        if self.slots.locked():
            await close(writer)
            return
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream = None
        try:
            async with self.slots:
                async with asyncio.timeout(5):
                    greeting = await reader.readexactly(2)
                    if greeting[0] != 5 or not 1 <= greeting[1] <= 16:
                        return
                    if 2 not in await reader.readexactly(greeting[1]):
                        writer.write(b"\x05\xff")
                        await writer.drain()
                        return
                    writer.write(b"\x05\x02")
                    await writer.drain()
                    version, length = await reader.readexactly(2)
                    if version != 1 or not length:
                        return
                    username = await reader.readexactly(length)
                    secret = await reader.readexactly((await reader.readexactly(1))[0])
                    valid_user = hmac.compare_digest(
                        username, self.config["username"].encode()
                    )
                    valid_secret = hmac.compare_digest(
                        hashlib.sha256(secret).hexdigest(), self.config["password_hash"]
                    )
                    writer.write(
                        b"\x01\x00" if valid_user and valid_secret else b"\x01\x01"
                    )
                    await writer.drain()
                    if not (valid_user and valid_secret):
                        return
                    if await reader.readexactly(4) != b"\x05\x01\x00\x03":
                        return
                    host = domain(
                        (
                            await reader.readexactly((await reader.readexactly(1))[0])
                        ).decode("ascii")
                    )
                    if await reader.readexactly(2) != b"\x01\xbb" or not rule_for(
                        dns.name.from_text(host), self.rules
                    ):
                        return
                    address = await self.resolve(host)
                    origin, upstream = await self.dial(address, 443)
                    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()

                async def pump(source, target):
                    while data := await asyncio.wait_for(source.read(16384), 90):
                        target.write(data)
                        await asyncio.wait_for(target.drain(), 5)

                flows = [
                    asyncio.create_task(pump(reader, upstream)),
                    asyncio.create_task(pump(origin, writer)),
                ]
                try:
                    async with asyncio.timeout(86400):
                        done, _ = await asyncio.wait(
                            flows, return_when=asyncio.FIRST_COMPLETED
                        )
                        for flow in done:
                            flow.result()
                finally:
                    for flow in flows:
                        flow.cancel()
                    await asyncio.gather(*flows, return_exceptions=True)
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            await close(upstream)
            await close(writer)
            self.tasks.discard(task)

    async def stop(self):
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


async def serve(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["tls_cert"], config["tls_key"])
    handler = ExitServer(config)
    server = await asyncio.start_server(
        handler.handle,
        config["listen"],
        config["port"],
        ssl=context,
        ssl_handshake_timeout=5,
        ssl_shutdown_timeout=1,
    )
    try:
        await asyncio.Event().wait()
    finally:
        server.close()
        await server.wait_closed()
        await handler.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser(
        "init",
        help="Write a private configuration; show the new gateway credential once",
    )
    init.add_argument("destination", type=Path)
    init.add_argument("--listen", default="127.0.0.1")
    init.add_argument("--port", type=int, default=9445)
    init.add_argument("--tls-cert", required=True)
    init.add_argument("--tls-key", required=True)
    init.add_argument("--domain", action="append", required=True)
    run = sub.add_parser("run")
    run.add_argument("config", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        import ipaddress

        ipaddress.ip_address(args.listen)
        if not 1 <= args.port <= 65535 or not all(
            Path(p).is_absolute() for p in (args.tls_cert, args.tls_key)
        ):
            parser.error("Use a valid port and absolute TLS paths")
        password, username = secrets.token_urlsafe(32), secrets.token_hex(12)
        config = {
            "listen": args.listen,
            "port": args.port,
            "tls_cert": args.tls_cert,
            "tls_key": args.tls_key,
            "domains": sorted({domain(d) for d in args.domain}),
            "username": username,
            "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        }
        args.destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            json.dump(config, file)
        print(json.dumps({"username": username, "password": password}))
    else:
        info = args.config.stat()
        if info.st_mode & 0o077:
            parser.error("Exit configuration must be private (0600)")
        asyncio.run(serve(json.loads(args.config.read_text())))


if __name__ == "__main__":
    main()
