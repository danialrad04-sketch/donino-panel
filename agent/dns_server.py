"""Optional same-host DNS gateway. Socket-source leases authorize UDP/TCP/DoT.

Uses the control host's database and a loopback validating Unbound upstream.
Remote-node signed DNS deployment and DoQ are separate, unfinished work.
"""

import argparse
import asyncio
import ipaddress
import os
import ssl
import struct

from fastapi import HTTPException

from app.db import initialize
from app.dns_service import DNSService


class DatagramGateway(asyncio.DatagramProtocol):
    def __init__(self, service, limit=64):
        self.service, self.limit = service, limit
        self.pending = set()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(self.pending) >= self.limit or not 12 <= len(data) <= 4096:
            return
        task = asyncio.create_task(self.answer(data, addr))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def answer(self, data, addr):
        try:
            response = await asyncio.to_thread(
                self.service.answer, data, source_ip=addr[0], udp=True
            )
            if self.transport and not self.transport.is_closing():
                self.transport.sendto(response, addr)
        except (HTTPException, ValueError, OSError):
            pass  # Unauthorized UDP receives no reflection/amplification response.

    async def close(self):
        if self.transport:
            self.transport.close()
        if self.pending:
            await asyncio.gather(*self.pending, return_exceptions=True)


class StreamGateway:
    def __init__(self, service, limit=32):
        self.service = service
        self.slots = asyncio.Semaphore(limit)

    async def handle(self, reader, writer):
        if self.slots.locked():
            writer.close()
            return
        try:
            async with self.slots:
                peer = writer.get_extra_info("peername")
                for _ in range(100):
                    header = await asyncio.wait_for(reader.readexactly(2), timeout=5)
                    size = struct.unpack("!H", header)[0]
                    if not 12 <= size <= 4096:
                        return
                    wire = await asyncio.wait_for(reader.readexactly(size), timeout=5)
                    output = await asyncio.to_thread(
                        self.service.answer, wire, source_ip=peer[0]
                    )
                    writer.write(struct.pack("!H", len(output)) + output)
                    await asyncio.wait_for(writer.drain(), timeout=5)
        except (
            HTTPException,
            ValueError,
            OSError,
            asyncio.IncompleteReadError,
            TimeoutError,
        ):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def serve(args):
    service = DNSService()
    gateway = DatagramGateway(service)
    stream = StreamGateway(service)
    loop = asyncio.get_running_loop()
    context = None
    if args.dot_port:
        if not args.tls_cert or not args.tls_key:
            raise ValueError("DoT requires a certificate and private key")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        context.set_alpn_protocols(["dot"])
    servers = []
    try:
        servers.append(
            await asyncio.start_server(stream.handle, args.listen, args.port)
        )
        await loop.create_datagram_endpoint(
            lambda: gateway, local_addr=(args.listen, args.port)
        )
        if context:
            servers.append(
                await asyncio.start_server(
                    stream.handle,
                    args.listen,
                    args.dot_port,
                    ssl=context,
                    ssl_handshake_timeout=5,
                )
            )
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()
        await gateway.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--listen",
        default=os.environ.get("DONINO_DNS_LISTEN", "127.0.0.1"),
        type=ipaddress.ip_address,
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("DONINO_DNS_PORT", "5353"))
    )
    parser.add_argument(
        "--dot-port",
        type=int,
        default=int(os.environ["DONINO_DOT_PORT"])
        if os.environ.get("DONINO_DOT_PORT")
        else None,
    )
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or (
        args.dot_port is not None and not 1 <= args.dot_port <= 65535
    ):
        parser.error("Invalid listen port")
    args.listen = str(args.listen)
    initialize()
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
