"""Bounded TLS/SOCKS framing shared by Smart DNS gateway and exit node.

The customer's TLS stream is forwarded unchanged. Neither endpoint holds an
origin certificate or decrypts customer application data.
"""

import asyncio
import ipaddress
import socket
import ssl

from .dns_policy import DNSRule

MAX_HELLO = 32768


def domain(value):
    name = DNSRule(domain=value, action="allow").domain
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("An explicit DNS name is required")


def client_name(hello):
    """Parse one complete ClientHello handshake; reject ECH and ambiguous SNI."""

    def take(data, offset, length):
        if offset + length > len(data):
            raise ValueError("Truncated ClientHello")
        return data[offset : offset + length], offset + length

    if (
        len(hello) < 4
        or hello[0] != 1
        or int.from_bytes(hello[1:4], "big") != len(hello) - 4
    ):
        raise ValueError("Invalid ClientHello")
    data, at = hello[4:], 34
    raw, at = take(data, at, 1)
    _, at = take(data, at, raw[0])
    raw, at = take(data, at, 2)
    _, at = take(data, at, int.from_bytes(raw, "big"))
    raw, at = take(data, at, 1)
    _, at = take(data, at, raw[0])
    raw, at = take(data, at, 2)
    extensions, end = take(data, at, int.from_bytes(raw, "big"))
    if end != len(data):
        raise ValueError("Trailing ClientHello data")
    at, names, seen = 0, [], set()
    while at < len(extensions):
        raw, at = take(extensions, at, 4)
        kind, length = int.from_bytes(raw[:2], "big"), int.from_bytes(raw[2:], "big")
        value, at = take(extensions, at, length)
        if kind in seen or kind in (0xFE0D, 0xFFCE):
            raise ValueError("Duplicate extension or encrypted client name")
        seen.add(kind)
        if kind == 0:
            if len(value) < 5 or int.from_bytes(value[:2], "big") != len(value) - 2:
                raise ValueError("Invalid server-name list")
            pos = 2
            while pos < len(value):
                raw, pos = take(value, pos, 3)
                name, pos = take(value, pos, int.from_bytes(raw[1:], "big"))
                if raw[0] != 0:
                    raise ValueError("Unsupported server-name type")
                names.append(domain(name.decode("ascii")))
    if len(names) != 1:
        raise ValueError("One clear server name is required")
    return names[0]


async def read_hello(reader):
    wire, handshake = bytearray(), bytearray()
    async with asyncio.timeout(5):
        for _ in range(32):
            header = await reader.readexactly(5)
            length = int.from_bytes(header[3:], "big")
            if header[0] != 22 or header[1] != 3 or not 1 <= length <= 16384:
                raise ValueError("Expected TLS handshake record")
            record = await reader.readexactly(length)
            wire.extend(header + record)
            handshake.extend(record)
            if len(wire) > MAX_HELLO:
                raise ValueError("ClientHello size limit")
            if len(handshake) >= 4:
                required = 4 + int.from_bytes(handshake[1:4], "big")
                if required > MAX_HELLO:
                    raise ValueError("ClientHello size limit")
                if len(handshake) >= required:
                    return client_name(bytes(handshake[:required])), bytes(wire)
    raise ValueError("ClientHello record limit")


async def close(writer):
    if writer:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, TimeoutError):
            pass


async def public_destination(host):
    # Resolve once, validate every result, then connect the selected literal IP.
    # No second DNS lookup may replace that address with an internal target.
    values = await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(
            domain(host), 443, type=socket.SOCK_STREAM
        ),
        3,
    )
    addresses = []
    for _, _, _, _, address in values:
        ip = ipaddress.ip_address(address[0])
        if (
            not ip.is_global
            or ip.is_multicast
            or getattr(ip, "ipv4_mapped", None)
            or getattr(ip, "sixtofour", None)
            or getattr(ip, "teredo", None)
        ):
            raise ValueError("Nonpublic origin refused")
        addresses.append(str(ip))
    if not addresses:
        raise ValueError("Origin has no public address")
    return addresses[0]


async def socks_auth(reader, writer, username, password):
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    if await reader.readexactly(2) != b"\x05\x02":
        raise ValueError("SOCKS authentication required")
    user, secret = username.encode(), password.encode()
    writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    await writer.drain()
    if await reader.readexactly(2) != b"\x01\x00":
        raise ValueError("SOCKS authentication failed")


async def connect_exit(config, host=None, ca=None):
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    writer = None
    try:
        async with asyncio.timeout(5):
            reader, writer = await asyncio.open_connection(
                config["host"],
                config["port"],
                ssl=context,
                server_hostname=config["sni"],
                ssl_handshake_timeout=3,
            )
            await socks_auth(reader, writer, config["username"], config["password"])
            if host is not None:
                name = domain(host).encode("ascii")
                writer.write(
                    b"\x05\x01\x00\x03" + bytes([len(name)]) + name + b"\x01\xbb"
                )
                await writer.drain()
                reply = await reader.readexactly(4)
                if reply != b"\x05\x00\x00\x01":
                    raise ValueError("Exit refused origin")
                await reader.readexactly(6)
            return reader, writer
    except BaseException:
        await close(writer)
        raise
