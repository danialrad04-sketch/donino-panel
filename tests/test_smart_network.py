"""Real UDP DNS, SNI edge, TLS exits and verified HTTPS origins on loopback.

Only test fixtures inject loopback origin resolution and ephemeral dial ports.
Production exits reject private destinations and connect public literals on 443.
"""

import asyncio
import hashlib
import os
import ssl
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import dns.message
import dns.query
import dns.rcode

from agent.dns_server import DatagramGateway
from agent.smart_exit import ExitServer
from agent.smart_gateway import Gateway
from app import smart_dns
from app.db import database
from app.smart_wire import (
    client_name,
    close,
    connect_exit,
    public_destination,
    read_hello,
)
from test_xray_transports import _write_test_pki
import test_smart_dns as fixtures


class SmartNetworkTest(fixtures.SmartFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.ca, self.cert, self.key = _write_test_pki(
            Path(self.tmp.name) / "smart-pki", ("localhost", "play.example.com")
        )
        os.environ.update(
            DONINO_SMART_DNS_IPS="127.0.0.1", DONINO_SMART_DNS_CA=str(self.ca)
        )
        with database() as db:
            db.execute("UPDATE dns_ip_leases SET ip='127.0.0.1'")
        smart_dns.heartbeat("fixture")
        self.servers, self.exits, self.origins = [], [], []
        self.connections = set()
        self.origin_count = [0, 0]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(self.cert, self.key)
        self.client_context = ssl.create_default_context(cafile=str(self.ca))
        for index in range(2):

            async def origin(reader, writer, index=index):
                self.connections.add(writer)
                self.origin_count[index] += 1
                try:
                    request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                    body = ("origin-" + str(index + 1)).encode()
                    if b"/large" in request:
                        body *= 32768
                    if b"/hold" in request:
                        writer.write(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n" + body
                        )
                        await writer.drain()
                        await reader.read()
                    else:
                        writer.write(
                            b"HTTP/1.1 200 OK\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\n\r\n"
                            + body
                        )
                        await writer.drain()
                except (OSError, TimeoutError, asyncio.IncompleteReadError):
                    pass
                finally:
                    await close(writer)
                    self.connections.discard(writer)

            server = await asyncio.start_server(
                origin, "127.0.0.1", 0, ssl=self.context, ssl_shutdown_timeout=1
            )
            self.servers.append(server)
            port = server.sockets[0].getsockname()[1]

            async def resolve(host):
                self.assertEqual(host, "play.example.com")
                return "127.0.0.1"

            async def dial(address, requested, port=port):
                self.assertEqual(requested, 443)
                return await asyncio.open_connection(address, port)

            config = {
                "username": self.exit_body["username"],
                "password_hash": hashlib.sha256(
                    self.exit_body["password"].encode()
                ).hexdigest(),
                "domains": ["example.com"],
            }
            handler = ExitServer(config, resolve=resolve, dial=dial)
            self.exits.append(handler)
            server = await asyncio.start_server(
                handler.handle, "127.0.0.1", 0, ssl=self.context, ssl_shutdown_timeout=1
            )
            self.servers.append(server)
            body = {
                **self.exit_body,
                "name": f"real exit {index}",
                "port": server.sockets[0].getsockname()[1],
                "sni": "localhost",
            }
            if index == 0:
                row = self.client.put(
                    "/api/dns/smart/exits/" + self.exit["id"],
                    headers=self.headers,
                    json={**body, "username": "", "password": ""},
                ).json()
            else:
                row = self.post("/dns/smart/exits", body).json()
            probed = await asyncio.to_thread(
                self.post, "/dns/smart/exits/" + row["id"] + "/probe"
            )
            self.assertTrue(probed.json()["ok"], probed.text)
            self.assertFalse(probed.json()["application_verified"])
            enabled = self.client.put(
                "/api/dns/smart/exits/" + row["id"],
                headers=self.headers,
                json={**body, "password": "", "username": "", "mode": "active"},
            )
            self.assertEqual(enabled.status_code, 200, enabled.text)
            self.origins.append(enabled.json())
        self.rules[0]["exit_ids"] = [r["id"] for r in self.origins]
        self.update_policy(self.rules)
        self.gateway = Gateway()
        server = await asyncio.start_server(self.gateway.handle, "127.0.0.1", 0)
        self.servers.append(server)
        self.gateway_port = server.sockets[0].getsockname()[1]
        from app.dns_service import DNSService

        self.dns = DatagramGateway(DNSService())
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: self.dns, local_addr=("127.0.0.1", 0)
        )
        self.dns_port = transport.get_extra_info("sockname")[1]

        async def heartbeat():
            while True:
                await asyncio.to_thread(smart_dns.heartbeat, "fixture")
                await asyncio.sleep(2)

        self.heartbeat = asyncio.create_task(heartbeat())

    async def asyncTearDown(self):
        self.heartbeat.cancel()
        await asyncio.gather(self.heartbeat, return_exceptions=True)
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        await self.dns.close()
        await self.gateway.stop()
        for handler in self.exits:
            await handler.stop()
        for writer in list(self.connections):
            await close(writer)

    def update_policy(self, rules):
        result = self.client.put(
            "/api/dns/policies/" + self.policy["id"],
            headers=self.headers,
            json={"name": "smart", "rules": rules},
        )
        self.assertEqual(result.status_code, 200, result.text)

    async def query(self):
        return await asyncio.to_thread(
            dns.query.udp,
            dns.message.make_query("play.example.com", "A"),
            "127.0.0.1",
            port=self.dns_port,
            timeout=3,
        )

    async def request(self, path="/", host="play.example.com"):
        response = await self.query()
        self.assertEqual(response.answer[0][0].address, "127.0.0.1")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                response.answer[0][0].address,
                self.gateway_port,
                ssl=self.client_context,
                server_hostname=host,
            ),
            7,
        )
        try:
            writer.write(
                b"GET "
                + path.encode()
                + b" HTTP/1.1\r\nHost: "
                + host.encode()
                + b"\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            if path == "/hold":
                header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                marker = await asyncio.wait_for(reader.readexactly(8), 5)
                return reader, writer, header + marker
            return await asyncio.wait_for(reader.read(), 7)
        finally:
            if path != "/hold":
                await close(writer)

    async def test_real_dns_tls_exit_switch_and_separate_accounting(self):
        self.assertIn(b"origin-1", await self.request())
        self.rules[0]["exit_ids"].reverse()
        self.update_policy(self.rules)
        self.assertIn(b"origin-2", await self.request())
        with database() as db:
            self.assertGreater(
                db.execute("SELECT relay_up+relay_down FROM dns_periods").fetchone()[0],
                0,
            )
            self.assertEqual(db.execute("SELECT used FROM users").fetchone()[0], 0)
        self.assertNotIn(
            "play.example.com", self.client.get("/api/dns/smart/sessions").text
        )

    async def test_actual_primary_loss_failover_and_both_exits_down_never_direct(self):
        primary = self.servers[1]
        primary.close()
        await primary.wait_closed()
        self.assertIn(b"origin-2", await self.request())
        self.servers[3].close()
        await self.servers[3].wait_closed()
        before = list(self.origin_count)
        with self.assertRaises(
            (OSError, TimeoutError, asyncio.IncompleteReadError, IndexError)
        ):
            await self.request()
        self.assertEqual(self.origin_count, before)
        self.assertEqual((await self.query()).rcode(), dns.rcode.SERVFAIL)

    async def test_live_user_expiry_and_policy_change_close_existing_tls_streams(self):
        reader, writer, body = await self.request("/hold")
        self.assertIn(b"origin-1", body)
        self.rules[0]["exit_ids"] = [self.origins[1]["id"]]
        self.update_policy(self.rules)
        self.assertEqual(await asyncio.wait_for(reader.read(), 3), b"")
        await close(writer)
        reader, writer, _ = await self.request("/hold")
        with database() as db:
            db.execute("UPDATE users SET expires=1")
        self.assertEqual(await asyncio.wait_for(reader.read(), 3), b"")
        await close(writer)

    async def test_unknown_sni_tls_trust_and_wrong_exit_credentials_fail(self):
        before = list(self.origin_count)
        with self.assertRaises((OSError, TimeoutError)):
            await self.request(host="not-allowed.example.net")
        self.assertEqual(self.origin_count, before)
        node = self.origins[0]
        config = {
            **node,
            "username": self.exit_body["username"],
            "password": self.exit_body["password"],
        }
        with self.assertRaises(ssl.SSLCertVerificationError):
            await connect_exit(config)
        with self.assertRaises(ValueError):
            await connect_exit(
                {**config, "password": "wrong-secret-12345"}, ca=str(self.ca)
            )

    async def test_byte_quota_stops_large_transfer_before_forwarding_over_credit(self):
        with database() as db:
            db.execute("UPDATE dns_accounts SET relay_limit=6000")
        try:
            body = await self.request("/large")
            self.assertLess(len(body), 32768 * 8)
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        with database() as db:
            spent = db.execute(
                "SELECT relay_up+relay_down FROM dns_periods"
            ).fetchone()[0]
            self.assertGreater(spent, 0)
            self.assertLessEqual(spent, 6000)


class SmartFramingTest(unittest.IsolatedAsyncioTestCase):
    async def test_ech_missing_or_duplicate_names_never_select_a_route(self):
        host = b"play.example.com"
        names = b"\x00" + len(host).to_bytes(2, "big") + host
        sni = len(names).to_bytes(2, "big") + names
        extension = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni

        def hello(extensions):
            body = (
                b"\x03\x03"
                + b"x" * 32
                + b"\x00\x00\x02\x13\x01\x01\x00"
                + len(extensions).to_bytes(2, "big")
                + extensions
            )
            return b"\x01" + len(body).to_bytes(3, "big") + body

        self.assertEqual(client_name(hello(extension)), host.decode())
        for extensions in (
            b"",
            extension + extension,
            extension + b"\xfe\x0d\x00\x00",
            extension + b"\xff\xce\x00\x00",
        ):
            with self.assertRaises(ValueError):
                client_name(hello(extensions))

    async def test_fragmented_client_hello_and_malformed_or_overflow_rejected(self):
        context = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = context.wrap_bio(
            incoming, outgoing, server_hostname="play.example.com"
        )
        with self.assertRaises(ssl.SSLWantReadError):
            client.do_handshake()
        record = outgoing.read()
        handshake = record[5:]
        chunks = [handshake[:2], handshake[2:35], handshake[35:]]
        wire = b"".join(
            b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part for part in chunks
        )
        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()
        name, preserved = await read_hello(reader)
        self.assertEqual(name, "play.example.com")
        self.assertEqual(preserved, wire)
        for value in (
            b"GET / HTTP/1.1\r\n",
            b"\x16\x03\x01\xff\xff",
            b"\x16\x03\x01\x00\x01x" * 33,
        ):
            reader = asyncio.StreamReader()
            reader.feed_data(value)
            reader.feed_eof()
            with self.assertRaises((ValueError, asyncio.IncompleteReadError)):
                await read_hello(reader)

    async def test_public_destination_rejects_rebinding_and_ipv6_transition_addresses(
        self,
    ):
        loop = asyncio.get_running_loop()
        for ip in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::ffff:127.0.0.1",
            "2002:7f00:1::1",
            "::1",
        ):
            values = [(2, 1, 6, "", ("1.1.1.1", 443)), (2, 1, 6, "", (ip, 443))]
            with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=values)):
                with self.assertRaises(ValueError):
                    await public_destination("play.example.com")

    async def test_proxy_headers_only_trusted_on_loopback(self):
        class Peer:
            def __init__(self, ip):
                self.ip = ip

            def get_extra_info(self, key):
                return (self.ip, 10000)

        gateway = Gateway(proxy_protocol=True)
        reader = asyncio.StreamReader()
        reader.feed_data(b"PROXY TCP4 1.1.1.1 2.2.2.2 1234 443\r\n")
        self.assertEqual(await gateway.source(reader, Peer("127.0.0.1")), "1.1.1.1")
        with self.assertRaises(ValueError):
            await gateway.source(asyncio.StreamReader(), Peer("8.8.8.8"))
