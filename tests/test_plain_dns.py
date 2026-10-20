"""Plain DNS clients need no TLS, DoH token or domain name."""

import asyncio
import os
import socket
import time
from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import dns.message
import dns.query
from app.db import database
from ops.install import arguments, dns_options
from ops.common import InstallError
from agent.dns_server import serve
from test_accounts import PanelBase


class PlainDNSTest(PanelBase):
    def create(self, name="ordinary", limit=0):
        user = self.post("/users", {"name": name}).json()
        policy = self.post(
            "/dns/policies",
            {
                "name": name,
                "rules": [
                    {
                        "domain": "game.example",
                        "action": "rewrite",
                        "addresses": ["1.2.3.4"],
                    }
                ],
            },
        ).json()
        account = self.post(
            "/dns/accounts",
            {
                "user_id": user["id"],
                "policy_id": policy["id"],
                "qps": 100,
                "query_limit": limit,
            },
        ).json()
        return user, account

    def test_http_metadata_managed_ip_roles_conflicts_and_expiry(self):
        user, account = self.create()
        endpoint = f"/dns/accounts/{account['id']}/ip-leases"
        with patch.dict(
            os.environ,
            DONINO_PUBLIC_URL="http://203.0.113.10",
            DONINO_DNS_ENABLED="1",
            DONINO_DNS_LISTEN="0.0.0.0",
            DONINO_DNS_PUBLIC_IPS="203.0.113.10",
            DONINO_DNS_PORT="53",
            DONINO_DOT_PORT="",
        ):
            value = self.client.get("/api/dns/runtime").json()
            self.assertEqual(value["addresses"], ["203.0.113.10"])
            self.assertEqual(value["transports"], ["udp", "tcp"])
            self.assertIsNone(value["doh_url"])
            token = (
                self.client.get(f"/api/users/{user['id']}/subscription")
                .json()["url"]
                .split("/sub/")[1]
                .split("?")[0]
            )
            portal = self.client.get(f"/api/portal/{token}/dns").json()
            self.assertIsNone(portal["doh_url"])
            self.assertEqual(portal["connection"]["addresses"], value["addresses"])
        for ip in ("0.0.0.0", "224.0.0.1", "fe80::1", "fe80::1%eth0", "not-an-ip"):
            self.assertEqual(self.post(endpoint, {"ip": ip}).status_code, 422)
        self.assertEqual(
            self.post(endpoint, {"ip": "::ffff:203.0.113.8"}).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api" + endpoint).json()[0]["ip"], "203.0.113.8"
        )
        _, other = self.create("other")
        self.assertEqual(
            self.post(
                f"/dns/accounts/{other['id']}/ip-leases", {"ip": "203.0.113.8"}
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.delete(
                f"/api/dns/accounts/{other['id']}/ip-leases/203.0.113.8",
                headers=self.headers,
            ).status_code,
            404,
        )
        self.login("viewer")
        self.assertEqual(self.post(endpoint, {"ip": "203.0.113.9"}).status_code, 403)
        self.login("operator")
        self.assertEqual(
            self.post(endpoint, {"ip": "203.0.113.9", "ttl": 60}).status_code, 200
        )
        self.assertEqual(self.post(endpoint, {"ip": "203.0.113.10"}).status_code, 200)
        self.assertEqual(self.post(endpoint, {"ip": "203.0.113.11"}).status_code, 409)
        with database() as db:
            db.execute(
                "UPDATE dns_ip_leases SET expires=? WHERE ip=?",
                (int(time.time()) - 1, "203.0.113.9"),
            )
        self.assertEqual(self.post(endpoint, {"ip": "203.0.113.11"}).status_code, 200)
        self.assertEqual(
            self.client.delete(
                "/api" + endpoint + "/203.0.113.8", headers=self.headers
            ).status_code,
            200,
        )

    def test_actual_udp_tcp_without_certificate_lease_quota_and_user_expiry(self):
        user, account = self.create(limit=3)
        endpoint = f"/dns/accounts/{account['id']}/ip-leases"
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        query = dns.message.make_query("game.example", "A")

        async def scenario():
            task = asyncio.create_task(
                serve(
                    SimpleNamespace(
                        listen="127.0.0.1",
                        port=port,
                        dot_port=0,
                        tls_cert=None,
                        tls_key=None,
                    )
                )
            )
            try:
                for _ in range(100):
                    try:
                        reader, writer = await asyncio.open_connection(
                            "127.0.0.1", port
                        )
                        writer.close()
                        await writer.wait_closed()
                        break
                    except OSError:
                        await asyncio.sleep(0.01)
                with self.assertRaises(dns.exception.Timeout):
                    await asyncio.to_thread(
                        dns.query.udp, query, "127.0.0.1", port=port, timeout=0.15
                    )
                self.assertEqual(
                    self.post(endpoint, {"ip": "127.0.0.1"}).status_code, 200
                )
                for method in (dns.query.udp, dns.query.tcp, dns.query.udp):
                    answer = await asyncio.to_thread(
                        method, query, "127.0.0.1", port=port, timeout=2
                    )
                    self.assertEqual(answer.answer[0][0].address, "1.2.3.4")
                with self.assertRaises((EOFError, OSError, dns.exception.Timeout)):
                    await asyncio.to_thread(
                        dns.query.tcp, query, "127.0.0.1", port=port, timeout=0.3
                    )
                rows = self.client.get(
                    f"/api/dns/accounts/{account['id']}/periods"
                ).json()
                self.assertEqual(rows[0]["queries"], 3)
                self.assertGreater(rows[0]["response_bytes"], 0)
                self.assertEqual(
                    self.post(f"/dns/accounts/{account['id']}/reset").status_code, 200
                )
                self.client.delete(
                    "/api" + endpoint + "/127.0.0.1", headers=self.headers
                )
                with self.assertRaises(dns.exception.Timeout):
                    await asyncio.to_thread(
                        dns.query.udp, query, "127.0.0.1", port=port, timeout=0.15
                    )
                self.post(endpoint, {"ip": "127.0.0.1"})
                response = self.client.put(
                    "/api/users/" + user["id"],
                    headers=self.headers,
                    json={
                        "name": user["name"],
                        "enabled": True,
                        "expires": int(time.time()) - 1,
                    },
                )
                self.assertEqual(response.status_code, 200)
                with self.assertRaises((EOFError, OSError, dns.exception.Timeout)):
                    await asyncio.to_thread(
                        dns.query.tcp, query, "127.0.0.1", port=port, timeout=0.3
                    )
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                await asyncio.get_running_loop().shutdown_default_executor()

        asyncio.run(scenario())

    def test_plain_installer_defaults_without_disabling_https_dns(self):
        value = dns_options(arguments(["--with-dns", "--tls", "none"]), {})
        self.assertEqual(value, {"listen": "127.0.0.1", "port": 53, "dot_port": 0})
        self.assertEqual(
            dns_options(arguments(["--with-dns", "--tls", "existing"]), {})["dot_port"],
            8530,
        )
        with self.assertRaises(InstallError):
            dns_options(
                arguments(["--with-dns", "--tls", "none", "--dot-port", "853"]), {}
            )
