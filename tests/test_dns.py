import base64
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from fastapi import HTTPException
from fastapi.testclient import TestClient

from test_accounts import PanelBase
from app.db import database
from app.dns_policy import DNSResolver, parse_query, serialize
from app.dns_service import DNSService
from app.main import app


class DNSTest(PanelBase):
    def policy(self, name="default", rules=None):
        result = self.post("/dns/policies", {"name": name, "rules": rules or []})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def account(self, *, name="dns user", policy=None, limit=0, qps=100):
        policy = policy or self.policy()
        user = self.post("/users", {"name": name}).json()
        result = self.post(
            "/dns/accounts",
            {
                "user_id": user["id"],
                "policy_id": policy["id"],
                "query_limit": limit,
                "qps": qps,
            },
        )
        self.assertEqual(result.status_code, 201, result.text)
        return user, result.json()

    def doh(self, token, *, name="sample.example", method="POST", **kwargs):
        wire = dns.message.make_query(name, "A", want_dnssec=True).to_wire()
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/dns-message",
        }
        if method == "GET":
            return self.client.get(
                "/dns-query",
                headers=headers,
                params={"dns": base64.urlsafe_b64encode(wire).decode().rstrip("=")},
                **kwargs,
            )
        return self.client.post("/dns-query", headers=headers, content=wire, **kwargs)

    @staticmethod
    def upstream(query, *args, **kwargs):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AD | dns.flags.RA
        response.answer.append(
            dns.rrset.from_text(query.question[0].name, 120, "IN", "A", "1.2.3.4")
        )
        return response

    def test_policy_validation_roles_and_secret_redaction(self):
        for rules in (
            [{"domain": "*.example.com", "action": "block"}],
            [{"domain": "com", "action": "block"}],
            [{"domain": "example.com", "action": "rewrite"}],
            [{"domain": "example.com", "action": "block", "addresses": ["1.2.3.4"]}],
            [{"domain": "example.com", "action": "rewrite", "addresses": ["0.0.0.0"]}],
            [{"domain": "example.com", "action": "block"}] * 2,
        ):
            self.assertEqual(
                self.post("/dns/policies", {"name": "bad", "rules": rules}).status_code,
                422,
            )
        policy = self.policy(rules=[{"domain": "EXAMPLE.com.", "action": "block"}])
        self.assertEqual(
            self.client.get("/api/dns/policies").json()[0]["rules"][0]["domain"],
            "example.com",
        )
        _, account = self.account(policy=policy)
        text = self.client.get("/api/dns/accounts").text
        self.assertNotIn(account["token"], text)
        self.assertNotIn("token_hash", text)
        self.assertEqual(
            self.client.delete(
                "/api/dns/policies/" + policy["id"], headers=self.headers
            ).status_code,
            409,
        )
        self.login("viewer")
        self.assertEqual(self.post("/dns/accounts", {}).status_code, 403)
        self.assertEqual(self.post("/dns/policies", {"name": "no"}).status_code, 403)

    def test_doh_post_get_rotation_expiry_and_separate_dns_ledger(self):
        user, account = self.account()
        with patch("dns.query.udp", side_effect=self.upstream) as upstream:
            for method in ("POST", "GET"):
                result = self.doh(account["token"], method=method)
                self.assertEqual(result.status_code, 200, result.text)
                self.assertEqual(
                    result.headers["content-type"], "application/dns-message"
                )
                self.assertEqual(result.headers["cache-control"], "no-store")
                self.assertTrue(
                    dns.message.from_wire(result.content).flags & dns.flags.AD
                )
            self.assertEqual(upstream.call_count, 1)
        values = self.client.get("/api/dns/accounts").json()[0]
        self.assertEqual(values["queries"], 2)
        self.assertGreater(values["request_bytes"], 0)
        self.assertGreater(values["response_bytes"], values["request_bytes"])
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 0)
        token = self.post(f"/dns/accounts/{account['id']}/rotate-token").json()["token"]
        self.assertEqual(self.doh(account["token"]).status_code, 401)
        self.assertEqual(self.doh(token).status_code, 200)
        with database() as db:
            db.execute(
                "UPDATE users SET expires=? WHERE id=?",
                (int(time.time()) - 1, user["id"]),
            )
        self.assertEqual(self.doh(token).status_code, 403)

    def test_closed_default_bad_messages_no_body_bypass_and_no_cookie_auth(self):
        user, account = self.account()
        query = dns.message.make_query("example.com", "A").to_wire()
        self.assertEqual(
            self.client.get("/dns-query", params={"dns": "AA"}).status_code, 401
        )
        headers = {"Authorization": "Bearer " + account["token"]}
        self.assertEqual(
            self.client.post("/dns-query", headers=headers, content=query).status_code,
            415,
        )
        headers["Content-Type"] = "application/dns-message"
        self.assertEqual(
            self.client.post(
                "/dns-query", headers=headers, content=b"x" * 4097
            ).status_code,
            413,
        )
        self.assertEqual(
            self.client.post("/dns-query", headers=headers, content=b"bad").status_code,
            400,
        )
        self.assertEqual(
            self.client.get(
                "/dns-query", headers=headers, params={"dns": "!"}
            ).status_code,
            400,
        )
        for kind in ("ANY", "AXFR", "IXFR"):
            with self.assertRaises(ValueError):
                parse_query(dns.message.make_query("example.com", kind).to_wire())
        service = DNSService()
        with self.assertRaises(HTTPException) as refused:
            service.answer(query, source_ip="1.1.1.1")
        self.assertEqual(refused.exception.status_code, 401)

    def test_cache_isolation_revision_case_dnssec_and_cname_policy(self):
        normal = self.policy("normal")
        blocked = self.policy(
            "blocked", [{"domain": "sample.example", "action": "block"}]
        )
        _, first = self.account(name="first", policy=normal)
        _, second = self.account(name="second", policy=blocked)
        with patch("dns.query.udp", side_effect=self.upstream) as upstream:
            self.assertEqual(self.doh(first["token"]).status_code, 200)
            value = dns.message.from_wire(self.doh(second["token"]).content)
            self.assertEqual(value.rcode(), dns.rcode.NXDOMAIN)
            self.assertFalse(value.flags & dns.flags.AD)
            self.assertEqual(upstream.call_count, 1)
            mixed = dns.message.from_wire(
                self.doh(first["token"], name="SaMpLe.ExAmPlE").content
            )
            self.assertEqual(mixed.question[0].name.to_text(), "SaMpLe.ExAmPlE.")
            result = self.client.put(
                "/api/dns/policies/" + normal["id"],
                headers=self.headers,
                json={
                    "name": "normal",
                    "rules": [
                        {
                            "domain": "sample.example",
                            "action": "rewrite",
                            "addresses": ["5.6.7.8", "2001:db8::1"],
                        }
                    ],
                },
            )
            self.assertEqual(result.status_code, 200)
            value = dns.message.from_wire(self.doh(first["token"]).content)
            self.assertEqual(value.answer[0][0].address, "5.6.7.8")
            self.assertFalse(value.flags & dns.flags.AD)
        resolver = DNSResolver()
        query = dns.message.make_query("alias.example", "A")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AD
        response.answer.append(
            dns.rrset.from_text(
                "alias.example.", 60, "IN", "CNAME", "target.sample.example."
            )
        )
        response.answer.append(
            dns.rrset.from_text("target.sample.example.", 60, "IN", "A", "1.2.3.4")
        )
        with patch("dns.query.udp", return_value=response):
            value, denied = resolver.resolve(
                query,
                {
                    "id": "test",
                    "revision": "one",
                    "rules": [{"domain": "sample.example", "action": "block"}],
                },
            )
        self.assertTrue(denied)
        self.assertEqual(value.rcode(), dns.rcode.NXDOMAIN)
        self.assertFalse(value.flags & dns.flags.AD)

    def test_query_quota_concurrent_requests_and_old_period_responses(self):
        _, account = self.account(limit=3)
        query = dns.message.make_query("quota.example", "A").to_wire()
        service = DNSService()

        def answer(_):
            try:
                return service.answer(query, token=account["token"])
            except HTTPException as exc:
                return exc.status_code

        with patch("dns.query.udp", side_effect=self.upstream):
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(answer, range(8)))
        self.assertEqual(sum(isinstance(r, bytes) for r in results), 3)
        self.assertEqual(results.count(403), 5)
        self.assertEqual(
            self.post(f"/dns/accounts/{account['id']}/reset").status_code, 200
        )

        def reset_during_query(query, *args, **kwargs):
            self.assertEqual(
                self.post(f"/dns/accounts/{account['id']}/reset").status_code, 200
            )
            return self.upstream(query)

        with patch("dns.query.udp", side_effect=reset_during_query):
            service.answer(
                dns.message.make_query("new.example", "A").to_wire(),
                token=account["token"],
            )
        periods = self.client.get(f"/api/dns/accounts/{account['id']}/periods").json()
        self.assertEqual(periods[0]["queries"], 0)
        self.assertEqual(periods[0]["response_bytes"], 0)
        self.assertEqual(periods[1]["queries"], 1)
        self.assertGreater(periods[1]["response_bytes"], 0)

    def test_rate_limit_across_credentials_and_ip_leases(self):
        user, account = self.account(qps=1)
        with database() as db:
            db.execute(
                "INSERT INTO dns_ip_leases VALUES(?,?,?,?)",
                ("1.1.1.1", account["id"], int(time.time()) + 60, int(time.time())),
            )
        service = DNSService()
        wire = dns.message.make_query("rate.example", "A").to_wire()
        with (
            patch("app.dns_service.time.time", return_value=2_000_000_000),
            patch("dns.query.udp", side_effect=self.upstream),
        ):
            # Keep a valid lease under the fixed clock.
            with database() as db:
                db.execute("UPDATE dns_ip_leases SET expires=?", (2_000_000_100,))
            service.answer(wire, token=account["token"])
            with self.assertRaises(HTTPException) as rate:
                service.answer(wire, source_ip="1.1.1.1")
            self.assertEqual(rate.exception.status_code, 429)

    def test_ip_proof_rejects_forged_headers_conflicts_and_expired_lease(self):
        first_user, first = self.account(name="first")
        second_user, second = self.account(name="second", policy=self.policy("second"))
        with database() as db:
            users = {
                r["id"]: r["token"] for r in db.execute("SELECT id,token FROM users")
            }
        path = f"/api/portal/{users[first_user['id']]}/dns/claim-ip"
        self.assertEqual(
            self.client.post(
                path, headers={**self.headers, "X-Forwarded-For": "1.1.1.1"}, json={}
            ).status_code,
            422,
        )
        client = TestClient(app, client=("1.1.1.1", 1234))
        self.assertEqual(
            client.post(path, headers=self.headers, json={}).status_code, 200
        )
        other = f"/api/portal/{users[second_user['id']]}/dns/claim-ip"
        self.assertEqual(
            client.post(other, headers=self.headers, json={}).status_code, 409
        )
        with database() as db:
            db.execute("UPDATE dns_ip_leases SET expires=?", (int(time.time()) - 1,))
        self.assertEqual(
            client.post(other, headers=self.headers, json={}).status_code, 200
        )
        with database() as db:
            self.assertEqual(
                db.execute("SELECT account_id FROM dns_ip_leases").fetchone()[0],
                second["id"],
            )
        self.assertEqual(
            client.delete(
                f"/api/portal/{users[second_user['id']]}/dns/ip-leases",
                headers=self.headers,
            ).status_code,
            200,
        )
        self.assertEqual(
            client.get(f"/api/portal/{users[second_user['id']]}/dns").json()[
                "ip_leases"
            ],
            [],
        )

    def test_udp_truncation_tcp_fallback_errors_and_no_negative_cache_ttl_extension(
        self,
    ):
        resolver = DNSResolver()
        query = dns.message.make_query("large.example.", "TXT")
        truncated = dns.message.make_response(query)
        truncated.flags |= dns.flags.TC
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text(
                "large.example.",
                60,
                "IN",
                "TXT",
                *['"' + str(i) + "x" * 100 + '"' for i in range(10)],
            )
        )
        with (
            patch("dns.query.udp", return_value=truncated),
            patch("dns.query.tcp", return_value=response) as tcp,
        ):
            result, blocked = resolver.resolve(
                query, {"id": "tcp", "revision": "one", "rules": []}
            )
        self.assertEqual(tcp.call_count, 1)
        self.assertFalse(blocked)
        self.assertTrue(
            dns.message.from_wire(serialize(result, query, udp=True)).flags
            & dns.flags.TC
        )
        self.assertFalse(
            dns.message.from_wire(serialize(result, query)).flags & dns.flags.TC
        )
        negative = dns.message.make_response(query)
        negative.set_rcode(dns.rcode.NXDOMAIN)
        negative.authority.append(
            dns.rrset.from_text(
                "example.",
                120,
                "IN",
                "SOA",
                "ns.example. hostmaster.example. 1 60 60 60 2",
            )
        )
        clock = [100.0]
        with (
            patch("app.dns_policy.time.monotonic", side_effect=lambda: clock[0]),
            patch("dns.query.udp", return_value=negative) as upstream,
        ):
            policy = {"id": "negative", "revision": "one", "rules": []}
            resolver.resolve(query, policy)
            clock[0] += 1
            resolver.resolve(query, policy)
            self.assertEqual(upstream.call_count, 1)
            clock[0] += 2
            resolver.resolve(query, policy)
            self.assertEqual(upstream.call_count, 2)
        _, account = self.account()
        with patch("dns.query.udp", side_effect=OSError("upstream down")):
            result = self.doh(account["token"], name="unavailable.example")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(
            dns.message.from_wire(result.content).rcode(), dns.rcode.SERVFAIL
        )
        self.assertEqual(self.client.get("/api/dns/accounts").json()[0]["errors"], 1)
        with self.assertRaises(ValueError):
            DNSResolver(upstream="8.8.8.8")

    def test_explicit_allow_ipv6_rewrite_and_portal_credential_ownership(self):
        policy = self.policy(
            rules=[
                {"domain": "example.com", "action": "block"},
                {"domain": "ok.example.com", "action": "allow"},
                {
                    "domain": "v6.example.com",
                    "action": "rewrite",
                    "addresses": ["2001:db8::2"],
                },
            ]
        )
        user, account = self.account(policy=policy)
        with patch("dns.query.udp", side_effect=self.upstream):
            self.assertEqual(
                dns.message.from_wire(
                    self.doh(account["token"], name="ok.example.com").content
                ).rcode(),
                dns.rcode.NOERROR,
            )
        service = DNSService()
        query = dns.message.make_query("v6.example.com", "AAAA", want_dnssec=True)
        response = dns.message.from_wire(
            service.answer(query.to_wire(), token=account["token"])
        )
        self.assertEqual(response.answer[0][0].address, "2001:db8::2")
        self.assertFalse(response.flags & dns.flags.AD)
        with database() as db:
            token = db.execute(
                "SELECT token FROM users WHERE id=?", (user["id"],)
            ).fetchone()[0]
        self.assertEqual(
            self.client.post(
                "/api/portal/not-a-token/dns/rotate-token", headers=self.headers
            ).status_code,
            404,
        )
        result = self.client.post(
            f"/api/portal/{token}/dns/rotate-token", headers=self.headers
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.doh(account["token"]).status_code, 401)
