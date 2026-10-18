"""Actual Unbound validates a private signed zone and rejects a bogus signature."""

import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

from test_accounts import PanelBase
from app.dns_policy import DNSResolver
from app.main import app


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_UNBOUND"),
    "Set DONINO_TEST_UNBOUND to a real Unbound binary",
)
class DNSRuntimeTest(PanelBase):
    def setUp(self):
        super().setUp()
        # Ubuntu's packaged AppArmor profile permits the Unbound state tree,
        # rather than arbitrary /tmp configs. CI prepares a private, runner-owned
        # subdirectory there; database files and application keys stay separate.
        fixture = tempfile.TemporaryDirectory(
            prefix="donino-dns-", dir=os.environ.get("DONINO_TEST_UNBOUND_ROOT")
        )
        self.addCleanup(fixture.cleanup)
        self.resolver_directory = Path(fixture.name)

    def test_real_validating_resolver_and_doh_policy_isolation(self):
        zone = dns.name.from_text("signed.test.")
        private = ec.generate_private_key(ec.SECP256R1())
        key = dns.dnssec.make_dnskey(private.public_key(), 13, flags=257)
        keys = dns.rrset.from_rdata(zone, 300, key)
        key_sig = dns.rrset.from_rdata(
            zone, 300, dns.dnssec.sign(keys, private, zone, key, lifetime=600)
        )
        answers = {}
        for prefix in ("good", "bad"):
            name = prefix + ".signed.test."
            data = dns.rrset.from_text(name, 120, "IN", "A", "1.2.3.4")
            signature = dns.rrset.from_rdata(
                name, 120, dns.dnssec.sign(data, private, zone, key, lifetime=600)
            )
            if prefix == "bad":
                data = dns.rrset.from_text(name, 120, "IN", "A", "5.6.7.8")
            answers[name] = [data, signature]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        authority_port = sock.getsockname()[1]
        sock.settimeout(0.2)
        stop = threading.Event()

        def authority():
            while not stop.is_set():
                try:
                    wire, peer = sock.recvfrom(4096)
                    query = dns.message.from_wire(wire)
                    response = dns.message.make_response(query)
                    response.flags |= dns.flags.AA
                    question = query.question[0]
                    if (
                        question.name == zone
                        and question.rdtype == dns.rdatatype.DNSKEY
                    ):
                        response.answer.extend([keys, key_sig])
                    else:
                        response.answer.extend(answers.get(question.name.to_text(), []))
                    sock.sendto(response.to_wire(), peer)
                except socket.timeout:
                    continue
                except OSError:
                    break

        thread = threading.Thread(target=authority, daemon=True)
        thread.start()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = self.resolver_directory / "unbound.conf"
        config.write_text(f'''server:
    interface: 127.0.0.1
    port: {port}
    username: ""
    chroot: ""
    directory: "{self.resolver_directory}"
    pidfile: ""
    do-daemonize: no
    use-syslog: no
    logfile: ""
    verbosity: 0
    do-ip6: no
    do-not-query-localhost: no
    local-zone: "test." nodefault
    trust-anchor: "signed.test. 300 IN DNSKEY {key.to_text()}"
stub-zone:
    name: signed.test.
    stub-addr: 127.0.0.1@{authority_port}
    stub-prime: no
''')
        log = open(self.resolver_directory / "unbound.log", "w+")
        process = subprocess.Popen(
            [os.environ["DONINO_TEST_UNBOUND"], "-d", "-c", str(config)],
            stdout=log,
            stderr=log,
        )
        try:
            ready = False
            for _ in range(20):
                try:
                    value = dns.query.udp(
                        dns.message.make_query(
                            "good.signed.test.", "A", want_dnssec=True
                        ),
                        "127.0.0.1",
                        port=port,
                        timeout=0.2,
                    )
                    if value.answer:
                        ready = True
                        break
                except (OSError, dns.exception.DNSException):
                    pass
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            log.flush()
            log.seek(0)
            self.assertTrue(
                ready,
                log.read()[-2500:]
                + (value.to_text() if "value" in locals() else "no response"),
            )
            self.assertTrue(value.flags & dns.flags.AD, value.to_text())
            bad = dns.query.udp(
                dns.message.make_query("bad.signed.test.", "A", want_dnssec=True),
                "127.0.0.1",
                port=port,
                timeout=3,
            )
            self.assertEqual(bad.rcode(), dns.rcode.SERVFAIL)
            self.assertFalse(bad.flags & dns.flags.AD)
            policy = self.post("/dns/policies", {"name": "validated"}).json()
            user = self.post("/users", {"name": "dnssec user"}).json()
            account = self.post(
                "/dns/accounts", {"user_id": user["id"], "policy_id": policy["id"]}
            ).json()
            with patch.object(
                app.state.dns_service, "resolver", DNSResolver(port=port)
            ):
                query = dns.message.make_query(
                    "good.signed.test.", "A", want_dnssec=True
                ).to_wire()
                headers = {
                    "Authorization": "Bearer " + account["token"],
                    "Content-Type": "application/dns-message",
                }
                result = self.client.post("/dns-query", headers=headers, content=query)
                self.assertEqual(result.status_code, 200)
                self.assertTrue(
                    dns.message.from_wire(result.content).flags & dns.flags.AD
                )
                self.assertEqual(
                    self.client.put(
                        "/api/dns/policies/" + policy["id"],
                        headers=self.headers,
                        json={
                            "name": "validated",
                            "rules": [
                                {
                                    "domain": "signed.test",
                                    "action": "rewrite",
                                    "addresses": ["9.9.9.9"],
                                }
                            ],
                        },
                    ).status_code,
                    200,
                )
                result = self.client.post("/dns-query", headers=headers, content=query)
                rewritten = dns.message.from_wire(result.content)
                self.assertFalse(rewritten.flags & dns.flags.AD)
                self.assertEqual(rewritten.answer[0][0].address, "9.9.9.9")
            print(
                "  Real Unbound validated a signed answer, refused bogus DNSSEC and preserved DoH policy/cache isolation"
            )
        finally:
            process.terminate()
            process.wait(timeout=5)
            stop.set()
            thread.join(timeout=1)
            sock.close()
            log.close()
