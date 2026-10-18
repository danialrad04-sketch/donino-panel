import contextlib
import hashlib
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from app import tunnel_probe
from test_xray_transports import _write_test_pki


class ProbeTransportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ca, self.cert, self.key = _write_test_pki(self.root / "pki")

    def tearDown(self):
        self.tmp.cleanup()

    @contextlib.contextmanager
    def socks(self, reply, *, slow=False):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(2)
        seen = []

        def serve():
            try:
                with server.accept()[0] as raw:
                    raw.settimeout(2)
                    self.assertEqual(tunnel_probe._exact(raw, 3), b"\x05\x01\x00")
                    raw.sendall(b"\x05\x00")
                    header = tunnel_probe._exact(raw, 5)
                    seen.append(tunnel_probe._exact(raw, header[4]).decode())
                    self.assertEqual(tunnel_probe._exact(raw, 2), b"\x01\xbb")
                    raw.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.cert, self.key)
                    with context.wrap_socket(raw, server_side=True) as tls:
                        request = b""
                        while b"\r\n\r\n" not in request:
                            request += tls.recv(1024)
                        seen.append(request)
                        if slow:
                            tls.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
                            )
                            for _ in range(100):
                                tls.sendall(b"x")
                                time.sleep(0.04)
                        else:
                            tls.sendall(reply)
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield server.getsockname()[1], seen
        finally:
            server.close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def test_verified_https_through_socks_and_no_proxy_destination_override(self):
        payload = b"actual-https-body"
        with self.socks(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n" + payload) as (
            port,
            seen,
        ):
            digest = tunnel_probe._response(
                port,
                urlsplit("https://localhost/check"),
                str(self.ca),
                time.monotonic() + 5,
            )
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(seen[0], "localhost")
        self.assertIn(b"GET /check HTTP/1.1", seen[1])

    def test_redirect_and_oversized_body_are_refused(self):
        for response, code in (
            (
                b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n",
                "probe_http_rejected",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n" + b"x" * 65537,
                "probe_response_too_large",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort",
                "probe_incomplete_response",
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "probe_empty_response"),
        ):
            with self.socks(response) as (port, seen):
                with self.assertRaisesRegex(tunnel_probe.ProbeError, code):
                    tunnel_probe._response(
                        port,
                        urlsplit("https://localhost/check"),
                        str(self.ca),
                        time.monotonic() + 5,
                    )
            self.assertEqual(seen[0], "localhost")

    def test_slow_drip_is_bounded_by_total_response_deadline(self):
        with self.socks(b"", slow=True) as (port, _):
            started = time.monotonic()
            with patch.object(tunnel_probe, "SOCKET_SECONDS", 0.2):
                with self.assertRaises((OSError, tunnel_probe.ProbeError)):
                    tunnel_probe._response(
                        port,
                        urlsplit("https://localhost/check"),
                        str(self.ca),
                        time.monotonic() + 5,
                    )
            self.assertLess(time.monotonic() - started, 1)

    def test_target_hostname_and_unknown_ca_remain_verified(self):
        for target, ca in (
            ("https://wrong.example/check", str(self.ca)),
            ("https://localhost/check", ""),
        ):
            with self.socks(b"") as (port, _):
                with self.assertRaises(ssl.SSLCertVerificationError):
                    tunnel_probe._response(
                        port, urlsplit(target), ca, time.monotonic() + 5
                    )

    def test_operator_configuration_is_required_and_urls_are_restricted(self):
        with patch.dict(
            os.environ,
            {
                "DONINO_TUNNEL_PROBE_MIHOMO": "/usr/bin/true",
                "DONINO_TUNNEL_PROBE_URL": "https://example.com/check",
                "DONINO_TUNNEL_PROBE_SHA256": "a" * 64,
                "DONINO_TUNNEL_PROBE_CA": "",
            },
        ):
            self.assertTrue(tunnel_probe.available())
            for value in (
                "http://example.com",
                "https://user:password@example.com",
                "https://example.com:99999",
                "https://example.com/?secret=1",
                "https://example.com/#fragment",
                "https://example.com/\r\nInjected:yes",
            ):
                with patch.dict(os.environ, {"DONINO_TUNNEL_PROBE_URL": value}):
                    self.assertFalse(tunnel_probe.available())
            with patch.dict(os.environ, {"DONINO_TUNNEL_PROBE_MIHOMO": "relative"}):
                self.assertFalse(tunnel_probe.available())

    @unittest.skipUnless(sys.platform == "linux", "Linux parent-death primitive")
    def test_probe_process_is_killed_when_its_worker_dies(self):
        ready = self.root / "engine-ready"
        engine = (
            "from pathlib import Path; import time; Path("
            + repr(str(ready))
            + ").touch(); time.sleep(60)"
        )
        parent = (
            "import os,subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-m','app.probe_runner','--parent',str(os.getpid()),"
            "sys.executable,'-c'," + repr(engine) + "]); "
            "print(p.pid,flush=True); time.sleep(60)"
        )
        worker = subprocess.Popen(
            [sys.executable, "-c", parent], stdout=subprocess.PIPE, text=True
        )
        child = None
        try:
            child = int(worker.stdout.readline())
            deadline = time.monotonic() + 3
            while not ready.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            worker.kill()
            worker.wait(timeout=3)
            deadline = time.monotonic() + 3
            while True:
                status = Path(f"/proc/{child}/stat")
                try:
                    state = status.read_text().split()[2]
                except (FileNotFoundError, ProcessLookupError):
                    break
                if state == "Z":
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=3)
            if child:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass
            worker.stdout.close()
