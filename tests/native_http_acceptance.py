"""Real HTTP/IP install, reinstallation, repair and TTY menu in isolated systemd.

No VPS or public ACME claim. Uses the same OS/dependency fixture as HTTPS.
"""

import argparse
import secrets
import tempfile

from native_acceptance import IMAGES, NativeFixture


class HTTPFixture(NativeFixture):
    http_only = True

    def install(self, name, **_):
        self.exec(
            name,
            "./install.sh",
            "install",
            "--domain",
            "127.0.0.1",
            "--tls",
            "none",
            "--with-dns",
            "--dns-listen",
            "127.0.0.1",
            "--dns-port",
            "53",
            "--with-smart-dns",
            "--smart-dns-ip",
            "127.0.0.1",
        )

    def run(self):
        self.prepare()
        print(self.os_name + ": HTTP source prepared", flush=True)
        name, client = self.start()
        try:
            assert client.get("/readyz").status_code == 200
            assert not client.get("/readyz").is_redirect
            raw = self.exec(
                name,
                "cat",
                "/var/lib/donino-installer/bootstrap-access.txt",
                capture=True,
            )
            assert "http://127.0.0.1/#setup=" in raw
            token = raw.strip().split("#setup=", 1)[1]
            credentials = {
                "username": "http-owner",
                "password": secrets.token_urlsafe(24),
            }
            assert (
                client.post(
                    "/api/bootstrap", json=credentials | {"token": token}
                ).status_code
                == 201
            )
            response = client.post("/api/login", json=credentials)
            assert response.status_code == 200
            cookie = response.headers["set-cookie"].lower()
            assert "httponly" in cookie and "secure" not in cookie
            user = client.post(
                "/api/users", json={"name": "http-preserved", "quota": 123456789}
            ).json()
            assert user["id"]
            print(
                self.os_name + ": HTTP/IP bootstrap, login and API passed", flush=True
            )
            runtime = client.get("/api/dns/runtime").json()
            assert runtime["configured"] and runtime["port"] == 53
            assert runtime["doh_url"] is None and runtime["dot_port"] is None
            self.exec(
                name,
                "sh",
                "-c",
                "test ! -e /etc/donino/tls/panel.crt && test ! -e /var/lib/donino-panel/dns-tls/current/panel.key",
            )
            policy = client.post(
                "/api/dns/policies", json={"name": "plain-native"}
            ).json()
            dns_account = client.post(
                "/api/dns/accounts",
                json={
                    "user_id": user["id"],
                    "policy_id": policy["id"],
                    "query_limit": 2,
                },
            ).json()
            lease = client.post(
                f"/api/dns/accounts/{dns_account['id']}/ip-leases",
                json={"ip": "127.0.0.1"},
            )
            assert lease.status_code == 200
            self.exec(
                name,
                "/opt/donino-panel/current/.venv/bin/python",
                "-c",
                """
import dns.message,dns.query
query=dns.message.make_query('donino.health.','A')
for method in (dns.query.udp,dns.query.tcp):
 answer=method(query,'127.0.0.1',port=53,timeout=3)
 assert answer.answer[0][0].address=='127.0.0.1'
try:
 dns.query.udp(query,'127.0.0.1',port=53,timeout=.3)
 raise AssertionError('Exhausted DNS quota still answered')
except dns.exception.Timeout:pass
""",
            )
            stats = client.get(f"/api/dns/accounts/{dns_account['id']}/periods").json()
            assert stats[0]["queries"] == 2 and stats[0]["response_bytes"] > 0
            smart = client.get("/api/dns/smart/status").json()
            assert smart["enabled"] and smart["gateway_ready"]
            self.exec(
                name,
                "/opt/donino-panel/current/.venv/bin/python",
                "-c",
                """
import socket,ssl
# Only the application TLS handshake is passed through; no panel certificate.
context=ssl.create_default_context()
try:
 with socket.create_connection(('127.0.0.1',443),timeout=3) as raw:
  with context.wrap_socket(raw,server_hostname='unauthorized.example.com'):
   raise AssertionError('Unauthorized SNI passed the source/policy gate')
except (OSError,ssl.SSLError):pass
""",
            )
            print(
                self.os_name
                + ": certificate-free UDP/TCP53, real Unbound, source-IP allowlist, quota and HTTP-panel Smart gateway passed",
                flush=True,
            )
            node = client.post(
                "/api/nodes", json={"name": "http-fixture-node", "host": "127.0.0.1"}
            ).json()
            assert (
                client.post(
                    "/api/inbounds",
                    json={
                        "node_id": node["id"],
                        "name": "sealed-key-fixture",
                        "protocol": "shadowsocks",
                        "ss_method": "2022-blake3-aes-128-gcm",
                        "port": 8388,
                    },
                ).status_code
                == 201
            )
            check = "from pathlib import Path; import hashlib; print(hashlib.sha256(Path('/etc/donino/panel.env').read_bytes()+Path('/var/lib/donino-panel/master.key').read_bytes()).hexdigest())"
            before = self.exec(name, "python3", "-c", check, capture=True).strip()
            # No flags: saved mode/host must survive even with piped stdin.
            self.exec(name, "./install.sh", "install")
            self.exec(name, "./install.sh", "repair")
            assert self.exec(name, "./install.sh", "doctor", capture=True)
            assert (
                self.exec(name, "python3", "-c", check, capture=True).strip() == before
            )
            assert client.post("/api/login", json=credentials).status_code == 200
            rows = client.get("/api/users").json()
            assert any(r["id"] == user["id"] and r["quota"] == 123456789 for r in rows)
            print(
                self.os_name
                + ": HTTP reinstallation/repair retained owner, user, quota and private keys",
                flush=True,
            )
            # Real installed launcher, real controlling PTY, stdin disconnected.
            self.exec(
                name,
                "python3",
                "-c",
                r"""
import os,pty,select,time
pid,fd=pty.fork()
if pid==0:
 os.environ['TERM']='xterm-256color'
 null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0)
 os.execl('/usr/local/bin/donino','donino')
text=b'';deadline=time.monotonic()+10;sent=False
while time.monotonic()<deadline:
 if select.select([fd],[],[],.1)[0]:
  try:chunk=os.read(fd,65536)
  except OSError:break
  if not chunk:break
  text+=chunk
  if b'Choose' in text and not sent:os.write(fd,bytes([48,10]));sent=True
 else:
  done,status=os.waitpid(pid,os.WNOHANG)
  if done:break
else:
 os.kill(pid,9);os.waitpid(pid,0);raise AssertionError('Menu deadline')
os.close(fd)
assert b'DONINO PANEL' in text and bytes([27])+b'[?1049h' in text and bytes([27])+b'[?1049l' in text,'Menu TTY/alternate screen failed'
""",
            )
            print(
                self.os_name
                + ": installed terminal menu works with disconnected stdin and restores alternate screen",
                flush=True,
            )
            self.exec(name, "./install.sh", "uninstall")
            self.exec(
                name,
                "sh",
                "-c",
                "test -f /var/lib/donino-panel/master.key && test -d /var/lib/postgresql && test ! -e /usr/local/bin/donino",
            )
            print(
                "PASS "
                + self.os_name
                + ": HTTP/IP lifecycle, real systemd/NGINX/PostgreSQL and TTY menu; data-preserving uninstall.",
                flush=True,
            )
        finally:
            client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os", choices=sorted(IMAGES), required=True)
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="donino-native-http-") as folder:
        fixture = HTTPFixture(args.os, folder)
        if args.no_build:
            original = fixture.docker

            def docker(*values, **kwargs):
                if values[0] == "build":
                    original("image", "inspect", fixture.image, capture=True)
                    return ""
                return original(*values, **kwargs)

            fixture.docker = docker
        try:
            fixture.run()
        except BaseException:
            # Fixed diagnostics only; operation logs may contain credentials.
            import shutil
            from pathlib import Path

            target = Path("/tmp/donino-native-failures")
            target.mkdir(mode=0o700, exist_ok=True)
            path = target / ("http-" + args.os + "-" + secrets.token_hex(6) + ".log")
            shutil.copyfile(fixture.log, path)
            path.chmod(0o600)
            print("Private diagnostics: " + str(path))
            raise
        finally:
            fixture.cleanup()


if __name__ == "__main__":
    main()
