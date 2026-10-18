"""Real systemd/NGINX/PostgreSQL installation in isolated OS containers.

Needs a local Docker daemon and privileged containers. This is service/OS
acceptance, not a VM, public ACME or external-network acceptance claim.
All keys and setup credentials are temporary, private and never printed.
"""

import argparse
import ipaddress
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import httpx
import dns.message
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.security import hotp
from agent.identity import certificate_request, save_identity
from agent.main import NodeAgent
from agent.enroll import enroll as enroll_node
from app.node_identity import verify_desired
from ops.manifest import source_inventory, write_manifest

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "debian12": "debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587",
    "ubuntu24": "ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55",
}


class NativeFixture:
    def __init__(self, os_name, folder):
        self.folder = Path(folder)
        self.containers = []
        self.env = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_TLS",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
            }
        }
        self.image = "donino-native-test:" + os_name
        self.os_name = os_name
        self.smart = os_name == "ubuntu24"
        self.log = self.folder / "operations.log"
        self.log.touch(mode=0o600)

    def docker(self, *args, capture=False, allow_failure=False):
        command = ["docker", "--host=unix:///var/run/docker.sock", *map(str, args)]
        if capture:
            result = subprocess.run(
                command, env=self.env, text=True, capture_output=True
            )
        else:
            with self.log.open("a") as log:
                result = subprocess.run(
                    command,
                    env=self.env,
                    text=True,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
        if result.returncode and not allow_failure:
            if capture:
                with self.log.open("a") as log:
                    log.write((result.stdout or "") + (result.stderr or ""))
            raise RuntimeError(
                f"Docker operation {args[0]} failed; inspect the private operation log while this fixture is alive"
            )
        return result.stdout if capture else ""

    def prepare(self):
        self.docker("info", capture=True)
        self.docker(
            "build",
            "--secret",
            "id=system_ca,src=/etc/ssl/certs/ca-certificates.crt",
            "--build-arg",
            "BASE_IMAGE=" + IMAGES[self.os_name],
            "-t",
            self.image,
            ROOT / "tests/native",
        )
        source = self.folder / "source"
        source.mkdir()
        files, _ = source_inventory(ROOT)
        for origin, relative in files:
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, target)
        (source / "install.sh").chmod(0o755)
        write_manifest(source)
        certificates = self.folder / "certificates"
        certificates.mkdir(mode=0o700)
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Donino native test CA")]
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "panel.test")])
            )
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("panel.test"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        (certificates / "ca.pem").write_bytes(
            ca.public_bytes(serialization.Encoding.PEM)
        )
        (certificates / "panel.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + ca.public_bytes(serialization.Encoding.PEM)
        )
        atomic = certificates / "panel.key"
        atomic.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        atomic.chmod(0o600)
        self.context = ssl.create_default_context(cafile=str(certificates / "ca.pem"))

    def exec(self, name, *command, capture=False):
        return self.docker(
            "exec", "--workdir", "/donino-source", name, *command, capture=capture
        )

    def start(self):
        name = "donino-native-" + secrets.token_hex(6)
        self.docker(
            "run",
            "--detach",
            "--name",
            name,
            "--privileged",
            "--cgroupns=private",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--add-host",
            "panel.test:127.0.0.1",
            "--mount",
            "type=bind,src=/etc/ssl/certs/ca-certificates.crt,dst=/run/donino-system-ca.pem,readonly",
            "--env",
            "SSL_CERT_FILE=/run/donino-system-ca.pem",
            "--env",
            "PIP_CERT=/run/donino-system-ca.pem",
            "--publish",
            "127.0.0.1::443",
            self.image,
            capture=True,
        )
        self.containers.append(name)
        for _ in range(40):
            status = self.docker(
                "exec",
                name,
                "systemctl",
                "is-system-running",
                capture=True,
                allow_failure=True,
            ).strip()
            if status in {"running", "degraded"}:
                break
            time.sleep(0.25)
        self.docker("cp", str(self.folder / "source"), name + ":/donino-source")
        self.docker("cp", str(self.folder / "certificates"), name + ":/testcerts")
        self.install(name)
        port = (
            self.docker("port", name, "443/tcp", capture=True).strip().rsplit(":", 1)[1]
        )
        client = httpx.Client(
            base_url="https://127.0.0.1:" + port,
            verify=self.context,
            trust_env=False,
            headers={"X-Donino": "1"},
            timeout=10,
        )
        return name, client

    def install(self, name):
        self.exec(
            name,
            "./install.sh",
            *(
                ["--with-smart-dns", "--smart-dns-ip", "127.0.0.1"]
                if self.smart
                else []
            ),
            "--with-dns",
            "--dns-port",
            "53" if self.os_name == "ubuntu24" else "5353",
            "--dot-port",
            "853" if self.os_name == "ubuntu24" else "8530",
            "--domain",
            "panel.test",
            "--expected-ip",
            "127.0.0.1",
            "--tls",
            "existing",
            "--cert-file",
            "/testcerts/panel.pem",
            "--key-file",
            "/testcerts/panel.key",
            "--ca-file",
            "/testcerts/ca.pem",
        )

    def doctor(self, name):
        result = json.loads(self.exec(name, "./install.sh", "doctor", capture=True))
        assert result["installation_complete"] and result["api"]["status"] == "ok"

    def secure_client(self, base, metadata, state):
        context = ssl.create_default_context(
            cafile=str(self.folder / "certificates/ca.pem")
        )
        context.load_cert_chain(
            state / metadata["directory"] / "client.crt",
            state / metadata["directory"] / "client.key",
        )
        return httpx.Client(base_url=base, verify=context, trust_env=False, timeout=10)

    def run(self):
        self.prepare()
        print(self.os_name + ": source snapshot prepared", flush=True)
        first, client = self.start()
        print(self.os_name + ": first installation passed", flush=True)
        assert client.get("/healthz").json()["status"] == "ok"
        raw = self.exec(
            first, "cat", "/var/lib/donino-installer/bootstrap-access.txt", capture=True
        )
        token = raw.strip().split("#setup=", 1)[1]
        password = secrets.token_urlsafe(24)
        credentials = {"username": "native-owner", "password": password}
        assert (
            client.post(
                "/api/bootstrap", json={**credentials, "token": token}
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/api/bootstrap", json={**credentials, "token": token}
            ).status_code
            == 409
        )
        assert client.post("/api/login", json=credentials).status_code == 200
        user = client.post(
            "/api/users",
            json={"name": "native-preserved-user", "quota": 50_000_000_000},
        ).json()
        assert user["id"]
        policy = client.post(
            "/api/dns/policies", json={"name": "native resolver"}
        ).json()
        dns_account = client.post(
            "/api/dns/accounts", json={"user_id": user["id"], "policy_id": policy["id"]}
        ).json()
        query = dns.message.make_query("donino.health.", "A").to_wire()
        result = client.post(
            "/dns-query",
            content=query,
            headers={
                "Authorization": "Bearer " + dns_account["token"],
                "Content-Type": "application/dns-message",
            },
        )
        assert result.status_code == 200, result.status_code
        assert dns.message.from_wire(result.content).answer[0][0].address == "127.0.0.1"
        self.exec(
            first,
            "/opt/donino-panel/current/.venv/bin/python",
            "-c",
            """
import os,ssl,sys,time
import dns.message,dns.query
from ops.common import read_env
os.environ.update(read_env('/etc/donino/panel.env'))
from app.db import database
account=sys.argv[1]
port,dot_port=map(int,sys.argv[2:4])
with database() as db:
    db.execute('INSERT INTO dns_ip_leases VALUES(?,?,?,?)',('127.0.0.1',account,int(time.time())+60,int(time.time())))
try:
    query=dns.message.make_query('donino.health.','A')
    for method in (dns.query.udp,dns.query.tcp):
        value=method(query,'127.0.0.1',port=port,timeout=3)
        assert value.answer[0][0].address=='127.0.0.1'
    context=ssl.create_default_context(cafile='/testcerts/ca.pem')
    value=dns.query.tls(query,'127.0.0.1',port=dot_port,timeout=3,ssl_context=context,server_hostname='panel.test')
    assert value.answer[0][0].address=='127.0.0.1'
finally:
    with database() as db:
        db.execute('DELETE FROM dns_ip_leases WHERE ip=?',('127.0.0.1',))
try:
    dns.query.udp(query,'127.0.0.1',port=port,timeout=0.25)
except dns.exception.Timeout:
    pass
else:
    raise AssertionError('Unleased UDP was accepted')
""",
            dns_account["id"],
            "53" if self.os_name == "ubuntu24" else "5353",
            "853" if self.os_name == "ubuntu24" else "8530",
        )
        print(
            self.os_name
            + ": optional Unbound, authenticated HTTPS DoH and leased UDP/TCP/DoT passed",
            flush=True,
        )
        self.smart = True  # Also exercise conversion from the original TLS listener.
        self.install(first)
        smart = client.get("/api/dns/smart/status").json()
        assert smart["enabled"] and smart["gateway_ready"], smart
        self.exec(
            first,
            "/opt/donino-panel/current/.venv/bin/python",
            "-c",
            """import socket,ssl
context=ssl.create_default_context(cafile='/testcerts/ca.pem')
with socket.create_connection(('127.0.0.1',443),timeout=3) as raw:
    with context.wrap_socket(raw,server_hostname='panel.test'):
        pass
context.check_hostname=False
try:
    with socket.create_connection(('127.0.0.1',443),timeout=3) as raw:
        with context.wrap_socket(raw,server_hostname='unauthorized.example.com'):
            raise AssertionError('Non-panel SNI bypassed the Smart gateway')
except (OSError,ssl.SSLError):
    pass
""",
            capture=True,
        )
        self.doctor(first)
        assert client.get("/api/dns/accounts").json()[0]["id"] == dns_account["id"]
        node = client.post(
            "/api/nodes", json={"name": "native-mtls-node", "host": "vpn.example.com"}
        ).json()
        enrollment = client.post(f"/api/nodes/{node['id']}/enrollment").json()
        state = self.folder / "node-identity"
        metadata = enroll_node(
            str(client.base_url).rstrip("/"),
            node["id"],
            enrollment["token"],
            state,
            ca_file=self.folder / "certificates/ca.pem",
        )
        secure = self.secure_client(client.base_url, metadata, state)
        desired = secure.get("/api/agent/config")
        assert desired.status_code == 200, desired.status_code
        verify_desired(desired.json(), metadata["config_verify_key"], node["id"])
        assert (
            client.get(
                "/api/agent/config",
                headers={"Authorization": "Bearer " + node["token"]},
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/agent/config",
                headers={
                    "X-Donino-Client-Cert": (
                        state / metadata["directory"] / "client.crt"
                    )
                    .read_text()
                    .replace("\n", "%0A"),
                    "X-Donino-Client-Verify": "SUCCESS",
                    "X-Donino-Proxy-Key": "untrusted-client-header",
                },
            ).status_code
            == 401
        )
        next_private, next_csr = certificate_request()
        renewed = secure.post("/api/agent/renew-certificate", json={"csr": next_csr})
        assert renewed.status_code == 200, renewed.status_code
        metadata = save_identity(
            state,
            str(client.base_url).rstrip("/"),
            node["id"],
            renewed.json(),
            next_private,
        )
        secure.close()
        secure = self.secure_client(client.base_url, metadata, state)
        assert secure.get("/api/agent/config").status_code == 200
        with patch.dict(
            os.environ,
            {
                "DONINO_PANEL_URL": str(client.base_url).rstrip("/"),
                "DONINO_NODE_STATE": str(state),
                "DONINO_PANEL_CA_FILE": str(self.folder / "certificates/ca.pem"),
            },
        ):
            supervisor = NodeAgent()
            try:
                supervisor.authenticate_identity()
                supervisor.report()
                assert supervisor.bound
                try:
                    supervisor.validate_desired(desired.json())
                except ValueError:
                    pass
                else:
                    raise AssertionError(
                        "Node supervisor accepted an older signed config"
                    )
                supervisor.identity["expires"] = int(time.time())
                supervisor.renew_identity()
                supervisor.report()
                metadata = supervisor.identity
            finally:
                supervisor.close()
        print(
            self.os_name
            + ": real NGINX mTLS enrollment, signed config and renewal passed",
            flush=True,
        )
        print(self.os_name + ": reinstallation passed", flush=True)
        assert client.get("/api/users").json()[0]["id"] == user["id"]
        self.docker("restart", first)
        port = (
            self.docker("port", first, "443/tcp", capture=True)
            .strip()
            .rsplit(":", 1)[1]
        )
        client.base_url = "https://127.0.0.1:" + port
        for _ in range(120):
            try:
                if client.get("/healthz").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        assert client.get("/api/users").json()[0]["id"] == user["id"]
        self.doctor(first)
        setup = client.post(
            "/api/account/mfa/setup", json={"password": password}
        ).json()
        seed = setup["secret"]
        enrollment_step = int(time.time()) // 30
        assert (
            client.post(
                "/api/account/mfa/enable",
                json={"code": hotp(seed, int(time.time()) // 30)},
            ).status_code
            == 200
        )
        self.exec(first, "./install.sh", "backup")
        self.doctor(first)
        latest = self.exec(
            first,
            "python3",
            "-c",
            "from pathlib import Path; print(max(Path('/var/backups/donino').glob('*.dnb'),key=lambda p:p.stat().st_mtime))",
            capture=True,
        ).strip()
        self.docker("cp", first + ":" + latest, str(self.folder / "recover.dnb"))
        self.docker(
            "cp", first + ":/etc/donino/backup.key", str(self.folder / "restore.key")
        )
        second, restored = self.start()
        print(self.os_name + ": recovery host installed", flush=True)
        self.docker(
            "cp", str(self.folder / "recover.dnb"), second + ":/tmp/recover.dnb"
        )
        self.docker(
            "cp", str(self.folder / "restore.key"), second + ":/etc/donino/restore.key"
        )
        self.exec(
            second,
            "./install.sh",
            "restore",
            "--archive",
            "/tmp/recover.dnb",
            "--backup-key-file",
            "/etc/donino/restore.key",
            "--apply",
        )
        while int(time.time()) // 30 <= enrollment_step:
            time.sleep(0.25)
        response = restored.post(
            "/api/login",
            json={**credentials, "code": hotp(seed, int(time.time()) // 30)},
        )
        assert response.status_code == 200, response.status_code
        assert restored.get("/api/users").json()[0]["id"] == user["id"]
        assert restored.get("/api/dns/accounts").json()[0]["id"] == dns_account["id"]
        self.doctor(second)
        recovered_node = self.secure_client(restored.base_url, metadata, state)
        desired = recovered_node.get("/api/agent/config")
        assert desired.status_code == 200, desired.status_code
        verify_desired(desired.json(), metadata["config_verify_key"], node["id"])
        assert (
            restored.post(f"/api/nodes/{node['id']}/revoke-certificates").status_code
            == 200
        )
        assert recovered_node.get("/api/agent/config").status_code == 401
        recovered_node.close()
        secure.close()
        # Nonempty restore must be refused without replacing the installed DB.
        self.exec(second, "./install.sh", "uninstall")
        count = self.exec(
            second,
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-d",
            "donino",
            "-At",
            "-c",
            "SELECT count(*) FROM users",
            capture=True,
        ).strip()
        assert count == "1"
        client.close()
        restored.close()
        print(
            f"PASS {self.os_name}: systemd install/reinstall/restart, verified local HTTPS, bootstrap, encrypted backup, second-host DB+MFA restore and data-preserving uninstall. Public ACME/ISP/VM checks remain separate."
        )

    def cleanup(self):
        for name in self.containers:
            subprocess.run(
                ["docker", "--host=unix:///var/run/docker.sock", "rm", "-f", name],
                env=self.env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--os", choices=sorted(IMAGES), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="donino-native-") as folder:
        fixture = NativeFixture(args.os, folder)
        try:
            fixture.run()
        except BaseException:
            for name in fixture.containers:
                with fixture.log.open("a") as log:
                    subprocess.run(
                        [
                            "docker",
                            "--host=unix:///var/run/docker.sock",
                            "exec",
                            name,
                            "journalctl",
                            "-n",
                            "80",
                            "--no-pager",
                        ],
                        env=fixture.env,
                        text=True,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
            # Do not publish raw operation logs: future package/service output
            # may include private data. The error identifies the failing phase.
            destination = Path("/tmp/donino-native-failures")
            destination.mkdir(mode=0o700, exist_ok=True)
            preserved = destination / (args.os + "-" + secrets.token_hex(6) + ".log")
            shutil.copyfile(fixture.log, preserved)
            preserved.chmod(0o600)
            print(
                "Private diagnostic log preserved at " + str(preserved), file=sys.stderr
            )
            raise
        finally:
            fixture.cleanup()


if __name__ == "__main__":
    main()
