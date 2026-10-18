"""Independent exit systemd acceptance; no control DB, WAN or game claim."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_acceptance import IMAGES, NativeFixture


class ExitFixture(NativeFixture):
    def install(self, name):
        self.exec(
            name,
            "./install.sh",
            "--role",
            "smart-exit",
            "--domain",
            "panel.test",
            "--expected-ip",
            "127.0.0.1",
            "--exit-listen",
            "127.0.0.1",
            "--exit-port",
            "9445",
            "--exit-allow-domain",
            "allowed.example.com",
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
        try:
            result = json.loads(
                self.exec(
                    name, "./install.sh", "doctor", "--role", "smart-exit", capture=True
                )
            )
        except BaseException:
            with self.log.open("a") as log:
                log.write(
                    self.exec(
                        name,
                        "journalctl",
                        "-u",
                        "donino-smart-exit",
                        "-n",
                        "60",
                        "--no-pager",
                        capture=True,
                    )
                )
            raise
        assert result["tls_auth"] == "ok" and not result["application_verified"]

    def run(self):
        self.prepare()
        name, unused = self.start()
        unused.close()
        self.doctor(name)
        print(
            self.os_name + ": standalone exit install and verified TLS/auth passed",
            flush=True,
        )
        digest = self.exec(
            name,
            "python3",
            "-c",
            "import hashlib; print(hashlib.sha256(open('/etc/donino-smart-exit/gateway-access.json','rb').read()).hexdigest())",
            capture=True,
        ).strip()
        self.exec(
            name,
            "/opt/donino-smart-exit/current/.venv/bin/python",
            "-c",
            """import asyncio,json,os,stat
from pathlib import Path
from app.smart_wire import connect_exit,close
assert not Path('/etc/donino/panel.env').exists()
assert not Path('/etc/postgresql').exists()
assert not Path('/var/lib/donino-panel').exists()
assert stat.S_IMODE(Path('/etc/donino-smart-exit/gateway-access.json').stat().st_mode)==0o600
assert stat.S_IMODE(Path('/var/lib/donino-smart-exit/exit.json').stat().st_mode)==0o600
import subprocess
for path in ('/etc/donino-smart-exit/gateway-access.json','/var/lib/donino-smart-exit/exit.json'):
    assert subprocess.run(['runuser','-u','nobody','--','cat',path],capture_output=True).returncode!=0
assert subprocess.check_output(['systemctl','show','donino-smart-exit','--value','-p','AmbientCapabilities'],text=True).strip()==''
access=json.load(open('/etc/donino-smart-exit/gateway-access.json'))
config=json.load(open('/var/lib/donino-smart-exit/exit.json'))
assert 'password' not in config and access['password'] not in json.dumps(config)
access['host']='127.0.0.1'
async def test():
    for kwargs,change in (({}, {'password':'wrong-private-credential'}),({}, {'sni':'wrong.example.com'}),({'ca':None},{}),({'host':'blocked.example.com'},{})):
        writer=None
        try:
            options={'ca':'/testcerts/ca.pem',**kwargs}
            _,writer=await connect_exit({**access,**change},**options)
        except (OSError,ValueError,asyncio.IncompleteReadError):
            continue
        finally:
            await close(writer)
        raise AssertionError('Exit accepted a forbidden peer/domain')
asyncio.run(test())
""",
            capture=True,
        )
        self.exec(name, "./install.sh", "upgrade", "--role", "smart-exit")
        repeated = self.exec(
            name,
            "python3",
            "-c",
            "import hashlib; print(hashlib.sha256(open('/etc/donino-smart-exit/gateway-access.json','rb').read()).hexdigest())",
            capture=True,
        ).strip()
        assert digest == repeated
        self.exec(
            name,
            "python3",
            "-c",
            """from pathlib import Path
import os,shutil,subprocess
folder=Path('/testcerts/donino-smart-exit'); folder.mkdir()
shutil.copyfile('/testcerts/panel.pem',folder/'fullchain.pem')
shutil.copyfile('/testcerts/panel.key',folder/'privkey.pem')
env={**os.environ,'RENEWED_LINEAGE':str(folder)}
command=['./install.sh','renew-certificate','--role','smart-exit']
assert subprocess.run(command,env=env,capture_output=True).returncode==0
before=Path('/etc/donino-smart-exit/tls/panel.key').read_bytes()
pid=subprocess.check_output(['systemctl','show','donino-smart-exit','--value','-p','MainPID'])
(folder/'privkey.pem').write_text('invalid test key')
assert subprocess.run(command,env=env,capture_output=True).returncode!=0
assert Path('/etc/donino-smart-exit/tls/panel.key').read_bytes()==before
assert subprocess.check_output(['systemctl','show','donino-smart-exit','--value','-p','MainPID'])==pid
""",
            capture=True,
        )
        self.doctor(name)
        self.docker("restart", name)
        self.doctor(name)
        self.exec(
            name,
            "python3",
            "-c",
            """from pathlib import Path
import subprocess
access=Path('/etc/donino-smart-exit/gateway-access.json')
private=access.read_bytes()
try:
    for mutation in ('invalid','missing'):
        if mutation=='invalid':
            access.write_text('{}')
        else:
            access.unlink()
        assert subprocess.run(['./install.sh','upgrade','--role','smart-exit'],capture_output=True).returncode!=0
        assert subprocess.run(['systemctl','is-active','--quiet','donino-smart-exit']).returncode==0
        access.write_bytes(private)
        access.chmod(0o600)
finally:
    access.write_bytes(private)
    access.chmod(0o600)
path=Path('/etc/systemd/system/donino-smart-exit.service')
old=path.read_bytes()
try:
    path.write_bytes(old+b'\\n# local change\\n')
    command=['./install.sh','uninstall','--role','smart-exit']
    assert subprocess.run(command,capture_output=True).returncode!=0
    assert subprocess.run(['systemctl','is-active','--quiet','donino-smart-exit']).returncode==0
finally:
    path.write_bytes(old)
""",
            capture=True,
        )
        self.exec(name, "./install.sh", "uninstall", "--role", "smart-exit")
        self.exec(
            name,
            "python3",
            "-c",
            """from pathlib import Path
assert Path('/etc/donino-smart-exit/gateway-access.json').is_file()
assert Path('/var/lib/donino-smart-exit/exit.json').is_file()
assert not Path('/etc/systemd/system/donino-smart-exit.service').exists()
""",
            capture=True,
        )
        print(
            "PASS "
            + self.os_name
            + ": independent exit install/reinstall/restart, private stable credential, verified TLS/auth, bad TLS/auth/domain refusal, renewal and bad-pair rollback, modified-file refusal and preserving uninstall; no control DB installed.",
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--os", choices=sorted(IMAGES), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="donino-exit-native-") as folder:
        fixture = ExitFixture(args.os, folder)
        try:
            fixture.run()
        except BaseException:
            import secrets
            import shutil

            destination = Path("/tmp/donino-native-failures")
            destination.mkdir(mode=0o700, exist_ok=True)
            target = destination / (
                "exit-" + args.os + "-" + secrets.token_hex(6) + ".log"
            )
            shutil.copyfile(fixture.log, target)
            target.chmod(0o600)
            print("Private diagnostic log: " + str(target), file=sys.stderr)
            raise
        finally:
            fixture.cleanup()


if __name__ == "__main__":
    main()
