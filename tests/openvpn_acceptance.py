"""Run the real OpenVPN lab in a disposable Docker namespace.

--no-build reuses only installed OS/dependencies; current product source is
always copied from the allowlisted inventory, never from a stale image layer.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops.manifest import source_inventory

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--split-routes", action="store_true")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        )
    }
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    image = "donino-openvpn-test:debian12"
    if not args.no_build:
        subprocess.run(
            docker
            + [
                "build",
                "--secret",
                "id=system_ca,src=/etc/ssl/certs/ca-certificates.crt",
                "-f",
                "tests/openvpn/Dockerfile",
                "-t",
                image,
                ".",
            ],
            cwd=ROOT,
            env=env,
            check=True,
        )
    with tempfile.TemporaryDirectory(prefix="donino-ovpn-source-") as folder:
        source = Path(folder)
        files, checksum = source_inventory(ROOT)
        for origin, relative in files:
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, target)
        shutil.copyfile(ROOT / "tests/openvpn/network.py", source / "network.py")
        name = "donino-ovpn-" + uuid.uuid4().hex[:12]
        try:
            subprocess.run(
                docker
                + [
                    "create",
                    "--rm",
                    "--privileged",
                    "--name",
                    name,
                    "-e",
                    "DONINO_TEST_OVPN_PROTOCOL=" + args.protocol,
                    "-e",
                    "DONINO_TEST_OVPN_SPLIT=" + ("1" if args.split_routes else "0"),
                    image,
                ],
                env=env,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                docker + ["cp", str(source) + "/.", name + ":/source"],
                env=env,
                check=True,
            )
            print(
                "Current product source:",
                checksum,
                "protocol:",
                args.protocol,
                flush=True,
            )
            result = subprocess.run(docker + ["start", "--attach", name], env=env)
            if result.returncode:
                raise SystemExit(result.returncode)
        finally:
            subprocess.run(
                docker + ["rm", "-f", name],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
