"""Download the tested Linux amd64 Xray release and verify its pinned SHA-256."""

import argparse
import hashlib
import io
import platform
import urllib.request
import zipfile
from pathlib import Path

VERSION = "v26.3.27"
SHA256 = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
URL = f"https://github.com/XTLS/Xray-core/releases/download/{VERSION}/Xray-linux-64.zip"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        parser.error(
            "This verified download is Linux amd64 only; install the official asset for your architecture manually."
        )
    if args.destination.exists() and any(args.destination.iterdir()):
        parser.error(
            "Use an empty destination; existing installations are not overwritten."
        )
    print("Downloading", VERSION)
    with urllib.request.urlopen(URL, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("SHA-256 mismatch; refusing to extract.")
    args.destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in ("xray", "geoip.dat", "geosite.dat", "LICENSE"):
            if name in archive.namelist():
                (args.destination / name).write_bytes(archive.read(name))
    (args.destination / "xray").chmod(0o755)
    print("Verified Xray installed at", args.destination.resolve())


if __name__ == "__main__":
    main()
