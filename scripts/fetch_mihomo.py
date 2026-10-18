"""Download the pinned Linux amd64 Mihomo release and verify its SHA-256 before use.

The release is a gzip-compressed single binary. Both the download and the
decompressed output are size-bounded. Nothing is written into the repository:
pass a destination outside the working tree, for example a scratch directory.
"""

import argparse
import gzip
import hashlib
import io
import platform
import shutil
import urllib.request
from pathlib import Path

VERSION = "v1.19.32"
ASSET = "mihomo-linux-amd64-compatible-v1.19.32.gz"
# SHA-256 of the .gz asset as published by MetaCubeX/mihomo, checked against the GitHub metadata.
SHA256 = "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"
URL = f"https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{ASSET}"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_BINARY = 256 * 1024 * 1024
CHUNK = 1024 * 1024


def _download(url):
    digest = hashlib.sha256()
    data = bytearray()
    with urllib.request.urlopen(url, timeout=120) as response:
        while chunk := response.read(CHUNK):
            data.extend(chunk)
            if len(data) > MAX_DOWNLOAD:
                raise SystemExit("Download exceeds the size limit; refusing to continue.")
            digest.update(chunk)
    return bytes(data), digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        parser.error(
            "This verified download is Linux amd64 only; build or fetch the Mihomo asset for your platform manually."
        )
    if args.destination.exists() and any(args.destination.iterdir()):
        parser.error("Use an empty destination; existing installations are not overwritten.")

    print("Downloading Mihomo", VERSION)
    data, digest = _download(URL)
    if digest != SHA256:
        raise SystemExit("SHA-256 mismatch; refusing to extract.")

    args.destination.mkdir(parents=True, exist_ok=True)
    target = args.destination / "mihomo"
    written = 0
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as source, open(target, "wb") as out:
        while chunk := source.read(CHUNK):
            written += len(chunk)
            if written > MAX_BINARY:
                raise SystemExit("Decompressed binary exceeds the size limit; refusing to continue.")
            out.write(chunk)
    target.chmod(0o755)
    print("Verified Mihomo installed at", target.resolve())


if __name__ == "__main__":
    main()
