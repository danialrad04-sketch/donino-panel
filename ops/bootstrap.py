"""Standalone stdlib-only downloader for a pinned Donino source release.

install.sh verifies this file's SHA-256 before execution. No downloaded product
module is imported until every product file and the inventory are verified.
"""

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

REPOSITORY = "danialrad04-sketch/donino-panel"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_UNPACKED = 256 * 1024 * 1024


def fetch(url, limit):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("Release download exceeds its size limit")
    return data


def unpack_verified(data, manifest, destination):
    if manifest.get("format") != "donino-source-v1" or not isinstance(
        manifest.get("files"), dict
    ):
        raise RuntimeError("Invalid source release manifest")
    inventory = manifest["files"]
    if not {"ops/install.py", "app/main.py", "LICENSE", "requirements.lock"} <= set(
        inventory
    ):
        raise RuntimeError("Incomplete source release inventory")
    hasher = hashlib.sha256()
    for name, expected in sorted(inventory.items()):
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or any(part in {".", "..", "__pycache__"} for part in path.parts)
            or "\x00" in name
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise RuntimeError("Unsafe source manifest entry")
        hasher.update(name.encode() + b"\0" + bytes.fromhex(expected))
    if hasher.hexdigest() != manifest.get("source_sha256"):
        raise RuntimeError("Source inventory digest mismatch")
    found = set()
    total = 0
    destination = Path(destination)
    with tempfile.TemporaryFile() as unpacked:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            while chunk := compressed.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UNPACKED:
                    raise RuntimeError("Release archive exceeds unpacked size limit")
                unpacked.write(chunk)
        unpacked.seek(0)
        _extract_tar(unpacked, inventory, destination, found)
    if found != set(inventory):
        raise RuntimeError("Release archive is missing product files")
    (destination / "release-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    )


def _extract_tar(unpacked, inventory, destination, found):
    prefix = None
    count = 0
    with tarfile.open(fileobj=unpacked, mode="r:") as archive:
        for member in archive:
            count += 1
            if count > 10000:
                raise RuntimeError("Release archive contains too many entries")
            name = PurePosixPath(member.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or not (member.isdir() or member.isfile())
            ):
                raise RuntimeError("Unsafe archive path or member type")
            if not name.parts:
                continue
            if prefix is None:
                prefix = name.parts[0]
            if name.parts[0] != prefix:
                raise RuntimeError("Release archive has multiple roots")
            if member.isdir():
                continue
            relative = str(PurePosixPath(*name.parts[1:]))
            if relative not in inventory:
                continue
            if relative in found:
                raise RuntimeError("Duplicate release archive entry")
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with archive.extractfile(member) as source, path.open("xb") as target:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    target.write(chunk)
            if digest.hexdigest() != inventory[relative]:
                raise RuntimeError("Release file checksum mismatch")
            path.chmod(0o644)
            found.add(relative)


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--ref", required=True)
    args, remaining = parser.parse_known_args(argv)
    if not re.fullmatch(
        r"(?:[0-9a-f]{40}|v\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?)", args.ref
    ):
        raise RuntimeError("Use a version tag or full commit ID, not a moving branch")
    manifest = json.loads(
        fetch(
            f"https://raw.githubusercontent.com/{REPOSITORY}/{args.ref}/release-manifest.json",
            1024 * 1024,
        )
    )
    archive = fetch(
        f"https://github.com/{REPOSITORY}/archive/{args.ref}.tar.gz", MAX_DOWNLOAD
    )
    with tempfile.TemporaryDirectory(prefix="donino-source-") as folder:
        unpack_verified(archive, manifest, folder)
        # Isolated interpreter ignores PYTHONPATH/user-site; add only verified
        # source to the module path before importing the installer.
        script = "import sys; sys.path.insert(0,sys.argv.pop(1)); from ops.install import main; raise SystemExit(main())"
        return subprocess.run(
            [sys.executable, "-I", "-c", script, folder, *remaining], cwd=folder
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
