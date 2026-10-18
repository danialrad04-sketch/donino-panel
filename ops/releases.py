"""Prepare an immutable, verified Python role release without activating it."""

import json
import os
import sys
from pathlib import Path

from .common import InstallError, atomic_write, run
from .manifest import source_inventory, verify_manifest


def prepare(source, base, *, expected=None, development=False):
    manifest = verify_manifest(source, expected=expected, development=development)
    files, checksum = source_inventory(source)
    base = Path(base)
    release = base / "releases" / checksum[:20]
    for directory in (base, base / "releases", release):
        directory.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(directory, 0o755)
    for path, relative in files:
        target = release / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        for parent in (target.parent, *target.parent.parents):
            if parent == release.parent:
                break
            os.chmod(parent, 0o755)
        if target.exists() and target.read_bytes() != path.read_bytes():
            raise InstallError(
                "Immutable exit release was modified; refusing overwrite", 3
            )
        if not target.exists():
            atomic_write(target, path.read_bytes(), 0o644)
    if not (release / ".venv/bin/python").exists():
        run([sys.executable, "-m", "venv", str(release / ".venv")], code=3)
    run(
        [
            str(release / ".venv/bin/python"),
            "-m",
            "pip",
            "install",
            "-r",
            str(release / "requirements.txt"),
        ],
        code=3,
    )
    atomic_write(
        release / "release-manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        0o644,
    )
    return release
