"""Deterministic product-source inventory; the manifest excludes itself."""

import ast
import hashlib
import json
from pathlib import Path

from .common import InstallError


def source_inventory(source):
    source = Path(source)
    allowed = {"app", "agent", "migrations", "ops", "deploy", "scripts", "docs"}
    files = []
    for path in sorted(
        source.rglob("*"), key=lambda path: str(path.relative_to(source))
    ):
        relative = path.relative_to(source)
        if relative.parts[0] not in allowed and str(relative) not in {
            "requirements.txt",
            "requirements-postgres.txt",
            "requirements.lock",
            "LICENSE",
            "README.md",
            "SECURITY.md",
            "CHANGELOG.md",
            "AGENTS.md",
            "CLAUDE.md",
            "install.sh",
        }:
            continue
        if any(
            part in {"__pycache__", ".git", ".venv", "node_modules"}
            for part in relative.parts
        ):
            continue
        if path.is_symlink():
            raise InstallError(
                "Source bundle contains a symlink; refusing ambiguous source", 3
            )
        if (
            path.is_file()
            and path.suffix not in {".pyc", ".db", ".pem", ".key"}
            and path.name != ".env"
        ):
            files.append((path, relative))
    required = {
        "app/main.py",
        "app/db.py",
        "ops/install.py",
        "requirements.txt",
        "requirements.lock",
        "LICENSE",
    }
    if not required <= {str(relative) for _, relative in files}:
        raise InstallError("Incomplete Donino source bundle", 3)
    hasher = hashlib.sha256()
    for path, relative in files:
        hasher.update(
            str(relative).encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest()
        )
    return files, hasher.hexdigest()


def build_manifest(source):
    files, checksum = source_inventory(source)
    module = ast.parse((Path(source) / "app/__init__.py").read_text())
    version = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        )
    )
    return {
        "format": "donino-source-v1",
        "version": version,
        "source_sha256": checksum,
        "files": {
            str(relative): hashlib.sha256(path.read_bytes()).hexdigest()
            for path, relative in files
        },
    }


def write_manifest(source):
    from .common import atomic_write

    result = build_manifest(source)
    atomic_write(
        Path(source) / "release-manifest.json",
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        0o644,
    )
    return result


def verify_manifest(source, *, expected=None, development=False):
    path = Path(source) / "release-manifest.json"
    actual = build_manifest(source)
    if path.exists():
        declared = json.loads(path.read_text())
        if declared != actual:
            raise InstallError(
                "Source manifest mismatch; do not install changed/incomplete release files",
                3,
            )
    elif not development and not expected:
        raise InstallError(
            "Missing release-manifest.json; use a published bundle or explicitly --development-source",
            3,
        )
    if expected and expected != actual["source_sha256"]:
        raise InstallError("Source bundle checksum mismatch", 3)
    return actual
