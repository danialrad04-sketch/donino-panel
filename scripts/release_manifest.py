"""Generate/check the product-source manifest before committing a checkpoint."""

import argparse
import ast
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops.manifest import verify_manifest, write_manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    shell = source / "install.sh"
    content = shell.read_text()
    expected = hashlib.sha256((source / "ops/bootstrap.py").read_bytes()).hexdigest()
    module = ast.parse((source / "app/__init__.py").read_text())
    version = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        )
    )
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", version)
    if not match:
        raise SystemExit("Unsupported release version")
    tag = (
        "v"
        + match[1]
        + (
            "-" + {"a": "alpha", "b": "beta", "rc": "rc"}[match[2]] + "." + match[3]
            if match[2]
            else ""
        )
    )
    content = re.sub(r"DONINO_REF:-v[0-9A-Za-z.-]+", "DONINO_REF:-" + tag, content)
    updated = re.sub(
        r"donino_bootstrap_sha256=[0-9a-f]{64}",
        "donino_bootstrap_sha256=" + expected,
        content,
    )
    if args.check and shell.read_text() != updated:
        raise SystemExit("Bootstrap hash is outdated; regenerate the release manifest")
    if not args.check:
        shell.write_text(updated)
    result = verify_manifest(source) if args.check else write_manifest(source)
    print(
        "Source manifest "
        + ("verified" if args.check else "generated")
        + ": "
        + result["source_sha256"]
    )


if __name__ == "__main__":
    main()
