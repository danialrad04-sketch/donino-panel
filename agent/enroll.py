"""Register a node with a one-use token; its private key never leaves this host."""

import argparse
import fcntl
import os
import sys
from pathlib import Path

from .identity import certificate_request, panel_client, save_identity, validate_origin
from .journal import UsageJournal
from app.node_identity import private_bytes
from ops.common import atomic_write


def enroll(panel, node_id, token, directory, *, ca_file=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(directory / "agent.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                "Stop the node supervisor before changing its identity"
            ) from exc
        return _enroll(panel, node_id, token, directory, ca_file=ca_file)


def _enroll(panel, node_id, token, directory, *, ca_file=None):
    panel = validate_origin(panel)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    UsageJournal(directory / "usage.db").bind(panel, node_id)
    # Persist the key before sending the CSR, so an interrupted handoff is recoverable.
    pending = directory / "enrollment-pending.key"
    if pending.exists():
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(private_bytes(pending), password=None)
        private, csr = certificate_request(key)
    else:
        private, csr = certificate_request()
        atomic_write(pending, private)
    with panel_client(panel, ca_file=ca_file) as client:
        result = client.post(
            "/api/agent/enroll", json={"node_id": node_id, "token": token, "csr": csr}
        )
        result.raise_for_status()
        metadata = save_identity(directory, panel, node_id, result.json(), private)
    pending.unlink(missing_ok=True)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(os.environ.get("DONINO_NODE_STATE", "/var/lib/donino-node")),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--token-file", type=Path)
    source.add_argument("--token-stdin", action="store_true")
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    token = (
        private_bytes(args.token_file).decode().strip()
        if args.token_file
        else sys.stdin.readline(256).strip()
    )
    try:
        enroll(args.panel, args.node_id, token, args.state, ca_file=args.ca_file)
    except Exception as exc:
        parser.exit(
            2,
            "Enrollment failed ("
            + type(exc).__name__
            + "); no credentials were printed.\n",
        )
    print(
        "Node enrolled. The private key and pinned verification key are stored in its private state directory."
    )


if __name__ == "__main__":
    main()
