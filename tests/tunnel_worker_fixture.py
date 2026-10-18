"""Read-only lab + real upstream preview. Does not install or contact two servers."""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.environ["DONINO_TEST_TUNNEL_SOURCE"])
from aiohttp import web
from donino_link.config import atomic_json
from donino_link.panel import password_record
from donino_link.provision import Worker, application


async def main():
    root = Path(sys.argv[1])
    config = {
        "schema": 1,
        "role": "iran",
        "health_key": "ab" * 32,
        "services": [{"id": "echo", "listen": "127.0.0.1:12345"}],
        "paths": [
            {
                "id": "primary",
                "priority": 10,
                "health": "127.0.0.1:12346",
                "backends": {"echo": "127.0.0.1:12347"},
            }
        ],
        "policy": {
            "probe_interval": 3,
            "probe_timeout": 2,
            "failures": 3,
            "recoveries": 2,
            "connect_timeout": 2,
            "idle_timeout": 300,
            "max_connections": 20,
        },
        "panel": {
            "listen": "127.0.0.1:8090",
            "credentials_file": str(root / "admin.json"),
            "api_token_file": str(root / "api-token"),
        },
        "state_db": str(root / "state.sqlite3"),
    }
    atomic_json(root / "node.json", config)
    atomic_json(root / "admin.json", password_record("fixture-long-password-only"))
    (root / "api-token").write_text("fixture-only-token")
    worker = Worker(root / "control", root / "node.json")
    # Host discovery is outside this contract test; never inspect/mutate host units.
    worker.inventory.scan = lambda: {"services": []}
    atomic_json(
        worker.root / "profiles.json",
        [
            {
                "id": "a" * 32,
                "name": "foreign",
                "host": "198.51.100.20",
                "management": "https-v1",
                "agent_port": 9444,
                "panel_listen": "127.0.0.1:8091",
                "agent_token": "private-fixture-token",
            }
        ],
    )
    runner = web.AppRunner(application(worker), access_log=None)
    await runner.setup()
    sock = root / "worker.sock"
    await web.UnixSite(runner, str(sock)).start()
    sock.chmod(0o660)
    (root / "ready").write_text(json.dumps({"ready": True}))
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
