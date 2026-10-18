"""Private loopback-only two-role runtime from the reviewed tunnel source.

No installer, systemd service, host route or firewall is changed. Parent creates
the real rendered plan; this child runs its FRP, framed relays and gateway.
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

sys.path.insert(0, os.environ["DONINO_TEST_TUNNEL_SOURCE"])

from donino_link.config import atomic_json
from donino_link.framed import FramedRelay
from donino_link.gateway import Gateway
from donino_link.health import start_responder
from donino_link.store import Store
from donino_link.tlsfront import TLSFront


async def main(root):
    config = json.loads((root / "iran/node.json").read_text())
    foreign = json.loads((root / "foreign/node.json").read_text())
    config["policy"].update(
        probe_interval=0.2, probe_timeout=0.5, failures=1, recoveries=1
    )
    config["state_db"] = str(root / "state.db")
    # All public listeners in this lab are deliberately rebound to loopback.
    for service in config["services"]:
        service["listen"] = service["listen"].replace("0.0.0.0:", "127.0.0.1:")
    for role in ("iran", "foreign"):
        for file in (root / role / "transports").glob("*.toml"):
            file.write_text(
                file.read_text()
                .replace("/etc/donino-link/current", str(root / role))
                .replace('bindAddr = "0.0.0.0"', 'bindAddr = "127.0.0.1"')
            )
    store = Store(config["state_db"])
    gateway = Gateway(config, store)
    relays = []
    for role in ("iran", "foreign"):
        relay = json.loads((root / role / "transports/framed.json").read_text())
        relay["stats_file"] = str(root / f"framed-{role}.json")
        relays.append(FramedRelay(relay))
    port = tomllib.loads((root / "iran/transports/frp-wss.toml").read_text())[
        "bindPort"
    ]
    front = TLSFront(
        f"127.0.0.1:{port - 1000}",
        f"127.0.0.1:{port}",
        root / "iran/certs/server.crt",
        root / "iran/certs/server.key",
        root / "iran/certs/ca.crt",
    )
    # FRP honors HTTP_PROXY. Only these loopback lab subprocesses omit it; all
    # artifact downloads continue to use the managed environment proxy.
    env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")
    }
    engines, logs = {}, []

    async def start(carrier):
        for role, binary in (("iran", "frps"), ("foreign", "frpc")):
            log = (root / f"{carrier}-{role}.log").open("a")
            logs.append(log)
            engines[carrier, role] = subprocess.Popen(
                [
                    str(Path(os.environ["DONINO_TEST_FRP_DIR"]) / binary),
                    "-c",
                    str(root / role / "transports" / (carrier + ".toml")),
                ],
                stdout=log,
                stderr=log,
                env=env,
            )
        if carrier == "frp-wss":
            await front.start()

    async def stop(carrier):
        for role in ("iran", "foreign"):
            process = engines.get((carrier, role))
            if process and process.poll() is None:
                # Abrupt real process loss, rather than a mocked health flag or
                # FRP's lengthy graceful drain, is the partition control.
                process.kill()
        for role in ("iran", "foreign"):
            process = engines.get((carrier, role))
            if process:
                await asyncio.to_thread(process.wait, 3)
        if carrier == "frp-wss":
            await front.stop()

    done = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(sig, done.set)
    health = None
    try:
        health = await start_responder(
            foreign["health_listen"], config["health_key"], foreign["targets"]
        )
        for relay in relays:
            await relay.start()
        for carrier in ("frp-wss", "frp-quic"):
            await start(carrier)
        await gateway.start()
        deadline = time.monotonic() + 20
        while not all(p.healthy for p in gateway.paths.values()):
            if time.monotonic() >= deadline:
                raise RuntimeError("Real carrier health did not become ready")
            await asyncio.sleep(0.1)
        (root / "ready").touch()
        while not done.is_set():
            command = root / "command.json"
            if command.exists():
                value = json.loads(command.read_text())
                command.unlink()
                if value["action"] == "stop":
                    await stop(value["carrier"])
                elif value["action"] == "start":
                    await start(value["carrier"])
                else:
                    gateway.action(value["carrier"], "prefer")
            atomic_json(
                root / "observed.json",
                {
                    "selected": gateway.last_path,
                    "healthy": {
                        key: value.healthy for key, value in gateway.paths.items()
                    },
                    "accepted": gateway.accepted,
                },
            )
            await asyncio.sleep(0.05)
    finally:
        await gateway.stop()
        for carrier in ("frp-wss", "frp-quic"):
            await stop(carrier)
        for relay in relays:
            await relay.stop()
        if health:
            health.close()
            await health.wait_closed()
        for log in logs:
            log.close()
        store.close()


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
