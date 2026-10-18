"""Optional unprivileged singleton. No API, listener, shell or installation."""

import os
import signal
import threading
import uuid

from app import tunnel_monitor, tunnel_probe
from app.db import database, schema_version, SCHEMA_VERSION
from app.tunnel_api import call


def main():
    if not tunnel_monitor.configured() or not tunnel_probe.available():
        raise SystemExit(
            "Tunnel monitor requires opt-in, bridge and verifier configuration"
        )
    with database() as db:
        if schema_version(db) != SCHEMA_VERSION:
            raise SystemExit("Migrate the control database before starting the monitor")
    stop = threading.Event()
    instance = uuid.uuid4().hex
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if not tunnel_monitor.heartbeat(instance):
        raise SystemExit("Another tunnel monitor owns the live lease")

    def pulse():
        while not stop.wait(5):
            try:
                if not tunnel_monitor.heartbeat(instance):
                    stop.set()
                    return
            except Exception:
                stop.set()
                return

    thread = threading.Thread(target=pulse, daemon=True)
    thread.start()
    try:
        while not stop.is_set():
            # A slow-drip local controller must not extend a claim indefinitely.
            # Exiting also kills the verifier via its Linux parent-death signal.
            watchdog = threading.Timer(
                tunnel_monitor.CLAIM_SECONDS - 30, lambda: os._exit(1)
            )
            watchdog.daemon = True
            watchdog.start()
            try:
                worked = tunnel_monitor.run_due(instance, call, stopping=stop.is_set)
            finally:
                watchdog.cancel()
            if not worked:
                stop.wait(2)
    finally:
        stop.set()
        thread.join(timeout=6)
        tunnel_monitor.release(instance)


if __name__ == "__main__":
    main()
