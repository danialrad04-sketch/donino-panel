"""Pull-based node agent. Owns one Xray process; no shell commands or remote exec."""
import json
import logging
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx

log = logging.getLogger('donino-node')


def parse_stats(data):
    users = {}
    for stat in data.get('stat', []):
        parts = stat.get('name', '').split('>>>')
        if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic':
            continue
        if parts[3] not in ('uplink', 'downlink'):
            continue
        value = int(stat.get('value', 0))
        if value < 0:
            raise ValueError('Negative Xray counter')
        user = users.setdefault(parts[1], {'user_id': parts[1], 'up': 0, 'down': 0})
        user['up' if parts[3] == 'uplink' else 'down'] = value
    return list(users.values())


class NodeAgent:
    def __init__(self):
        base = os.environ['DONINO_PANEL_URL'].rstrip('/')
        parsed = urlsplit(base)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')):
            raise ValueError('Panel URL must use HTTPS (HTTP only allowed on loopback)')
        self.client = httpx.Client(base_url=base, timeout=12, follow_redirects=False,
                                   headers={'Authorization': 'Bearer ' + os.environ['DONINO_NODE_TOKEN']})
        self.binary = os.environ.get('DONINO_XRAY', '/usr/local/bin/xray')
        self.directory = Path(os.environ.get('DONINO_NODE_STATE', 'node-state')).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.proc = None
        self.epoch = str(uuid.uuid4())
        self.revision = ''
        self.last_contact = time.monotonic()
        self.stop_requested = False
        self.max_stale = int(os.environ.get('DONINO_MAX_STALE_SECONDS', '120'))
        if self.max_stale < 15:
            raise ValueError('Maximum stale time must be at least 15 seconds')
        self.interval = 5
        self.usage = []

    def stop_core(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    def snapshot(self):
        if not self.proc or self.proc.poll() is not None:
            return self.usage
        result = subprocess.run([self.binary, 'api', 'statsquery', '-s=127.0.0.1:10085',
                                 '-pattern=user>>>', '-reset=false'],
                                capture_output=True, text=True, timeout=8, check=True)
        self.usage = parse_stats(json.loads(result.stdout))
        return self.usage

    def apply(self, desired):
        config = desired['config']
        # Defense in depth: pin the management API to loopback.
        api = next((i for i in config['inbounds'] if i.get('tag') == 'api'), None)
        if not api or api.get('listen') != '127.0.0.1' or api.get('port') != 10085:
            raise ValueError('Invalid local management endpoint')
        path = self.directory / 'candidate.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(config, file)
        # Keep the running process/config intact if validation fails.
        result = subprocess.run([self.binary, 'run', '-test', '-c', str(path)],
                                capture_output=True, timeout=15)
        if result.returncode:
            raise ValueError('Xray config validation failed; check node certificates and Xray version')
        # Report the last obtainable counters before replacing a running process.
        self.report()
        self.stop_core()
        active = self.directory / 'config.json'
        path.replace(active)
        self.epoch = str(uuid.uuid4())
        self.usage = []
        self.proc = subprocess.Popen([self.binary, 'run', '-c', str(active)],
                                     stdout=subprocess.DEVNULL, stderr=None)
        time.sleep(0.4)
        if self.proc.poll() is not None:
            raise RuntimeError('Xray exited on startup; inspect the node service log')
        self.revision = desired['revision']
        log.info('Applied revision %s', self.revision[:12])

    def report(self, error=''):
        result = self.client.post('/api/agent/heartbeat', json={
            'epoch': self.epoch, 'applied_revision': self.revision,
            'usage': self.snapshot(), 'error': error})
        result.raise_for_status()

    def tick(self):
        self.report()
        response = self.client.get('/api/agent/config')
        response.raise_for_status()
        desired = response.json()
        if desired['revision'] != self.revision or not self.proc or self.proc.poll() is not None:
            self.apply(desired)
        self.last_contact = time.monotonic()

    def run(self):
        def stop(*_):
            self.stop_requested = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            while not self.stop_requested:
                try:
                    self.tick()
                except Exception as error:
                    # Avoid logging HTTP request URLs/headers, which can contain secrets.
                    log.warning('Node synchronization failed (%s)', type(error).__name__)
                    if isinstance(error, httpx.HTTPStatusError) and error.response.status_code in (401, 403):
                        self.stop_core()
                    try:
                        self.report('Node synchronization or Xray error; inspect node service')
                    except Exception:
                        pass
                    if time.monotonic() - self.last_contact >= self.max_stale:
                        log.warning('Panel unavailable beyond grace period; stopping Xray')
                        self.stop_core()
                for _ in range(self.interval * 5):
                    if self.stop_requested:
                        break
                    time.sleep(0.2)
        finally:
            try:
                self.report('Node agent stopping')
            except Exception:
                pass
            self.stop_core()
            self.client.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    NodeAgent().run()
