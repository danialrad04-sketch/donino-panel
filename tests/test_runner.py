import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == "linux", "Linux parent-death semantics")
class RunnerTest(unittest.TestCase):
    def test_engine_dies_after_supervisor_is_killed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "fixture-engine"
            binary.write_text(
                "#!"
                + sys.executable
                + "\nimport os,time\nfrom pathlib import Path\nPath(os.environ['DONINO_RUNNER_TEST_MARKER']).write_text(str(os.getpid()))\ntime.sleep(60)\n"
            )
            binary.chmod(0o700)
            # An isolated subreaper owns the orphan, even if PID 1 is PostgreSQL.
            # Leaving a SIGKILL orphan for postmaster to reap can restart that DB.
            helper = textwrap.dedent("""
                import ctypes, os, signal, subprocess, sys, time
                from pathlib import Path
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.prctl(36, 1, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), 'subreaper')
                binary, marker = Path(sys.argv[1]), Path(sys.argv[2])
                script = "import os,subprocess,sys,time; subprocess.Popen([sys.executable,'-m','agent.runner','--parent',str(os.getpid()),'--binary',sys.argv[1],'--config',sys.argv[2]]); time.sleep(60)"
                parent = subprocess.Popen(
                    [sys.executable, '-c', script, str(binary), str(binary.parent / 'unused.json')],
                    env={**os.environ, 'DONINO_RUNNER_TEST_MARKER': str(marker)},
                )
                child = None
                reaped = False
                try:
                    until = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < until:
                        time.sleep(0.02)
                    assert marker.exists(), 'Fixture engine did not start'
                    child = int(marker.read_text())
                    parent.kill()
                    parent.wait(timeout=5)
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        pid, status = os.waitpid(child, os.WNOHANG)
                        if pid:
                            reaped = True
                            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, 'Engine did not receive parent-death signal'
                            break
                        time.sleep(0.02)
                    assert reaped, 'Engine survived its supervisor'
                finally:
                    if parent.poll() is None:
                        parent.kill()
                        parent.wait(timeout=5)
                    if child and not reaped:
                        os.kill(child, signal.SIGKILL)
                        os.waitpid(child, 0)
            """)
            result = subprocess.run(
                [sys.executable, "-c", helper, str(binary), str(root / "child.pid")],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
