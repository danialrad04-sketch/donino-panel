import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "coordination", ROOT / "scripts/coordination.py"
)
coordination = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coordination)


class CoordinationTest(unittest.TestCase):
    def test_assignment_is_resumable_and_review_requires_evidence(self):
        task = coordination.assignment(ROOT, "claude")
        checkpoint = coordination.read(coordination.inside(ROOT, task["checkpoint"]))
        coordination.validate(checkpoint, task)
        # The tracked checkpoint is mutable workflow data. It may already be a
        # valid review handoff; invalid-transition fixtures must be explicit.
        incomplete = {
            **checkpoint,
            "status": "assigned",
            "last_verified_commit": None,
            "remaining": ["acceptance pending"],
            "tests": [],
            "blockers": [],
            "pr_url": None,
        }
        for changes in (
            {"task_id": "other"},
            {"branch": "main"},
            {"status": "waiting_for_review"},
            {"status": "blocked"},
        ):
            with self.assertRaises(ValueError):
                coordination.validate({**incomplete, **changes}, task)
        complete = {
            **checkpoint,
            "status": "waiting_for_review",
            "remaining": [],
            "tests": ["test suite passed"],
            "last_verified_commit": "a" * 40,
            "pr_url": "https://github.com/danialrad04-sketch/donino-panel/pull/13",
        }
        coordination.validate(complete, task)

    def test_paths_and_secret_checkpoint_rejected_and_save_is_valid_json(self):
        task = coordination.assignment(ROOT, "claude")
        data = copy.deepcopy(
            coordination.read(coordination.inside(ROOT, task["checkpoint"]))
        )
        with self.assertRaises(ValueError):
            coordination.inside(ROOT, "../../outside.json")
        data["next_action"] = "-----BEGIN PRIVATE KEY-----"
        with self.assertRaises(ValueError):
            coordination.validate(data, task)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "checkpoint.json"
            coordination.save(path, {"valid": True})
            self.assertEqual(json.loads(path.read_text()), {"valid": True})
            self.assertEqual(len(list(path.parent.iterdir())), 1)

    def test_cli_checkpoint_keeps_manifest_valid_and_invalid_input_changes_neither(
        self,
    ):
        from ops.manifest import source_inventory

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "source"
            for source, relative in source_inventory(ROOT)[0]:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            task = coordination.assignment(root, "claude")
            checkpoint = coordination.inside(root, task["checkpoint"])
            data = coordination.read(checkpoint)
            data["next_action"] = (
                "A different, persisted next action in the isolated test"
            )
            supplied = Path(folder) / "input.json"
            supplied.write_text(json.dumps(data))
            command = [
                sys.executable,
                str(root / "scripts/coordination.py"),
                "checkpoint",
                "--actor",
                "claude",
                "--input",
                str(supplied),
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            checked = subprocess.run(
                [sys.executable, str(root / "scripts/release_manifest.py"), "--check"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            manifest = root / "release-manifest.json"
            before = checkpoint.read_bytes(), manifest.read_bytes()
            supplied.write_text(json.dumps({**data, "task_id": "wrong-task"}))
            refused = subprocess.run(command, capture_output=True, timeout=20)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual((checkpoint.read_bytes(), manifest.read_bytes()), before)
