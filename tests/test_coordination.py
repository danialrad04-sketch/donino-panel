import copy
import importlib.util
import json
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
        for changes in (
            {"task_id": "other"},
            {"branch": "main"},
            {"status": "waiting_for_review"},
            {"status": "blocked"},
        ):
            with self.assertRaises(ValueError):
                coordination.validate({**checkpoint, **changes}, task)
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
