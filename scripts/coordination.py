#!/usr/bin/env python3
"""Validate and atomically save a Git-based contributor handoff; no task execution."""

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {
    "task_id",
    "status",
    "branch",
    "last_verified_commit",
    "completed",
    "remaining",
    "next_action",
    "tests",
    "blockers",
    "pr_url",
}
STATES = {"assigned", "in_progress", "blocked", "waiting_for_review"}


def read(path):
    if path.stat().st_size > 65536:
        raise ValueError("Coordination file exceeds 64 KiB")
    return json.loads(path.read_text())


def inside(root, relative):
    if not isinstance(relative, str):
        raise ValueError("Invalid coordination path")
    path = (root / relative).resolve()
    if not path.is_relative_to(root / "docs/coordination"):
        raise ValueError("Coordination path escapes its directory")
    return path


def assignment(root, actor):
    data = read(root / "docs/coordination/assignments.json")
    if data.get("format") != "donino-coordination-v1":
        raise ValueError("Unknown coordination format")
    item = data["assignments"][actor]
    if not re.fullmatch(r"[a-z0-9-]{1,80}", item["task_id"]):
        raise ValueError("Invalid task ID")
    if not inside(root, item["document"]).is_file():
        raise ValueError("Task document is missing")
    inside(root, item["checkpoint"])
    return item


def validate(data, task):
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError("Checkpoint fields differ from the documented format")
    if data["task_id"] != task["task_id"] or data["branch"] != task["branch"]:
        raise ValueError("Checkpoint belongs to a different task or branch")
    if data["status"] not in STATES:
        raise ValueError("Invalid checkpoint status")
    sha = data["last_verified_commit"]
    if sha is not None and (
        not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
    ):
        raise ValueError("Verified commit must be a full SHA or null")
    for key in ("completed", "remaining", "tests", "blockers"):
        rows = data[key]
        if (
            not isinstance(rows, list)
            or len(rows) > 100
            or any(
                not isinstance(row, str) or not 1 <= len(row) <= 2000 for row in rows
            )
        ):
            raise ValueError("Checkpoint lists must contain bounded text")
    if (
        not isinstance(data["next_action"], str)
        or not 1 <= len(data["next_action"]) <= 2000
    ):
        raise ValueError("A concrete next action is required")
    url = data["pr_url"]
    if url is not None and (
        not isinstance(url, str)
        or not re.fullmatch(
            r"https://github\.com/danialrad04-sketch/donino-panel/pull/[1-9][0-9]*", url
        )
    ):
        raise ValueError("PR URL must identify this repository")
    if data["status"] == "waiting_for_review" and (
        not url or data["remaining"] or not data["tests"] or not sha
    ):
        raise ValueError(
            "Review handoff requires PR, verified commit, tests and no remaining acceptance steps"
        )
    if data["status"] == "blocked" and not data["blockers"]:
        raise ValueError("Blocked status requires a concrete blocker")
    serialized = json.dumps(data)
    if re.search(
        r"PRIVATE KEY|donino1\.[0-9a-f]{64}\.|dnk_[A-Za-z0-9_-]{20,}", serialized
    ):
        raise ValueError("Possible credential in checkpoint; redact before saving")
    return data


def save(path, data):
    payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if len(payload.encode()) > 65536:
        raise ValueError("Checkpoint exceeds 64 KiB")
    fd, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "check", "checkpoint"))
    parser.add_argument("--actor")
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "check":
            actors = (
                [args.actor]
                if args.actor
                else read(ROOT / "docs/coordination/assignments.json")["assignments"]
            )
            for actor in actors:
                task = assignment(ROOT, actor)
                validate(read(inside(ROOT, task["checkpoint"])), task)
            print("Coordination checkpoints validated")
            return
        actor = args.actor or "claude"
        task = assignment(ROOT, actor)
        if task.get("suspended"):
            if args.command == "checkpoint":
                parser.exit(
                    1, "Actor is paused; resume requires a new user instruction.\n"
                )
            print(
                json.dumps(
                    {
                        "actor": actor,
                        "status": "paused",
                        "reason": task.get("suspension_reason", ""),
                        "assignment": task,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return
        path = inside(ROOT, task["checkpoint"])
        if args.command == "checkpoint":
            if not args.input:
                raise ValueError("checkpoint requires --input")
            data = validate(read(args.input), task)
            save(path, data)
            # Checkpoints are part of the release source inventory. Updating a
            # handoff must not leave the source manifest stale after final CI.
            sys.path.insert(0, str(ROOT))
            from ops.manifest import write_manifest

            write_manifest(ROOT)
        data = validate(read(path), task)
        if args.command == "status":
            print(
                json.dumps(
                    {"assignment": task, "checkpoint": data},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print("Coordination checkpoint validated")
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Do not echo submitted checkpoint content or unknown field names.
        parser.exit(
            1,
            f"Coordination validation failed ({type(error).__name__}); check the documented format.\n",
        )


if __name__ == "__main__":
    main()
