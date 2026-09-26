#!/usr/bin/env python3
"""Safe public entry point for the packaged analyses."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


PACKAGE_ROOT = Path(__file__).resolve().parent


def resolve_path(value: str | None, base: Path) -> Path | None:
    if value is None:
        return None
    path = Path(value).expanduser()
    return (base / path).resolve() if not path.is_absolute() else path.resolve()


def main() -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=str(PACKAGE_ROOT / "repro_config.json"))
    known, _ = pre.parse_known_args()
    config_path = Path(known.config).expanduser().resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    parser = argparse.ArgumentParser(description=__doc__, parents=[pre])
    parser.add_argument("--project-root")
    parser.add_argument("--python-executable")
    parser.add_argument("--tokenizer-cache")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("formal", "s6", "oof-audit"):
        command = commands.add_parser(name)
        command.add_argument("--run", action="store_true", help="Required to execute; omission prints the plan only.")
    commands.choices["oof-audit"].add_argument("--out")
    args = parser.parse_args()
    base = config_path.parent
    root = resolve_path(args.project_root or config["project_root"], base)
    python_value = args.python_executable or config.get("python_executable") or sys.executable
    python = shutil.which(python_value) or str(Path(python_value).expanduser().resolve())
    cache = resolve_path(args.tokenizer_cache or config.get("tokenizer_cache"), base)
    assert root is not None and root.is_dir(), f"Project root is unavailable: {root}"
    scripts = {
        "formal": root / "experiments/formal_analysis.py",
        "s6": root / "experiments/core_inject_analysis.py",
        "oof-audit": root / "experiments/oof_input_audit.py",
    }
    script = scripts[args.command]
    assert script.is_file() and script.resolve().is_relative_to(root), f"Missing packaged script: {script}"
    command = [python, str(script)]
    if args.command == "formal":
        command.append("--run")
    elif args.command == "oof-audit":
        command += ["--project-root", str(root)]
        if args.out:
            command += ["--out", str(resolve_path(args.out, Path.cwd()))]
    plan = {"command": args.command, "project_root": str(root), "python": python,
            "tokenizer_cache": str(cache) if cache else None,
            "script": str(script), "will_execute": bool(args.run)}
    if not args.run:
        print(json.dumps(plan, indent=2))
        return 0
    env = os.environ.copy()
    env["MI_CONTEXT_LENGTH_ROOT"] = str(root)
    env["MI_CONTEXT_LENGTH_PYTHON"] = python
    if cache:
        env["MI_CONTEXT_LENGTH_TOKENIZER_CACHE"] = str(cache)
    return subprocess.run(command, cwd=root, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
