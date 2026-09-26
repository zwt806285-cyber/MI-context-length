"""Central runtime paths for the public reproducibility package."""
from __future__ import annotations

import os
from pathlib import Path
import sys


PACKAGE_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _path_from_env(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default.resolve()


PROJECT_ROOT = _path_from_env("MI_CONTEXT_LENGTH_ROOT", PACKAGE_PROJECT_ROOT)
PYTHON = os.environ.get("MI_CONTEXT_LENGTH_PYTHON", sys.executable)
TOKENIZER_CACHE = _path_from_env(
    "MI_CONTEXT_LENGTH_TOKENIZER_CACHE",
    PROJECT_ROOT / "external" / "o200k_base_cache",
)
