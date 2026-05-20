"""Test config — wires the in-tree package onto sys.path and points the cache at a tmpdir."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

# Keep tests fully self-contained; cache to a temp dir so we never poison the user's real cache.
os.environ.setdefault("HOME", str(ROOT / ".test-home"))
(Path(os.environ["HOME"]) / ".cache" / "sureguard").mkdir(parents=True, exist_ok=True)
