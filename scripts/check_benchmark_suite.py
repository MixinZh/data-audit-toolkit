#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from data_audit_toolkit.benchmark import run_benchmark

payload = run_benchmark()
print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
raise SystemExit(1 if payload["failures"] else 0)
