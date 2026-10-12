#!/usr/bin/env python3
"""Extract complete literal command lines; refuse cursor/history/completion editing."""
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("session_export", Path(__file__).resolve().parents[1] / "session-export.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)
try:
    parser = export.InputLines()
    lines = parser.feed(export.body(Path(sys.argv[1] + ".in").read_bytes()))
    parser.finish()
except (export.Refused, ValueError, OSError) as exc:
    sys.exit(f"REFUSED: {exc}")
print("\n".join(lines))
