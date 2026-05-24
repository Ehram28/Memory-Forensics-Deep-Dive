#!/usr/bin/env python3
"""Run Volatility3 pslist and store output to a file."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vol", default="volatility3")
    ap.add_argument("-f", "--image", required=True)
    ap.add_argument("--profile", default="auto")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = [args.vol, "-f", args.image, "windows.pslist"]
    if args.profile and args.profile != "auto":
        cmd += ["--profile", args.profile]

    p = subprocess.run(cmd, capture_output=True, text=True)
    out.write_text(p.stdout + "\n\n[stderr]\n" + p.stderr, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

