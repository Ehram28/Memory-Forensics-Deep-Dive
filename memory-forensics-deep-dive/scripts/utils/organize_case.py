#!/usr/bin/env python3
"""Organize and verify evidence for a case.

Creates a deterministic evidence folder layout and (optionally) computes hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List


def sha256(p: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--case-dir', required=True, help='Path to memory_dumps/CASE')
    ap.add_argument('--out', required=True, help='Write case.json here')
    ap.add_argument('--hashes', action='store_true', help='Compute sha256 for all files')
    args = ap.parse_args()

    case_dir = Path(args.case_dir)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    evidence: List[Dict[str, str]] = []
    for f in sorted(case_dir.rglob('*')):
        if f.is_file():
            entry = {'path': str(f.relative_to(case_dir))}
            if args.hashes:
                entry['sha256'] = sha256(f)
            evidence.append(entry)

    payload = {'evidence_dir': str(case_dir), 'files': evidence}
    out.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

