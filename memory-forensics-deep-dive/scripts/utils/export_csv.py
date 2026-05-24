#!/usr/bin/env python3
"""Export IOC lists from json to csv (utility scaffold)."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--in-json', required=True)
    ap.add_argument('--out-csv', required=True)
    args = ap.parse_args()

    data = json.loads(Path(args.in_json).read_text(encoding='utf-8'))
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['ioc_type', 'value', 'source', 'confidence'])
        w.writeheader()
        for x in data:
            w.writerow({
                'ioc_type': x.get('ioc_type'),
                'value': x.get('value'),
                'source': x.get('source'),
                'confidence': x.get('confidence'),
            })

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

