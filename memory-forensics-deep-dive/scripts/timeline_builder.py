#!/usr/bin/env python3
"""Timeline builder from extracted plugin outputs and IOC artifacts.

This scaffold creates a best-effort timeline CSV and a human-readable report.
For true DFIR accuracy, provide time-stamped events (e.g., from Windows artifacts
or parser outputs) and extend the correlator.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TS_RE = re.compile(r"(20\d{2})[-_/](\d{2})[-_/](\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?")


def parse_ts(s: str) -> Optional[str]:
    m = TS_RE.search(s)
    if not m:
        return None
    parts = m.groups()
    year, mo, day, hh, mm, ss = parts
    ss = ss or '00'
    try:
        dt = datetime(int(year), int(mo), int(day), int(hh), int(mm), int(ss))
        return dt.isoformat(timespec='seconds')
    except Exception:
        return None


def extract_events_from_files(paths: List[str]) -> List[Dict[str, str]]:
    events: List[Dict[str, str]] = []

    for p in paths:
        fp = Path(p)
        if not fp.exists():
            continue

        if fp.is_dir():
            files = list(fp.rglob('*.json')) + list(fp.rglob('*.txt'))
        else:
            files = [fp]

        for f in files:
            try:
                text = f.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue

            # JSON: accept list of {timestamp, event, ...}
            if f.suffix.lower() == '.json':
                try:
                    raw = json.loads(text)
                    if isinstance(raw, list):
                        for item in raw:
                            if isinstance(item, dict):
                                ts = item.get('timestamp') or item.get('time')
                                ev = item.get('event') or item.get('ioc_type') or 'event'
                                if ts:
                                    events.append({'timestamp': str(ts), 'event': str(ev), 'source': str(f)})
                    continue
                except Exception:
                    pass

            # Text heuristic: look for timestamp patterns and take a nearby snippet
            for line in text.splitlines():
                ts = parse_ts(line)
                if ts:
                    snippet = line.strip()[:200]
                    events.append({'timestamp': ts, 'event': snippet, 'source': str(f)})

    return events


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--inputs', nargs='+', required=True, help='Files/dirs to parse')
    ap.add_argument('--out-csv', required=True)
    ap.add_argument('--out-report', required=True)
    args = ap.parse_args()

    events = extract_events_from_files(args.inputs)

    # Dedupe
    seen = set()
    deduped: List[Dict[str, str]] = []
    for e in events:
        k = (e['timestamp'], e['event'])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(e)

    # Sort by timestamp if possible
    def sort_key(e: Dict[str, str]):
        try:
            return datetime.fromisoformat(e['timestamp'])
        except Exception:
            return datetime.min

    deduped.sort(key=sort_key)

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['timestamp', 'event', 'source'])
        w.writeheader()
        for e in deduped:
            w.writerow(e)

    report = Path(args.out_report)
    report.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Incident Timeline (Best-effort)", ""]
    if not deduped:
        lines += ["No timestamped events were found from the provided inputs."]
    else:
        for e in deduped:
            lines.append(f"- {e['timestamp']} | {e['event']} ({Path(e['source']).name})")

    report.write_text("\n".join(lines), encoding='utf-8')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

