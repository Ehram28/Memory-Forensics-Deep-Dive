#!/usr/bin/env python3
"""ASCII/Unicode strings + URL extraction (best-effort).

Portfolio scaffold for the DFIR workflow.

- Reads one or more input files (memory dumps or extracted artifacts)
- Extracts printable ASCII and UTF-16LE strings
- Extracts URLs and basic PowerShell-like command fragments
- Writes outputs into an evidence-friendly folder layout

This script is defensive and will skip unreadable files.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable, Iterator, List, Tuple

URL_RE = re.compile(r"\bhttps?://[^\s\"]+", re.IGNORECASE)
PSH_RE = re.compile(r"powershell[^\r\n]{0,200}", re.IGNORECASE)


def is_printable_ascii(b: int) -> bool:
    return 0x20 <= b <= 0x7E


def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    out: List[str] = []
    buf = bytearray()
    for x in data:
        if is_printable_ascii(x):
            buf.append(x)
        else:
            if len(buf) >= min_len:
                out.append(buf.decode('ascii', errors='ignore'))
            buf.clear()
    if len(buf) >= min_len:
        out.append(buf.decode('ascii', errors='ignore'))
    return out


def extract_utf16le_strings(data: bytes, min_len: int = 4) -> List[str]:
    out: List[str] = []
    # interpret as little-endian UTF-16 pairs; keep pairs where low byte is printable ascii and high byte is null
    # This is heuristic to avoid heavy decoding.
    pairs = [data[i:i+2] for i in range(0, len(data) - 1, 2)]
    buf: List[int] = []
    for p in pairs:
        lo = p[0]
        hi = p[1]
        if hi == 0x00 and 0x20 <= lo <= 0x7E:
            buf.append(lo)
        else:
            if len(buf) >= min_len:
                out.append(bytes(buf).decode('ascii', errors='ignore'))
            buf.clear()
    if len(buf) >= min_len:
        out.append(bytes(buf).decode('ascii', errors='ignore'))
    return out


def dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        k = x.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def safe_read(p: Path) -> bytes:
    try:
        return p.read_bytes()
    except Exception:
        return b""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--inputs', nargs='+', required=True, help='Files to scan for strings')
    ap.add_argument('--out-dir', required=True, help='Output directory')
    ap.add_argument('--min-len', type=int, default=4)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_ascii: List[str] = []
    all_utf16: List[str] = []
    all_urls: List[str] = []
    all_powershell: List[str] = []

    for inp in args.inputs:
        p = Path(inp)
        data = safe_read(p)
        if not data:
            continue

        ascii_s = extract_ascii_strings(data, min_len=args.min_len)
        utf16_s = extract_utf16le_strings(data, min_len=args.min_len)
        text = ' '.join(ascii_s[:20000])  # limit for regex search
        urls = URL_RE.findall(text)
        psh = PSH_RE.findall(text)

        all_ascii.extend(ascii_s)
        all_utf16.extend(utf16_s)
        all_urls.extend(urls)
        all_powershell.extend(psh)

    all_ascii = dedupe_keep_order(all_ascii)
    all_utf16 = dedupe_keep_order(all_utf16)
    all_urls = dedupe_keep_order(all_urls)
    all_powershell = dedupe_keep_order(all_powershell)

    (out_dir / 'strings_ascii.txt').write_text('\n'.join(all_ascii), encoding='utf-8')
    (out_dir / 'strings_utf16le.txt').write_text('\n'.join(all_utf16), encoding='utf-8')
    (out_dir / 'urls.txt').write_text('\n'.join(all_urls), encoding='utf-8')
    (out_dir / 'powershell_fragments.txt').write_text('\n'.join(all_powershell), encoding='utf-8')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

