#!/usr/bin/env python3
"""IOC extraction from normalized artifacts.

This is a scaffold that supports a DFIR workflow:
- ingest plugin outputs (JSON/text)
- apply keyword/regex rules (config-driven)
- emit structured IOCs in json/txt/csv

For this portfolio-ready repo, the module is defensive and works even if inputs
are missing (it will create empty outputs and helpful logs).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class IOC:
    ioc_type: str
    value: str
    source: str
    confidence: float = 0.5


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"]+", re.IGNORECASE)


def read_text_safe(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def iter_candidate_files(inputs: List[str], exts: Tuple[str, ...] = (".txt", ".json", ".csv")) -> Iterable[Path]:
    for inp in inputs:
        path = Path(inp)
        if path.is_file() and path.suffix.lower() in exts:
            yield path
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file() and f.suffix.lower() in exts:
                    yield f


def extract_iocs_from_text(text: str, source: str, suspicious_terms: Dict[str, List[str]]) -> List[IOC]:
    iocs: List[IOC] = []

    for m in IP_RE.findall(text):
        iocs.append(IOC("ip", m, source, 0.7))
    for m in DOMAIN_RE.findall(text):
        # reduce false positives
        if any(ch.isdigit() for ch in m) or m.count('.') >= 1:
            iocs.append(IOC("domain", m, source, 0.6))
    for m in URL_RE.findall(text):
        iocs.append(IOC("url", m, source, 0.8))

    for m in HASH_RE.findall(text):
        # length-based inference
        v = m
        if len(v) == 64:
            t = "sha256"
        elif len(v) == 40:
            t = "sha1"
        else:
            t = "md5"
        iocs.append(IOC(t, v, source, 0.65))

    # Keyword harvesting (best-effort)
    def harvest(term_list: List[str], key: str):
        for term in term_list:
            if term.lower() in text.lower():
                iocs.append(IOC(key, term, source, 0.4))

    harvest(suspicious_terms.get("powershell_terms", []), "powershell_term")
    harvest(suspicious_terms.get("process_injection_terms", []), "injection_term")
    harvest(suspicious_terms.get("credential_terms", []), "credential_term")
    harvest(suspicious_terms.get("network_terms", []), "network_term")

    return iocs


def dedupe(iocs: List[IOC]) -> List[IOC]:
    seen = set()
    out: List[IOC] = []
    for i in iocs:
        k = (i.ioc_type, i.value.lower())
        if k in seen:
            continue
        seen.add(k)
        out.append(i)
    return out


def write_outputs(iocs: List[IOC], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "iocs.json"
    txt_path = out_dir / "iocs.txt"
    csv_path = out_dir / "iocs.csv"

    json_path.write_text(json.dumps([i.__dict__ for i in iocs], indent=2), encoding="utf-8")

    with txt_path.open("w", encoding="utf-8") as f:
        for i in iocs:
            f.write(f"{i.ioc_type}\t{i.value}\t{i.source}\t{i.confidence}\n")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ioc_type", "value", "source", "confidence"])
        w.writeheader()
        for i in iocs:
            w.writerow(i.__dict__)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True, help="Files/dirs to scan for indicators")
    ap.add_argument("--suspicious-terms", default=None, help="Path to JSON with suspicious terms")
    ap.add_argument("--out-dir", required=True, help="Output directory for IOC artifacts")
    args = ap.parse_args()

    terms: Dict[str, List[str]] = {
        "process_injection_terms": [],
        "powershell_terms": [],
        "credential_terms": [],
        "network_terms": [],
    }
    if args.suspicious_terms:
        terms = json.loads(Path(args.suspicious_terms).read_text(encoding="utf-8"))

    all_iocs: List[IOC] = []
    for f in iter_candidate_files(args.inputs):
        txt = read_text_safe(f)
        if not txt.strip():
            continue
        all_iocs.extend(extract_iocs_from_text(txt, str(f), terms))

    all_iocs = dedupe(all_iocs)
    write_outputs(all_iocs, Path(args.out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

