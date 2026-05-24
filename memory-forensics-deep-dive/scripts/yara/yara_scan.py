#!/usr/bin/env python3
"""Automated YARA scanning for extracted artifacts.

Workflow:
- Compile all rules from a directory
- Scan target files (recursively) or explicit inputs
- Emit matches to JSON + TXT

This is designed to be SOC/DFIR portfolio-friendly and defensive.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def yara_scan_file(yara_compiled: Any, file_path: Path) -> List[Dict[str, Any]]:
    matches_out: List[Dict[str, Any]] = []
    try:
        data = file_path.read_bytes()
        matches = yara_compiled.match(data=data)
        for m in matches:
            matches_out.append({
                "rule": m.rule,
                "tags": list(getattr(m, "tags", [])) if hasattr(m, "tags") else [],
                "strings": [{"identifier": s[0], "offset": s[1], "data": s[2]} for s in (m.strings or [])],
            })
    except Exception as e:
        matches_out.append({"error": str(e), "rule": None})
    return matches_out


def iter_targets(targets: List[str]) -> List[Path]:
    out: List[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_dir():
            out.extend([x for x in p.rglob("*") if x.is_file()])
        elif p.is_file():
            out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules-dir", required=True, help="Directory containing .yar rules")
    ap.add_argument("--targets", nargs="+", required=True, help="Files/dirs to scan")
    ap.add_argument("--out-json", required=True, help="Output JSON path")
    ap.add_argument("--out-txt", required=True, help="Output TXT path")
    args = ap.parse_args()

    try:
        import yara  # type: ignore
    except Exception as e:
        raise SystemExit(f"yara-python not installed or yara import failed: {e}")

    rules_dir = Path(args.rules_dir)
    rule_paths = sorted([p for p in rules_dir.rglob("*.yar") if p.is_file()])
    if not rule_paths:
        raise SystemExit(f"No .yar rules found in {rules_dir}")

    compilation_sources = {str(p): p.read_text(encoding="utf-8", errors="ignore") for p in rule_paths}
    # yara-python supports compiling from sources individually.
    all_rules = []
    for src_path, src_text in compilation_sources.items():
        try:
            all_rules.append(yara.compile(source=src_text))
        except Exception:
            # If one rule fails, still continue with others.
            continue

    targets = iter_targets(args.targets)

    findings: List[Dict[str, Any]] = []
    for t in targets:
        per_file: Dict[str, Any] = {"file": str(t), "matches": []}
        # Combine results across compiled rule sets.
        for compiled in all_rules:
            per_file["matches"].extend(yara_scan_file(compiled, t))
        # Remove empty matches
        per_file["matches"] = [m for m in per_file["matches"] if m.get("rule") is not None or "error" in m]
        if per_file["matches"]:
            findings.append(per_file)

    out_json = Path(args.out_json)
    out_txt = Path(args.out_txt)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    lines: List[str] = []
    for f in findings:
        lines.append(f"FILE: {f['file']}")
        for m in f["matches"]:
            if "error" in m:
                lines.append(f"  ERROR: {m['error']}")
            else:
                lines.append(f"  RULE: {m['rule']}")
        lines.append("")
    out_txt.write_text("\n".join(lines), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

