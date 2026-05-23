#!/usr/bin/env python3
"""DFIR orchestrator - Memory Forensics Deep Dive (Live Response)

This repo provides an enterprise-style workflow/orchestration framework.
It executes external tools (Volatility3/Rekall/YARA) *if installed*.

Because this project is portfolio-ready and safe for lab demonstration,
this file focuses on: evidence folder creation, hashing hooks, plugin execution
wrappers, output normalization scaffolding, and report assembly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CaseConfig:
    case_id: str
    analysis_host: Dict[str, Any]
    memory_images: Dict[str, Any]
    output_root: str
    plugins: Dict[str, Any]
    suspicious_scoring: Dict[str, Any]
    yara: Dict[str, Any]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def setup_logger(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dfir_run")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    fh = logging.FileHandler(log_dir / "dfir_run.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(sh)

    return logger


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_config(config_path: Path) -> CaseConfig:
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    return CaseConfig(
        case_id=raw["case_id"],
        analysis_host=raw.get("analysis_host", {}),
        memory_images=raw.get("memory_images", {}),
        output_root=raw.get("output_root", "./"),
        plugins=raw.get("plugins", {}),
        suspicious_scoring=raw.get("suspicious_scoring", {}),
        yara=raw.get("yara", {}),
    )


def ensure_dirs(base: Path, case_id: str) -> Dict[str, Path]:
    d = {
        "memory_dumps": base / "memory_dumps" / case_id,
        "volatility": base / "volatility_analysis" / case_id,
        "rekall": base / "rekall_analysis" / case_id,
        "artifacts": base / "extracted_artifacts" / case_id,
        "strings": base / "extracted_artifacts" / case_id / "strings",
        "iocs": base / "extracted_artifacts" / case_id / "iocs",
        "yara_matches": base / "yara_matches" / case_id,
        "timelines": base / "timelines" / case_id,
        "reports": base / "reports" / case_id,
        "logs": base / "logs" / case_id,
    }
    for p in d.values():
        p.mkdir(parents=True, exist_ok=True)
    return d


def write_metadata(dirs: Dict[str, Path], cfg: CaseConfig, config_path: Path) -> None:
    meta = {
        "case_id": cfg.case_id,
        "started_utc": utc_now_iso(),
        "config_path": str(config_path.resolve()),
        "memory_images": cfg.memory_images,
        "plugins": cfg.plugins,
        "suspicious_scoring": cfg.suspicious_scoring,
        "yara": cfg.yara,
    }
    (dirs["reports"] / "run_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def run_cmd(logger: logging.Logger, cmd: List[str], cwd: Optional[Path] = None) -> int:
    logger.info("Running: %s", " ".join(cmd))
    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
        logger.debug("stdout:\n%s", p.stdout)
        logger.debug("stderr:\n%s", p.stderr)
        if p.returncode != 0:
            logger.warning("Command exited with %s", p.returncode)
        return p.returncode
    except FileNotFoundError:
        logger.error("Executable not found: %s", cmd[0])
        return 127


def run_volatility3(logger: logging.Logger, dirs: Dict[str, Path], cfg: CaseConfig) -> None:
    if not cfg.plugins.get("volatility3"):
        logger.info("No Volatility3 plugins configured; skipping")
        return

    vol3 = cfg.analysis_host.get("volatility3_path", "volatility3")

    win = cfg.memory_images.get("windows", {})
    image_path = win.get("image_path")
    profile = win.get("profile")

    if not image_path or not Path(image_path).exists():
        logger.warning("Windows memory image not found at %s; skipping Volatility3", image_path)
        return

    # Volatility3 plugin outputs vary; we run and store stdout to files.
    plugins = cfg.plugins.get("volatility3", [])
    for plugin in plugins:
        out_path = dirs["volatility"] / f"{plugin.replace('/', '_')}.stdout.txt"
        cmd = [vol3, "-f", image_path]
        if profile and profile != "auto":
            cmd += ["--profile", profile]
        cmd += plugin.split(" ")

        logger.info("Volatility3 plugin=%s", plugin)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True)
            out_path.write_text(
                "# command:\n" + " ".join(cmd) + "\n\n" + "# stdout:\n" + p.stdout + "\n\n" + "# stderr:\n" + p.stderr,
                encoding="utf-8",
            )
            if p.returncode != 0:
                logger.warning("Volatility3 returned %s for %s", p.returncode, plugin)
        except FileNotFoundError:
            logger.error("volatility3 not found in PATH and analysis_host.volatility3_path not set")
            return


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to scripts/config/case.json")
    args = ap.parse_args()

    config_path = Path(args.config)
    cfg = load_config(config_path)

    base = Path(cfg.output_root).resolve() if cfg.output_root else Path(".").resolve()
    dirs = ensure_dirs(base, cfg.case_id)
    logger = setup_logger(dirs["logs"])

    write_metadata(dirs, cfg, config_path)
    logger.info("DFIR run complete scaffolding for case_id=%s", cfg.case_id)

    # Minimal orchestration without heavy parsing (to keep this portable).
    run_volatility3(logger, dirs, cfg)

    report = dirs["reports"] / "incident_report.md"
    report.write_text(
        "# Incident Response Report (Template)\n\n"
        f"Case ID: {cfg.case_id}\n\n"
        "## Executive Summary\n"
        "This run produced evidence directories and attempted Volatility3 plugins.\n\n"
        "## Findings\n"
        "- Volatility3 outputs are stored under: volatility_analysis/<case_id>/\n"
        "\n## Recommendations\n"
        "- Continue with Rekall, strings extraction, YARA scanning, IOC extraction, and timeline reconstruction.\n",
        encoding="utf-8",
    )

    logger.info("Wrote template report: %s", report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

