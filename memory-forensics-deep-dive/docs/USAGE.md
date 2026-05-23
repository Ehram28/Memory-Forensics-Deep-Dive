# Usage Guide

## Quick start (developer/analyst)

### 1) Prepare evidence

Create a case folder and place memory dumps:

- `memory_dumps/<case_id>/windows/` (optional)
- `memory_dumps/<case_id>/linux/` (optional)

Compute SHA256 and store them in:
- `memory_dumps/<case_id>/hashes/sha256.txt`

### 2) Configure case

Edit:
- `scripts/config/example_case.json`

Then run:

```bash
python3 scripts/dfir_runner/dfir_run.py --config scripts/config/case.json
```

### 3) Outputs

The runner creates:

- `volatility_analysis/<case_id>/`
- `rekall_analysis/<case_id>/`
- `extracted_artifacts/<case_id>/strings/`
- `extracted_artifacts/<case_id>/iocs/`
- `yara_matches/<case_id>/`
- `timelines/<case_id>/timeline.csv`
- `reports/<case_id>/incident_report.md`

---

## What each module does

- `acquisition/`: evidence organization + template commands
- `dfir_runner/`: orchestrates plugin execution
- `volatility_analysis/`: executes Volatility3 plugins and normalizes output
- `ioc_extractor/`: turns raw findings into standardized IOC objects
- `yara_system/`: compiles rules and scans artifacts
- `strings_extract/`: extracts ASCII/Unicode strings + URLs
- `timeline_builder/`: correlates events into a timeline

---

## Note on “Live response”

This repo focuses on the DFIR pipeline and acquisition templates. For true live acquisition you must run the acquisition tool on the compromised host while it is still running.

