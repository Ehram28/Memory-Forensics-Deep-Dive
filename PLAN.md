# Plan (proposed)

## Information Gathered
- Repo workspace is currently empty (no existing project files).
- Need to bootstrap a full GitHub-ready project skeleton from scratch.

## Plan
1. Create project directory: `memory-forensics-deep-dive/`
2. Create core documentation:
   - `README.md` (full install/usage/workflow, feature list, DFIR process, diagrams placeholders)
   - `docs/INSTALL.md`, `docs/USAGE.md`, `docs/LAB_SCENARIOS.md`
3. Add evidence/project structure exactly as required:
   - `memory_dumps/`, `volatility_analysis/`, `rekall_analysis/`, `yara_rules/`, `extracted_artifacts/`, `timelines/`, `reports/`, `scripts/`, `notebooks/`, `logs/`
4. Implement automation framework (Python):
   - `scripts/dfir_runner/` plugin-based runner
   - Config-driven plugin list + output folder organization
   - JSON/CSV exporters + suspicious scoring
5. RAM acquisition module:
   - `scripts/acquisition/`:
     - Windows acquisition helper (WinPmem/DumpIt command templates)
     - Linux acquisition helper (LiME command templates)
     - hashing + verification
6. Volatility3 automation:
   - `volatility_analysis/run_volatility.py` that runs listed plugins and stores outputs
   - Parsers for key plugin outputs → standardized JSON/CSV
7. Rekall automation:
   - `rekall_analysis/` helper scripts + docs on profile selection
8. IOC extraction module:
   - `scripts/ioc_extractor.py` to parse standardized JSON and emit IOC formats (json/txt/csv)
   - include registry persistence key extraction placeholders (best-effort)
9. YARA detection system:
   - `yara_rules/*.yar` (custom rules)
   - `scripts/yara_scan.py` to scan extracted artifacts + memory strings (when available)
   - include rule testing examples
10. Strings & artifact extraction:
   - `scripts/strings_extract.py` (ASCII/Unicode), URL extraction, PowerShell recovery
11. Timeline reconstruction:
   - `scripts/timeline_builder.py` outputs `timelines/timeline.csv` and `reports/incident_timeline.md`
12. Final incident response report template:
   - `reports/incident_report_template.md` (filled by runner placeholders)
13. Visualizations:
   - `scripts/visualize/` optional placeholders (process tree chart, timeline chart)
14. Provide example outputs + logs templates.
15. Add `requirements.txt` / optional `pyproject.toml` for Python tooling.
16. Add “Advanced features”:
   - multithreaded scanning (strings/YARA)
   - evidence integrity verification (hashes)
   - suspicious score calculation

## Dependent Files to be edited
- None yet (new project bootstrap).

## Followup steps
- After scaffolding, run basic Python script smoke-tests (no external binaries required) to ensure import/CLI works.

<ask_followup_question>
Confirm whether you want the project implemented as:
A) pure skeleton + runnable scripts with command templates (recommended for portability), or
B) full working integration that assumes Volatility3/Rekall/LiME are already installed on the target VMs.

Reply with A or B. 
</ask_followup_question>

