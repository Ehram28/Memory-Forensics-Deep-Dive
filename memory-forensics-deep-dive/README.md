# Memory Forensics Deep Dive (Live Response)

A professional DFIR (Digital Forensics & Incident Response) project that simulates a compromised VM and performs **live memory forensics** and incident reconstruction using:

- **Volatility3** (Windows/Linux memory analysis)
- **Rekall** (alternative analysis + cross-validation)
- **LiME** (Linux memory acquisition)
- **WinPmem / DumpIt** (Windows memory acquisition templates)
- **YARA** (malware + artifact detection)
- **Python automation** (plugin-based runner, evidence organization, JSON/CSV exports)

> Note: This repo provides **enterprise-style orchestration, evidence workflow, parsers, and reporting**. It assumes the analyst will install and provide Volatility3/Rekall/LiME binaries on the analysis hosts.

---

## Project goals

1. Capture RAM from a running compromised VM (volatile memory acquisition)
2. Run full memory analysis and extract suspicious artifacts
3. Reconstruct a timeline of process execution and network activity
4. Generate IOCs (IPs, domains, hashes, DLL paths, command lines, persistence keys)
5. Detect malware and injected artifacts using **custom YARA rules**
6. Produce a SOC-ready incident report and evidence folder structure

---

## Repository layout

```text
memory-forensics-deep-dive/
│
├── memory_dumps/
├── volatility_analysis/
├── rekall_analysis/
├── yara_rules/
├── extracted_artifacts/
├── timelines/
├── reports/
├── scripts/
├── notebooks/
├── logs/
└── README.md
```

---

## Features (SOC / DFIR workflow)

- **Evidence folder organizer** (hash validation + metadata)
- **Acquisition templates** for Windows (WinPmem/DumpIt) and Linux (LiME)
- **Volatility3 automation runner**
  - windows.info, pslist, psscan, pstree, dlllist, malfind, cmdline, netscan, handles, hashdump
  - outputs normalized JSON/CSV and suspicious flags
- **Rekall helpers** (process scanning, socket enumeration, memory scanning, timeline scaffolding)
- **IOC extraction** into JSON/TXT/CSV
- **YARA detection system**
  - rules targeting PowerShell abuse, DLL injection, Meterpreter-like strings, credential dumping behaviors
  - automated scanning runner + rule test examples
- **Strings & artifact extraction**
  - ASCII/Unicode strings, URL extraction, PowerShell command recovery
- **Timeline reconstruction**
  - process/network events → CSV timeline + human readable report
- **Advanced features**
  - multithreaded scanning (strings + YARA)
  - evidence integrity verification
  - plugin-based architecture
  - config-driven investigations
  - suspicious score calculator

---

## Environment setup (VM lab)

### VMware / VirtualBox

1. Install **VMware Workstation** or **VirtualBox**.
2. Create 3 VMs:
   - **Kali Linux** (attacker)
   - **Windows 10** (victim)
   - **Ubuntu** (secondary victim / Linux acquisition practice)
3. Use Host-only or NAT networking for repeatability.

### Install Volatility3

On your analysis host (typically Kali/Ubuntu):

```bash
python3 -m pip install --upgrade pip
python3 -m pip install volatility3
```

> Alternative: install from source repository.

### Install Rekall

Rekall is often installed from its project source.

```bash
# Example placeholder (version may differ)
python3 -m pip install rekall
```

### Install LiME (Linux memory acquisition)

LiME typically requires kernel module build.

```bash
# Placeholder commands: follow LiME upstream for exact steps
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r)
```

### For Windows memory acquisition

This repo includes **command templates** for **WinPmem** and **DumpIt**.

- Ensure you run tools as admin
- Capture RAM to a writable location
- Verify SHA256 and move to `memory_dumps/`

---

## Simulated attack scenarios (lab)

This project is designed to simulate a typical incident chain:

- Reverse shell
- Malicious PowerShell execution
- DLL injection
- Process hollowing simulation
- Credential dumping simulation
- Suspicious network beaconing

A ready-to-use **attack simulation harness** can be implemented using your preferred internal tools (or safe PoC scripts). This repository focuses on DFIR orchestration and analysis.

See:
- `docs/LAB_SCENARIOS.md`

---

## Investigation workflow (end-to-end)

1. **Acquire memory**
   - store dumps in `memory_dumps/<case_id>/...`
   - record hashes
2. **Organize evidence**
   - run evidence organizer (creates `case.json`)
3. **Run Volatility3**
   - normalized outputs → `volatility_analysis/<case_id>/`
4. **Run Rekall**
   - cross-validation outputs → `rekall_analysis/<case_id>/`
5. **Extract artifacts**
   - strings/URL/PowerShell recovery → `extracted_artifacts/<case_id>/`
6. **IOC extraction**
   - outputs JSON/TXT/CSV → `extracted_artifacts/<case_id>/iocs/`
7. **YARA scanning**
   - rules and matches stored in reports
8. **Timeline reconstruction**
   - CSV timeline and incident timeline report
9. **Generate final incident report**
   - executive summary, attack overview, technical findings, IOCs, timeline, recommendations

---

## Usage

### 1) Configure a case

Copy the template config:

```bash
cp scripts/config/example_case.json scripts/config/case.json
```

Edit:
- `case_id`
- dump paths
- profile suggestions (Windows/Linux)

### 2) Run the DFIR orchestrator

```bash
python3 scripts/dfir_runner/dfir_run.py --config scripts/config/case.json
```

Outputs are written to:
- `memory_dumps/<case_id>/`
- `volatility_analysis/<case_id>/`
- `rekall_analysis/<case_id>/`
- `extracted_artifacts/<case_id>/`
- `timelines/<case_id>/`
- `reports/<case_id>/`

---

## Screenshots

Placeholders (for GitHub):

- `reports/screenshots/fig1-evidence-folders.png`
- `reports/screenshots/fig2-timeline-chart.png`
- `reports/screenshots/fig3-yara-matches.png`

---

## Technologies used

- Python (automation, parsing, exporters)
- Volatility3 (RAM parsing plugins)
- Rekall (cross-validation)
- LiME (Linux RAM acquisition)
- WinPmem / DumpIt templates (Windows acquisition)
- YARA (detection rules)
- Linux shell scripting (templates)
- Windows forensic technique references (persistence patterns, process artifacts)

---

## Future improvements

- Deeper memory carving for specific malware families
- Better registry persistence extraction from additional artifacts
- Real event parsing from `auditpol`/Windows event logs if available
- More sophisticated relationship graphs (process injection + network beacon correlation)

---

## License

MIT (placeholder). Add your preferred license.

