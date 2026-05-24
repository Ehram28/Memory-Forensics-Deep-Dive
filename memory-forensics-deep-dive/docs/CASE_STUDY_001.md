# CASE_STUDY_001 — PowerShell Reverse Shell + Injection (Simulated)

> This case study is a **portfolio write-up**. Use only in a controlled lab.

## Scenario
1. User opens a phishing attachment.
2. PowerShell launches with `-enc` (Base64 encoded command).
3. A reverse shell is established to the attacker.
4. The payload injects into a running process.
5. Network beaconing appears over HTTP(S).

## Evidence Artifacts (what to capture)
- Windows RAM image (WinPmem/DumpIt)
- Volatility3 outputs:
  - `windows.pslist`
  - `windows.netscan`
  - `windows.malfind`
  - `windows.cmdline`
- YARA matches from extracted strings

## Investigation Highlights
- **Volatility3** identifies suspicious process tree anomalies.
- **malfind** indicates potentially injected memory regions.
- **cmdline** reveals encoded PowerShell stages.
- **netscan** surfaces outbound C2 beacon endpoints.
- **YARA** flags PowerShell abuse and credential dumping patterns.

## Outcome
- IOC list exported as JSON/TXT/CSV.
- Incident timeline reconstructed into `timelines/CASE-001/timeline.csv`.
- Incident report created under `reports/CASE-001/incident_report.md`.

