# Lab Scenarios (Simulated Compromise)

This section describes safe-to-practice scenario design for building a repeatable DFIR dataset.

## Scenario overview

1. **Reverse shell**: establish outbound connection and maintain persistence.
2. **Malicious PowerShell execution**: run PowerShell with encoded commands.
3. **DLL injection**: load suspicious DLL into a running process.
4. **Process hollowing**: simulate by spawning then altering memory sections (PoC behavior).
5. **Credential dumping simulation**: simulate lsass access / credential artifacts.
6. **Suspicious beaconing**: periodic network connections to attacker-controlled endpoints.

## How to use this repo with scenarios

- Run the scenario in your victim VM.
- Acquire memory while the activity is ongoing (or shortly after).
- Place dumps into `memory_dumps/<case_id>/...`.
- Run DFIR runner; inspect IOCs, YARA hits, and timeline.

## Evidence targets

The project aims to surface evidence such as:

- process trees + command lines
- injected DLLs / malfind hits
- PowerShell artifacts in memory strings
- network endpoints (netscan) and socket details
- credential-related hashes and extracted artifacts

> For ethical use: keep all malware simulations within a controlled lab and use benign PoCs.

