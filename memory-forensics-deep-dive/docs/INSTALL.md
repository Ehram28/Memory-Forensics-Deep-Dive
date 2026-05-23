# Installation Guide

This repo orchestrates external tools (Volatility3/Rekall/LiME/WinPmem/DumpIt) and expects them to be installed on the analyst host.

## Python

```bash
python3 -m venv .venv
# Linux/Kali
source .venv/bin/activate
# Windows
# .venv\Scripts\activate
python3 -m pip install --upgrade pip
pip install yara-python
```

If you will use pandas:

```bash
pip install pandas
```

## Volatility3

Install via pip:

```bash
python3 -m pip install volatility3
```

Verify:

```bash
python3 -m volatility3 --info
```

## Rekall

Install Rekall according to its official instructions. This project treats it as an external dependency.

## LiME (Linux memory acquisition)

LiME is compiled as a kernel module.

```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r)
```

Build LiME following the LiME README.

## Windows RAM acquisition

### WinPmem

Use the command templates in:
- `scripts/acquisition/windows/winpmem_templates.sh`

### DumpIt

Use the command templates in:
- `scripts/acquisition/windows/dumpit_templates.ps1`

> Both tools are referenced as templates because exact commands/paths differ by build and environment.

---

## Dependencies for DFIR runner

Python scripts expect:
- `volatility3` command to be discoverable (PATH) or configured in the runner config
- optional `rekall` CLI
- optional `yara` binary (or `yara-python` Python bindings)

---

## Troubleshooting

- If Volatility3 fails due to missing profiles, ensure `--profile` is set or that your Volatility installation supports auto profile selection.
- If Rekall cannot enumerate sockets, confirm the memory image matches expected OS and build.

