# M87 Audit Agent Demo (SPOT + FORT Compliance)

This package contains output from the M87 Studio Governance Audit Agent — a CLI tool that uses Claude (Anthropic) to analyze Python source code under two rule sets:

## ✅ SPOT (Security Prevention & Output Tracking)
- Detects dangerous functions (`eval`, `exec`)
- Flags hardcoded secrets
- Prevents unsafe external access

## ✅ FORT (Framework-Oriented Runtime Trust)
- Enforces clean architecture
- Limits function complexity
- Blocks mutation of global state

## Included Files
- `audit_agent.py` — CLI audit tool
- `*.py` — Raw source files
- `*.audit.json` — AI-generated compliance reports

## Usage
Run with:

```bash
python audit_agent.py                # Full audit sweep
python audit_agent.py file.py       # Single file audit
