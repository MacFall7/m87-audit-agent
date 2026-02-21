# M87 Audit Agent

**Governed Python code auditor. Deterministic enforcement, cryptographic receipts, CI-ready.**

---

## Problem

LLM-assisted code generation is fast. Governance over that code is not.

Static analyzers catch syntax-level issues. They do not enforce *policy* — "no hardcoded secrets in auth modules," "functions under 50 statements," "no eval in user-facing code." Writing custom rules for every policy is slow and brittle.

M87 Audit Agent uses Claude as a *governed reasoning engine* — not a chatbot. Every audit call is:

- **Deterministic**: temperature=0, identical prompts for identical inputs.
- **Traceable**: every file gets a cryptographic receipt (SHA-256 file hash, rules hash, receipt chain).
- **CI-gated**: exits non-zero on any violation. Drop it into GitHub Actions and block the merge.

---

## Quick start

```bash
pip install requests pyyaml
export ANTHROPIC_API_KEY=sk-ant-...

# Audit all .py files in the current directory
python audit_agent.py

# Audit specific files or directories
python audit_agent.py src/ utils/auth.py

# Custom rules
python audit_agent.py --rules my_rules.yaml src/
```

---

## Output

Each audited file produces a `.receipt.json`:

```json
{
  "version": "2.0",
  "timestamp": "2026-02-21T14:30:00.000000Z",
  "file": {
    "path": "auth.py",
    "hash": "a1b2c3d4e5f6..."
  },
  "rules": {
    "path": "rules.yaml",
    "hash": "d4e5f6a7b8c9..."
  },
  "model": "claude-opus-4-6",
  "duration_seconds": 3.41,
  "result": {
    "passed": false,
    "risk_level": "CRITICAL",
    "spot_violation_count": 1,
    "fort_violation_count": 0,
    "summary": "eval() call on line 42 violates SPOT-001."
  },
  "chain": {
    "previous_receipt_hash": null
  },
  "receipt_hash": "f7a8b9c0d1e2..."
}
```

Exit code is `0` if all files pass, `1` if any file fails.

---

## Architecture invariants

1. **Prompt determinism.** `build_prompt(code, filename, rules_text)` is a pure function. Same inputs produce the same prompt string. No timestamps, no random IDs in the prompt.

2. **Rules are external YAML.** No rules are hardcoded. The `rules.yaml` file defines SPOT (security) and FORT (runtime trust) rulesets. Swap it per-repo or per-team.

3. **Receipts are hash-chained.** Each receipt includes the SHA-256 of the file content, the rules file, and the previous receipt hash. You can verify the chain offline without re-running the audit.

4. **Claude is the reasoning engine, not the policy store.** Rules are injected into the prompt verbatim. Claude evaluates code against those rules and returns structured JSON. If the model hallucinates a violation, the receipt records it — and you can diff against a re-audit.

5. **Zero runtime dependencies beyond `requests` and `pyyaml`.** No frameworks, no ORMs, no agent orchestration libraries.

---

## Rules format

```yaml
version: "1.0"
ruleset_id: "m87-default-v1"
description: "M87 Studio default audit rules"

SPOT:
  description: "Security Prevention & Output Tracking"
  rules:
    - id: SPOT-001
      name: No eval/exec
      description: "Forbids eval(), exec(), and compile() calls"
      severity: critical

FORT:
  description: "Framework-Oriented Runtime Trust"
  rules:
    - id: FORT-001
      name: Function complexity
      description: "Functions must not exceed 50 statements"
      severity: medium
```

Severity levels: `critical`, `high`, `medium`, `low`.

---

## CI workflow (GitHub Actions)

```yaml
name: M87 Audit
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install requests pyyaml

      - name: Run M87 audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: python audit_agent.py src/

      - name: Upload receipts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-receipts
          path: "*.receipt.json"
```

---

## Tests

```bash
pip install pytest pyyaml requests
pytest tests/ -v
```

Tests cover rule loading, prompt construction, hashing, receipt chaining, API response parsing (mocked), and target collection. No network calls required.

---

## Project structure

```
audit_agent.py             # CLI entry point and core logic
rules.yaml                 # Default SPOT + FORT ruleset
tests/test_audit_agent.py  # Full test suite
README.md
```

---

## License

MIT
