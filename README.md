<p align="center">
  <strong>M87 AUDIT AGENT</strong><br>
  <em>Governed Python code auditor. Deterministic enforcement, cryptographic receipts, CI-ready.</em>
</p>

<p align="center">
  <code>temperature: 0</code> &nbsp;&middot;&nbsp;
  <code>SHA-256 receipt chain</code> &nbsp;&middot;&nbsp;
  <code>fails closed</code> &nbsp;&middot;&nbsp;
  <code>50 tests</code>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &nbsp;&middot;&nbsp;
  <a href="#how-it-works">How It Works</a> &nbsp;&middot;&nbsp;
  <a href="#cli-reference">CLI Reference</a> &nbsp;&middot;&nbsp;
  <a href="#rules-format">Rules Format</a> &nbsp;&middot;&nbsp;
  <a href="#ci-integration">CI Integration</a> &nbsp;&middot;&nbsp;
  <a href="#architecture">Architecture</a> &nbsp;&middot;&nbsp;
  <a href="#api-reference">API Reference</a>
</p>

---

## The Problem

LLM-assisted code generation is fast. Governance over that code is not.

Static analyzers catch syntax-level issues. They do not enforce **policy** -- "no hardcoded secrets in auth modules," "functions under 50 statements," "no eval in user-facing code." Writing custom rules for every policy is slow and brittle.

M87 Audit Agent uses Claude as a **governed reasoning engine** -- not a chatbot. Every audit call is deterministic, traceable, and CI-gated. If the model produces invalid output, the system retries with the failure reason attached. If it fails three times, it raises `GovernanceValidationError` and blocks the pipeline. No invalid data ever reaches a receipt.

---

## Quick Start

### Prerequisites

- Python 3.9+
- An [Anthropic API key](https://console.anthropic.com/)

### Install

```bash
git clone https://github.com/MacFall7/m87-audit-agent.git
cd m87-audit-agent
pip install requests pyyaml
```

### Set your API key

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### Run your first audit

```bash
# Audit all .py files in the current directory (report only)
python audit_agent.py

# Audit specific files or directories
python audit_agent.py src/ utils/auth.py

# CI gate mode -- exit 1 on any violation
python audit_agent.py src/ --fail-on-violations

# Custom rules file
python audit_agent.py --rules my_rules.yaml src/

# Custom model and output directory
python audit_agent.py --model claude-sonnet-4-20250514 --output-dir reports/ src/
```

Each audited file produces a `<filename>.receipt.json` in the output directory.

---

## How It Works

```
rules.yaml ──┐
              ├──▶ build_prompt() ──▶ call_claude_with_validation() ──▶ receipt.json
source.py ───┘         │                        │
                  deterministic            retry loop (max 3)
                  temperature=0            schema validation
                                           failure store
                                           fails closed
```

1. **Load rules** from external YAML. Validated at startup -- malformed rules fail before any audit runs.
2. **Build prompt** deterministically. Same inputs always produce the same prompt string. No timestamps, no random IDs.
3. **Call Claude** with `temperature=0` and a 30-second timeout. If the response fails schema validation, retry with the failure reason appended. If it fails 3 times, raise `GovernanceValidationError`.
4. **Persist failures** to a local failure store. On future runs, the 5 most recent failures are injected as counter-examples in the prompt.
5. **Build receipt** with SHA-256 hashes of the file, rules, and previous receipt. The chain is verifiable offline.

---

## CLI Reference

```
python audit_agent.py [targets...] [options]
```

### Arguments

| Argument | Description |
|---|---|
| `targets` | Files or directories to audit. Defaults to `*.py` in the current directory. Directories are searched recursively for `.py` files. |

### Options

| Flag | Default | Description |
|---|---|---|
| `--rules PATH` | `rules.yaml` | Path to the YAML rules file. |
| `--model ID` | `claude-opus-4-6` | Anthropic model ID to use for audit calls. |
| `--output-dir DIR` | `.` | Directory for receipt JSON files. Created if it doesn't exist. |
| `--fail-on-violations` | off | Exit 1 if any violations are found. Without this flag, the agent always exits 0 (audit-only / reporting mode). |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | All files passed, or `--fail-on-violations` was not set. |
| `1` | Violations found and `--fail-on-violations` was set. |

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key. Raises `EnvironmentError` if missing. |

---

## Rules Format

Rules are defined in external YAML with two sections: **SPOT** (Security Prevention & Output Tracking) and **FORT** (Framework-Oriented Runtime Trust).

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
    - id: SPOT-002
      name: No hardcoded secrets
      description: "No string literals matching secret/key/password/token patterns"
      severity: critical

FORT:
  description: "Framework-Oriented Runtime Trust"
  rules:
    - id: FORT-001
      name: Function complexity
      description: "Functions must not exceed 50 statements"
      severity: medium
    - id: FORT-002
      name: No global mutation
      description: "Functions must not mutate module-level state"
      severity: medium
```

### Rule schema requirements

Each rule **must** have these keys: `id`, `name`, `description`. Optional: `severity` (defaults to `medium`).

Each section **must** be a mapping with a `rules` key containing a list.

Severity levels: `critical`, `high`, `medium`, `low`.

Rules are validated at load time. A malformed rules file raises `ValueError` before any audit runs -- not mid-pipeline.

### Tuning the default rules

The default ruleset ships with 10 rules. Some are strict by design and may produce noise in codebases that don't follow the convention they enforce:

| Rule | What it enforces | When to disable |
|---|---|---|
| `FORT-004` | Public functions must have return type annotations | Your team doesn't use strict type annotations. Most Python codebases will trigger this. |
| `FORT-005` | No wildcard imports | You use `from module import *` intentionally (e.g., re-exporting in `__init__.py`). |

To disable a rule, remove it from your `rules.yaml`. There is no `enabled: false` flag -- if a rule is in the file, it's enforced.

### Writing custom rules

Create a new YAML file following the schema above. You can have any number of rules per section. Rules are injected verbatim into the audit prompt, so write descriptions that are specific and unambiguous:

```yaml
# Good -- specific, testable
description: "Forbids eval(), exec(), and compile() calls in any context"

# Bad -- vague, subjective
description: "Code should be secure"
```

---

## Receipt Format

Each audited file produces a tamper-evident JSON receipt:

```json
{
  "version": "2.0",
  "timestamp": "2026-02-22T14:30:00.000000+00:00",
  "file": {
    "path": "auth.py",
    "hash": "a1b2c3d4..."
  },
  "rules": {
    "path": "rules.yaml",
    "hash": "d4e5f6a7..."
  },
  "model": "claude-opus-4-6",
  "duration_seconds": 3.41,
  "result": {
    "passed": false,
    "risk_level": "CRITICAL",
    "spot_violation_count": 1,
    "fort_violation_count": 0,
    "summary": "eval() call on line 42 violates SPOT-001.",
    "retry_count": 0
  },
  "chain": {
    "previous_receipt_hash": null
  },
  "receipt_hash": "f7a8b9c0..."
}
```

### Receipt fields

| Field | Description |
|---|---|
| `file.hash` | SHA-256 of the source file content at audit time. |
| `rules.hash` | SHA-256 of the rules file content. |
| `result.retry_count` | Number of validation retries (0 = first attempt succeeded). |
| `result.risk_level` | One of: `CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `chain.previous_receipt_hash` | SHA-256 of the previous receipt in the batch. `null` for the first file. |
| `receipt_hash` | SHA-256 of the receipt body. Verifiable offline. |

### Verifying the chain

Receipts are hash-chained within a single audit run. To verify:

1. Recompute the SHA-256 of each receipt body (all fields except `receipt_hash`).
2. Confirm each `previous_receipt_hash` matches the preceding receipt's `receipt_hash`.
3. Confirm `file.hash` matches the SHA-256 of the source file at the audited commit.

---

## CI Integration

### GitHub Actions

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

      - name: Run M87 audit (enforcement mode)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: python audit_agent.py src/ --fail-on-violations

      - name: Upload receipts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-receipts
          path: "*.receipt.json"
```

### Two modes

| Mode | Command | Behavior |
|---|---|---|
| **Audit only** (reporting) | `python audit_agent.py src/` | Always exits 0. Receipts are written. Violations are printed but don't block. |
| **Enforcement** (CI gate) | `python audit_agent.py src/ --fail-on-violations` | Exits 1 if any file has violations. Blocks the merge. |

Use audit-only mode in development branches. Use enforcement mode on PRs to `main`.

---

## Architecture

### Design invariants

1. **Prompt determinism.** `build_prompt(code, filename, rules_text)` is a pure function. Same inputs, same output. No timestamps, no random IDs in the prompt.

2. **Rules are external YAML.** No rules are hardcoded. Swap per-repo or per-team.

3. **Receipts are hash-chained.** Each receipt includes SHA-256 hashes of the file, rules, and previous receipt. Verifiable offline without re-running the audit.

4. **Claude is the reasoning engine, not the policy store.** Rules are injected verbatim. Claude evaluates code against those rules and returns structured JSON.

5. **Fails closed.** Invalid schema output after 3 retries raises `GovernanceValidationError`. API timeout after 30 seconds raises `RuntimeError`. Missing API key raises `EnvironmentError`. No silent degradation.

6. **Zero framework dependencies.** `requests` and `pyyaml`. No agent orchestration libraries, no ORMs, no DSLs.

### Validation retry loop

```
prompt ──▶ call_claude() ──▶ validate_audit_result()
               │                      │
               │                 valid? ──▶ return (result, attempt)
               │                      │
               │                 invalid ──▶ save_failure()
               │                              ──▶ append failure reason to prompt
               │                              ──▶ retry (up to 3x)
               │
               └── RuntimeError (JSON parse / timeout)
                       ──▶ save_failure()
                       ──▶ retry with failure reason
```

After `max_retries` failures: raises `GovernanceValidationError` with full `retry_trace`.

### Failure store

Failed LLM responses are persisted to `failures/` as JSON files. On subsequent runs, the 5 most recent failures are loaded and injected into the prompt as counter-examples. This creates a feedback loop: the model learns what *not* to produce.

- **Auto-rotation**: Only the 50 most recent failures are kept (`MAX_FAILURES=50`). Oldest files are deleted on each save.
- **Gitignored**: `failures/` is in `.gitignore`. These are local operational artifacts, not source.

### Production hardening

| Mechanism | What it prevents |
|---|---|
| API timeout (30s) | Hung API call stalling a CI pipeline indefinitely. |
| Failure store rotation (50 max) | Unbounded disk growth on repeated runs. |
| Rule schema validation on load | Malformed YAML failing mid-audit with an unhelpful error. |
| Schema validation on output | Invalid LLM output reaching a receipt. |
| `GovernanceValidationError` | Silent pass-through of unvalidated data. |

---

## API Reference

### Functions

#### `load_rules(rules_path) -> dict`
Load and validate a YAML rules file. Raises `FileNotFoundError` if the file doesn't exist. Raises `ValueError` if the schema is invalid (missing sections, bad types, missing rule keys).

#### `format_rules_for_prompt(schema) -> str`
Format loaded rules into a text block for injection into the audit prompt.

#### `build_prompt(code, file_name, rules_text) -> str`
Construct the deterministic audit prompt. Pure function -- no side effects.

#### `compute_hash(content) -> str`
SHA-256 hex digest of a UTF-8 string.

#### `build_receipt(..., retry_count=0) -> dict`
Build a tamper-evident audit receipt with hash chaining. Includes file hash, rules hash, result summary, retry count, and chain link.

#### `call_claude(prompt) -> dict`
Call the Anthropic Messages API. Returns parsed JSON. Strips markdown fences. Raises `EnvironmentError` on missing API key, `RuntimeError` on timeout or invalid JSON.

#### `validate_audit_result(data) -> tuple[bool, str]`
Validate an audit result dict against the required schema. Returns `(True, "")` on success, `(False, reason)` on failure.

#### `call_claude_with_validation(prompt, validator=..., max_retries=3) -> tuple[dict, int]`
Call Claude with schema validation and retry loop. Returns `(result, retry_count)`. Raises `GovernanceValidationError` after exhausting retries.

#### `save_failure(prompt, raw_response, reason) -> None`
Persist a failed LLM response to the failure store. Auto-rotates beyond `MAX_FAILURES`.

#### `load_negative_examples(max_examples=5) -> list[dict]`
Load the N most recent failure examples from the failure store.

#### `inject_negative_examples(prompt, examples) -> str`
Append failure counter-examples to a prompt string.

#### `collect_targets(paths) -> list[Path]`
Resolve a list of file/directory paths into `.py` file targets. Directories are searched recursively.

#### `main()`
CLI entry point. Parses arguments, loads rules, audits targets, writes receipts, exits with appropriate code.

### Exceptions

#### `GovernanceValidationError`
Raised when Claude output fails schema validation after all retries. Has a `retry_trace` attribute containing a list of `{"attempt": int, "reason": str}` dicts.

### Constants

| Constant | Value | Description |
|---|---|---|
| `REQUIRED_FIELDS` | `{spot_violations, fort_violations, passed, risk_level, summary}` | Required keys in audit result JSON. |
| `VALID_RISK_LEVELS` | `{CLEAN, LOW, MEDIUM, HIGH, CRITICAL}` | Allowed values for `risk_level`. |
| `REQUIRED_RULE_KEYS` | `{id, name, description}` | Required keys per rule in YAML. |
| `MAX_FAILURES` | `50` | Maximum failure files retained in the store. |
| `API_TIMEOUT` | `30` | Seconds before the API call times out. |

---

## Tests

```bash
pip install pytest requests pyyaml
pytest tests/ -v
```

50 tests. No network calls. All API interactions are mocked.

### Test coverage by area

| Area | Tests | What's covered |
|---|---|---|
| Rule loading | 7 | Valid load, missing file, missing section, non-dict section, non-list rules, missing rule keys, valid rules |
| Prompt construction | 3 | Determinism, file name inclusion, code inclusion |
| Hashing & receipts | 5 | SHA-256 correctness, determinism, different inputs, receipt structure, chain linking |
| Receipt fields | 2 | Violation counts, retry count |
| API call (mocked) | 6 | Markdown fence stripping, clean JSON, missing API key, invalid JSON, timeout, timeout kwarg |
| Model threading | 4 | Default model sent, custom model sent, model threaded through validation, `--model` flag reaches API call |
| Target collection | 4 | Empty glob, single file, directory recursion, non-py skip |
| `--fail-on-violations` | 3 | Violations + flag = exit 1, violations no flag = exit 0, clean + flag = exit 0 |
| Schema validator | 5 | Valid result, missing field, invalid risk level, wrong type, non-list violations |
| Retry loop | 4 | First attempt success, retry on schema failure, fail closed after max, retry trace |
| Failure store | 5 | Save/load round-trip, inject appends, inject empty unchanged, rotation prunes, rotation keeps recent |

---

## Project Structure

```
m87-audit-agent/
  audit_agent.py             # Single-file CLI and core logic (393 lines)
  rules.yaml                 # Default SPOT + FORT ruleset (10 rules)
  tests/
    test_audit_agent.py      # Full test suite (46 tests)
  failures/                  # Auto-created failure store (gitignored)
  .gitignore
  README.md
```

---

## Onboarding

### For engineers adding this to an existing repo

1. Copy `audit_agent.py` and `rules.yaml` into your repo root.
2. Edit `rules.yaml` to match your team's policies. Every rule needs `id`, `name`, and `description`.
3. Set `ANTHROPIC_API_KEY` in your environment (or CI secrets).
4. Run `python audit_agent.py src/` to verify it works locally.
5. Add the GitHub Actions workflow above to `.github/workflows/audit.yml`.
6. Use `--fail-on-violations` in CI to block merges on violations.

### For engineers modifying the agent

- **Adding a rule**: Edit `rules.yaml`. No code changes needed.
- **Changing the model**: Pass `--model claude-sonnet-4-20250514` (or any Anthropic model ID).
- **Adjusting retries**: Change `max_retries` in `call_claude_with_validation()`.
- **Adjusting timeout**: Change `API_TIMEOUT` in `audit_agent.py`.
- **Adjusting failure store size**: Change `MAX_FAILURES` in `audit_agent.py`.
- **Running tests**: `pytest tests/ -v`. All tests are self-contained with mocked API calls.

### For engineers reviewing audit results

- Receipts are in the output directory (default: current directory) as `<filename>.receipt.json`.
- `result.passed: false` means violations were found. Check `result.summary` for the one-line explanation.
- `result.retry_count > 0` means the model needed multiple attempts to produce valid schema output.
- `chain.previous_receipt_hash` links receipts in order. Verify the chain to confirm no receipts were tampered with or removed.

---

## License

MIT
