"""
M87 Audit Agent v2 — Governed Python code auditor.
Deterministic enforcement, cryptographic receipts, CI-ready.
"""

import os
import sys
import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml


class GovernanceValidationError(Exception):
    """Raised when Claude output fails schema validation after all retries."""

    def __init__(self, message, retry_trace=None):
        super().__init__(message)
        self.retry_trace = retry_trace or []


REQUIRED_FIELDS = {"spot_violations", "fort_violations", "passed", "risk_level", "summary"}
VALID_RISK_LEVELS = {"CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
FAILURES_DIR = Path(__file__).parent / "failures"
MAX_FAILURES = 50


REQUIRED_RULE_KEYS = {"id", "name", "description"}


def load_rules(rules_path):
    """Load and validate a YAML rules file."""
    rules_path = Path(rules_path)
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    with open(rules_path, "r", encoding="utf-8") as f:
        schema = yaml.safe_load(f)

    for section in ("SPOT", "FORT"):
        if section not in schema:
            raise ValueError(f"Missing required section: {section}")
        section_data = schema[section]
        if not isinstance(section_data, dict):
            raise ValueError(f"{section} must be a mapping, got: {type(section_data).__name__}")
        rules = section_data.get("rules")
        if not isinstance(rules, list):
            raise ValueError(f"{section}.rules must be a list")
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"{section}.rules[{i}] must be a mapping")
            missing = REQUIRED_RULE_KEYS - rule.keys()
            if missing:
                raise ValueError(f"{section}.rules[{i}] missing required keys: {missing}")

    return schema


def format_rules_for_prompt(schema):
    """Format loaded rules into a text block for the audit prompt."""
    lines = []
    for section_key in ("SPOT", "FORT"):
        section = schema[section_key]
        lines.append(f"## {section_key} — {section.get('description', '')}")
        for rule in section.get("rules", []):
            severity = rule.get("severity", "medium").upper()
            lines.append(
                f"  - [{rule['id']}] {rule['name']} ({severity}): {rule['description']}"
            )
        lines.append("")
    return "\n".join(lines)


def build_prompt(code, file_name, rules_text):
    """Construct the deterministic audit prompt."""
    return (
        "You are M87 Audit Agent, a governed security and runtime compliance auditor.\n"
        "Analyze the following Python file against the rules below.\n\n"
        f"File: {file_name}\n\n"
        f"Rules:\n{rules_text}\n\n"
        f"Code:\n```python\n{code}\n```\n\n"
        "Respond with ONLY a JSON object (no markdown fences, no commentary):\n"
        "{\n"
        '  "spot_violations": [{"rule_id": "...", "severity": "...", "line": N, "description": "..."}],\n'
        '  "fort_violations": [{"rule_id": "...", "severity": "...", "line": N, "description": "..."}],\n'
        '  "passed": true/false,\n'
        '  "risk_level": "CLEAN|LOW|MEDIUM|HIGH|CRITICAL",\n'
        '  "summary": "One-line summary"\n'
        "}"
    )


def compute_hash(content):
    """SHA-256 hash of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def build_receipt(
    file_path,
    file_content,
    audit_result,
    rules_path,
    model,
    duration_seconds,
    previous_receipt_hash,
    retry_count=0,
):
    """Build a tamper-evident audit receipt with hash chaining."""
    file_hash = compute_hash(file_content)
    rules_hash = compute_hash(Path(rules_path).read_text(encoding="utf-8"))
    timestamp = datetime.now(timezone.utc).isoformat()

    receipt_body = {
        "version": "2.0",
        "timestamp": timestamp,
        "file": {
            "path": str(file_path),
            "hash": file_hash,
        },
        "rules": {
            "path": str(rules_path),
            "hash": rules_hash,
        },
        "model": model,
        "duration_seconds": duration_seconds,
        "result": {
            "passed": audit_result["passed"],
            "risk_level": audit_result["risk_level"],
            "spot_violation_count": len(audit_result.get("spot_violations", [])),
            "fort_violation_count": len(audit_result.get("fort_violations", [])),
            "summary": audit_result.get("summary", ""),
            "retry_count": retry_count,
        },
        "chain": {
            "previous_receipt_hash": previous_receipt_hash,
        },
    }

    receipt_hash = compute_hash(json.dumps(receipt_body, sort_keys=True))
    receipt_body["receipt_hash"] = receipt_hash
    return receipt_body


API_TIMEOUT = 30  # seconds — fail closed rather than hang a CI pipeline


def call_claude(prompt):
    """Call the Anthropic Messages API and return parsed JSON."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-opus-4-6",
                "max_tokens": 4096,
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=API_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(
            f"Claude API call timed out after {API_TIMEOUT}s. "
            "Pipeline cannot proceed without a response — failing closed."
        )
    response.raise_for_status()

    text = response.json()["content"][0]["text"].strip()

    # Strip markdown fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse Claude response as JSON: {e}")


def validate_audit_result(data):
    """Validate audit result against required schema. Returns (valid, reason)."""
    if not isinstance(data, dict):
        return False, f"Response must be a JSON object, got: {type(data).__name__}"
    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        return False, f"Missing required fields: {missing}"
    if not isinstance(data["spot_violations"], list):
        return False, "spot_violations must be a list"
    if not isinstance(data["fort_violations"], list):
        return False, "fort_violations must be a list"
    if not isinstance(data["passed"], bool):
        return False, f"passed must be a boolean, got: {type(data['passed']).__name__}"
    if data["risk_level"] not in VALID_RISK_LEVELS:
        return False, f"risk_level must be one of {VALID_RISK_LEVELS}, got: '{data['risk_level']}'"
    return True, ""


def save_failure(prompt, raw_response, reason):
    """Persist a failed LLM response as a negative example."""
    FAILURES_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    failure = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "raw_response": raw_response,
    }
    path = FAILURES_DIR / f"failure.{ts}.json"
    path.write_text(json.dumps(failure, indent=2), encoding="utf-8")

    # Rotate: keep only the MAX_FAILURES most recent files
    all_failures = sorted(FAILURES_DIR.glob("failure.*.json"))
    for stale in all_failures[:-MAX_FAILURES]:
        stale.unlink()


def load_negative_examples(max_examples=5):
    """Load the N most recent failure examples for prompt injection."""
    if not FAILURES_DIR.exists():
        return []
    failures = sorted(FAILURES_DIR.glob("failure.*.json"), reverse=True)[:max_examples]
    examples = []
    for f in failures:
        try:
            examples.append(json.loads(f.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return examples


def inject_negative_examples(prompt, examples):
    """Inject failure examples into prompt as counter-examples."""
    if not examples:
        return prompt
    counter_block = "\n\n## Counter-examples (do NOT produce output like these)\n"
    for ex in examples:
        counter_block += f"\n- Reason this failed: {ex['reason']}\n"
        counter_block += f"  Bad output: {ex['raw_response'][:200]}\n"
    return prompt + counter_block


def call_claude_with_validation(
    prompt,
    validator=validate_audit_result,
    max_retries=3,
):
    """
    Call Claude with schema validation and retry loop.

    On validation failure, re-prompts with the specific failure reason attached.
    Persists failures to the failure store as negative examples.
    Fails closed after max_retries — never returns invalid output.

    Returns (result, retry_count).
    """
    retry_trace = []

    # Load and inject negative examples into initial prompt
    examples = load_negative_examples()
    active_prompt = inject_negative_examples(prompt, examples)

    for attempt in range(max_retries):
        try:
            result = call_claude(active_prompt)
        except RuntimeError as e:
            raw = str(e)
            reason = f"JSON parse failure: {e}"
            save_failure(active_prompt, raw, reason)
            retry_trace.append({"attempt": attempt + 1, "reason": reason})
            active_prompt = (
                prompt
                + f"\n\nYour previous response failed validation for this reason:\n{reason}"
                + "\n\nReturn only valid JSON matching the required schema. Try again."
            )
            continue

        valid, reason = validator(result)
        if valid:
            return result, attempt  # attempt=0 means first try succeeded

        # Validation failed — save to failure store and build retry prompt
        save_failure(active_prompt, json.dumps(result), reason)
        retry_trace.append({"attempt": attempt + 1, "reason": reason})
        active_prompt = (
            prompt
            + f"\n\nYour previous response failed validation for this reason:\n{reason}"
            + "\n\nReturn only valid JSON matching the required schema. Try again."
        )

    raise GovernanceValidationError(
        f"Claude output failed schema validation after {max_retries} attempts",
        retry_trace=retry_trace,
    )


def collect_targets(paths):
    """Resolve a list of paths into .py file targets."""
    if not paths:
        return sorted(Path(".").glob("*.py"))

    targets = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            targets.extend(sorted(p.glob("**/*.py")))
        elif p.is_file() and p.suffix == ".py":
            targets.append(p)
    return targets


def main():
    import argparse

    parser = argparse.ArgumentParser(description="M87 Audit Agent v2")
    parser.add_argument("targets", nargs="*", help="Files or directories to audit")
    parser.add_argument("--rules", default="rules.yaml", help="Path to rules YAML")
    parser.add_argument(
        "--model", default="claude-opus-4-6", help="Anthropic model ID"
    )
    parser.add_argument(
        "--output-dir", default=".", help="Directory for receipt JSON files"
    )
    parser.add_argument(
        "--fail-on-violations",
        action="store_true",
        help="Exit 1 if any violations found (CI gate mode)",
    )
    args = parser.parse_args()

    rules_path = Path(args.rules)
    schema = load_rules(rules_path)
    rules_text = format_rules_for_prompt(schema)

    targets = collect_targets(args.targets)
    if not targets:
        print("No .py files found to audit.")
        sys.exit(0)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    previous_hash = None
    all_passed = True

    for target in targets:
        print(f"Auditing: {target}")
        start = time.time()
        content = target.read_text(encoding="utf-8")
        prompt = build_prompt(content, str(target), rules_text)
        result, retry_count = call_claude_with_validation(prompt)
        duration = round(time.time() - start, 2)

        receipt = build_receipt(
            file_path=target,
            file_content=content,
            audit_result=result,
            rules_path=rules_path,
            model=args.model,
            duration_seconds=duration,
            previous_receipt_hash=previous_hash,
            retry_count=retry_count,
        )
        previous_hash = receipt["receipt_hash"]

        receipt_path = output_dir / f"{target.name}.receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

        status = "PASS" if result["passed"] else "FAIL"
        if not result["passed"]:
            all_passed = False
        print(f"  [{status}] {result['risk_level']} — {receipt_path}")

    sys.exit(1 if (not all_passed and args.fail_on_violations) else 0)


if __name__ == "__main__":
    main()
