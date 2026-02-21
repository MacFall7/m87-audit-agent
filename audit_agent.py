"""
M87 Audit Agent v2 — Governed Python code auditor.
Deterministic enforcement, cryptographic receipts, CI-ready.
"""

import os
import sys
import json
import time
import hashlib
import datetime
from pathlib import Path

import requests
import yaml


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
):
    """Build a tamper-evident audit receipt with hash chaining."""
    file_hash = compute_hash(file_content)
    rules_hash = compute_hash(Path(rules_path).read_text(encoding="utf-8"))
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

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
        },
        "chain": {
            "previous_receipt_hash": previous_receipt_hash,
        },
    }

    receipt_hash = compute_hash(json.dumps(receipt_body, sort_keys=True))
    receipt_body["receipt_hash"] = receipt_hash
    return receipt_body


def call_claude(prompt):
    """Call the Anthropic Messages API and return parsed JSON."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

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
        result = call_claude(prompt)
        duration = round(time.time() - start, 2)

        receipt = build_receipt(
            file_path=target,
            file_content=content,
            audit_result=result,
            rules_path=rules_path,
            model=args.model,
            duration_seconds=duration,
            previous_receipt_hash=previous_hash,
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
