"""
Tests for M87 Audit Agent v2.
Run: pytest tests/ -v
"""

import json
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import requests
import yaml

# Adjust path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from audit_agent import (
    load_rules,
    format_rules_for_prompt,
    build_prompt,
    compute_hash,
    build_receipt,
    call_claude,
    collect_targets,
    main,
    validate_audit_result,
    call_claude_with_validation,
    save_failure,
    load_negative_examples,
    inject_negative_examples,
    GovernanceValidationError,
    FAILURES_DIR,
    MAX_FAILURES,
    API_TIMEOUT,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rules_path(tmp_path):
    """Write a minimal rules YAML and return its path."""
    rules = {
        "version": "1.0",
        "ruleset_id": "test-ruleset",
        "description": "Test rules",
        "SPOT": {
            "description": "Security rules",
            "rules": [
                {"id": "SPOT-001", "name": "No eval", "description": "No eval()", "severity": "critical"}
            ],
        },
        "FORT": {
            "description": "Runtime rules",
            "rules": [
                {"id": "FORT-001", "name": "Complexity", "description": "<=10 lines", "severity": "medium"}
            ],
        },
    }
    p = tmp_path / "test_rules.yaml"
    p.write_text(yaml.dump(rules))
    return p


@pytest.fixture
def sample_py(tmp_path):
    code = "def hello():\n    return 'world'\n"
    p = tmp_path / "sample.py"
    p.write_text(code)
    return p


@pytest.fixture
def clean_audit_result():
    return {
        "spot_violations": [],
        "fort_violations": [],
        "passed": True,
        "risk_level": "CLEAN",
        "summary": "No violations found.",
    }


@pytest.fixture
def dirty_audit_result():
    return {
        "spot_violations": [
            {"rule_id": "SPOT-001", "severity": "critical", "line": 5, "description": "eval() used"}
        ],
        "fort_violations": [],
        "passed": False,
        "risk_level": "CRITICAL",
        "summary": "Critical SPOT violation found.",
    }


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def test_load_rules_success(rules_path):
    schema = load_rules(rules_path)
    assert "SPOT" in schema
    assert "FORT" in schema
    assert schema["ruleset_id"] == "test-ruleset"


def test_load_rules_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nonexistent.yaml")


def test_load_rules_missing_section(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.dump({"version": "1.0", "SPOT": {"description": "x", "rules": []}}))
    with pytest.raises(ValueError, match="FORT"):
        load_rules(bad)


def test_format_rules_for_prompt_contains_ids(rules_path):
    schema = load_rules(rules_path)
    text = format_rules_for_prompt(schema)
    assert "SPOT-001" in text
    assert "FORT-001" in text
    assert "CRITICAL" in text.upper() or "critical" in text.lower()


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def test_build_prompt_is_deterministic(rules_path):
    schema = load_rules(rules_path)
    rules_text = format_rules_for_prompt(schema)
    p1 = build_prompt("code here", "test.py", rules_text)
    p2 = build_prompt("code here", "test.py", rules_text)
    assert p1 == p2


def test_build_prompt_contains_file_name(rules_path):
    schema = load_rules(rules_path)
    rules_text = format_rules_for_prompt(schema)
    prompt = build_prompt("x = 1", "auth.py", rules_text)
    assert "auth.py" in prompt


def test_build_prompt_contains_code(rules_path):
    schema = load_rules(rules_path)
    rules_text = format_rules_for_prompt(schema)
    prompt = build_prompt("SECRET = 'abc123'", "config.py", rules_text)
    assert "SECRET = 'abc123'" in prompt


# ---------------------------------------------------------------------------
# Hashing and receipts
# ---------------------------------------------------------------------------

def test_compute_hash_is_sha256():
    content = "hello world"
    expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert compute_hash(content) == expected


def test_compute_hash_deterministic():
    assert compute_hash("abc") == compute_hash("abc")


def test_compute_hash_different_inputs():
    assert compute_hash("abc") != compute_hash("xyz")


def test_build_receipt_structure(sample_py, rules_path, clean_audit_result):
    content = sample_py.read_text()
    receipt = build_receipt(
        file_path=sample_py,
        file_content=content,
        audit_result=clean_audit_result,
        rules_path=rules_path,
        model="claude-opus-4-6",
        duration_seconds=1.23,
        previous_receipt_hash=None,
    )
    assert "receipt_hash" in receipt
    assert receipt["result"]["passed"] is True
    assert receipt["result"]["risk_level"] == "CLEAN"
    assert receipt["file"]["hash"] == compute_hash(content)
    assert receipt["chain"]["previous_receipt_hash"] is None


def test_build_receipt_chains_correctly(sample_py, rules_path, clean_audit_result):
    content = sample_py.read_text()
    r1 = build_receipt(sample_py, content, clean_audit_result, rules_path, "model", 1.0, None)
    r2 = build_receipt(sample_py, content, clean_audit_result, rules_path, "model", 1.0, r1["receipt_hash"])
    assert r2["chain"]["previous_receipt_hash"] == r1["receipt_hash"]


def test_receipt_hash_changes_with_content(sample_py, rules_path, clean_audit_result):
    r1 = build_receipt(sample_py, "content_a", clean_audit_result, rules_path, "model", 1.0, None)
    r2 = build_receipt(sample_py, "content_b", clean_audit_result, rules_path, "model", 1.0, None)
    assert r1["receipt_hash"] != r2["receipt_hash"]


def test_receipt_violation_counts(sample_py, rules_path, dirty_audit_result):
    receipt = build_receipt(sample_py, "code", dirty_audit_result, rules_path, "model", 0.5, None)
    assert receipt["result"]["spot_violation_count"] == 1
    assert receipt["result"]["fort_violation_count"] == 0
    assert receipt["result"]["passed"] is False


# ---------------------------------------------------------------------------
# API call (mocked)
# ---------------------------------------------------------------------------

def test_call_claude_strips_markdown_fences():
    mock_result = {"passed": True, "spot_violations": [], "fort_violations": [], "risk_level": "CLEAN", "summary": "ok"}
    fenced = f"```json\n{json.dumps(mock_result)}\n```"

    with patch("audit_agent.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.json.return_value = {"content": [{"text": fenced}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            result = call_claude("test prompt")

    assert result["passed"] is True


def test_call_claude_handles_clean_json():
    mock_result = {"passed": False, "spot_violations": [], "fort_violations": [], "risk_level": "HIGH", "summary": "bad"}

    with patch("audit_agent.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.json.return_value = {"content": [{"text": json.dumps(mock_result)}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            result = call_claude("test prompt")

    assert result["risk_level"] == "HIGH"


def test_call_claude_raises_on_missing_api_key():
    with patch.dict("os.environ", {}, clear=True):
        if "ANTHROPIC_API_KEY" in __import__("os").environ:
            del __import__("os").environ["ANTHROPIC_API_KEY"]
        with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
            call_claude("prompt")


def test_call_claude_raises_on_invalid_json():
    with patch("audit_agent.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.json.return_value = {"content": [{"text": "not valid json at all {{"}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            with pytest.raises(RuntimeError, match="Failed to parse"):
                call_claude("prompt")


# ---------------------------------------------------------------------------
# Target collection
# ---------------------------------------------------------------------------

def test_collect_targets_empty_returns_glob(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.py").touch()
    (tmp_path / "b.py").touch()
    targets = collect_targets([])
    names = [t.name for t in targets]
    assert "a.py" in names
    assert "b.py" in names


def test_collect_targets_single_file(tmp_path):
    f = tmp_path / "only.py"
    f.touch()
    targets = collect_targets([str(f)])
    assert len(targets) == 1
    assert targets[0].name == "only.py"


def test_collect_targets_directory(tmp_path):
    (tmp_path / "x.py").touch()
    (tmp_path / "y.py").touch()
    (tmp_path / "ignore.txt").touch()
    targets = collect_targets([str(tmp_path)])
    names = [t.name for t in targets]
    assert "x.py" in names
    assert "y.py" in names
    assert "ignore.txt" not in names


def test_collect_targets_skips_non_py(tmp_path):
    f = tmp_path / "README.md"
    f.touch()
    targets = collect_targets([str(f)])
    assert len(targets) == 0


# ---------------------------------------------------------------------------
# --fail-on-violations flag
# ---------------------------------------------------------------------------

def _run_main_with_args(argv, mock_result, rules_path, tmp_path):
    """Helper to invoke main() with mocked API and given CLI args."""
    target = tmp_path / "code.py"
    target.write_text("x = 1\n")

    full_argv = [str(target), "--rules", str(rules_path)] + argv

    with patch("audit_agent.call_claude_with_validation", return_value=(mock_result, 0)), \
         patch("sys.argv", ["audit_agent"] + full_argv):
        main()


def test_fail_on_violations_exits_1_when_violations(rules_path, tmp_path, dirty_audit_result):
    """With --fail-on-violations, violations should exit 1."""
    with pytest.raises(SystemExit) as exc:
        _run_main_with_args(["--fail-on-violations"], dirty_audit_result, rules_path, tmp_path)
    assert exc.value.code == 1


def test_no_fail_flag_exits_0_even_with_violations(rules_path, tmp_path, dirty_audit_result):
    """Without --fail-on-violations, violations should still exit 0 (audit-only mode)."""
    with pytest.raises(SystemExit) as exc:
        _run_main_with_args([], dirty_audit_result, rules_path, tmp_path)
    assert exc.value.code == 0


def test_fail_on_violations_exits_0_when_clean(rules_path, tmp_path, clean_audit_result):
    """With --fail-on-violations but no violations, should exit 0."""
    with pytest.raises(SystemExit) as exc:
        _run_main_with_args(["--fail-on-violations"], clean_audit_result, rules_path, tmp_path)
    assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Schema validator
# ---------------------------------------------------------------------------

def test_validate_audit_result_passes_clean_result(clean_audit_result):
    valid, reason = validate_audit_result(clean_audit_result)
    assert valid is True
    assert reason == ""


def test_validate_audit_result_missing_field(clean_audit_result):
    del clean_audit_result["risk_level"]
    valid, reason = validate_audit_result(clean_audit_result)
    assert valid is False
    assert "Missing required fields" in reason


def test_validate_audit_result_invalid_risk_level(clean_audit_result):
    clean_audit_result["risk_level"] = "UNKNOWN"
    valid, reason = validate_audit_result(clean_audit_result)
    assert valid is False
    assert "risk_level must be one of" in reason


def test_validate_audit_result_wrong_type_passed(clean_audit_result):
    clean_audit_result["passed"] = "yes"
    valid, reason = validate_audit_result(clean_audit_result)
    assert valid is False
    assert "passed must be a boolean" in reason


def test_validate_audit_result_violations_not_list(clean_audit_result):
    clean_audit_result["spot_violations"] = None
    valid, reason = validate_audit_result(clean_audit_result)
    assert valid is False
    assert "spot_violations must be a list" in reason


# ---------------------------------------------------------------------------
# Validation retry loop
# ---------------------------------------------------------------------------

def test_validation_succeeds_first_attempt(clean_audit_result):
    with patch("audit_agent.call_claude", return_value=clean_audit_result), \
         patch("audit_agent.load_negative_examples", return_value=[]):
        result, retries = call_claude_with_validation("test prompt")
    assert result == clean_audit_result
    assert retries == 0


def test_validation_retries_on_schema_failure(clean_audit_result):
    bad_result = {"not": "valid"}
    with patch("audit_agent.call_claude", side_effect=[bad_result, clean_audit_result]), \
         patch("audit_agent.load_negative_examples", return_value=[]), \
         patch("audit_agent.save_failure"):
        result, retries = call_claude_with_validation("test prompt")
    assert result == clean_audit_result
    assert retries == 1


def test_validation_fails_closed_after_max_retries():
    bad_result = {"not": "valid"}
    with patch("audit_agent.call_claude", return_value=bad_result), \
         patch("audit_agent.load_negative_examples", return_value=[]), \
         patch("audit_agent.save_failure"):
        with pytest.raises(GovernanceValidationError, match="failed schema validation after 3 attempts"):
            call_claude_with_validation("test prompt", max_retries=3)


def test_retry_trace_attached_to_exception():
    bad_result = {"not": "valid"}
    with patch("audit_agent.call_claude", return_value=bad_result), \
         patch("audit_agent.load_negative_examples", return_value=[]), \
         patch("audit_agent.save_failure"):
        with pytest.raises(GovernanceValidationError) as exc:
            call_claude_with_validation("test prompt", max_retries=2)
    assert len(exc.value.retry_trace) == 2
    assert exc.value.retry_trace[0]["attempt"] == 1
    assert exc.value.retry_trace[1]["attempt"] == 2


# ---------------------------------------------------------------------------
# Failure store
# ---------------------------------------------------------------------------

def test_save_and_load_negative_examples(tmp_path, monkeypatch):
    monkeypatch.setattr("audit_agent.FAILURES_DIR", tmp_path / "failures")
    save_failure("prompt text", '{"bad": true}', "Missing required fields")
    examples = load_negative_examples()
    assert len(examples) == 1
    assert examples[0]["reason"] == "Missing required fields"
    assert examples[0]["raw_response"] == '{"bad": true}'


def test_inject_negative_examples_appends_to_prompt():
    examples = [{"reason": "bad field", "raw_response": '{"x": 1}'}]
    result = inject_negative_examples("original prompt", examples)
    assert "original prompt" in result
    assert "Counter-examples" in result
    assert "bad field" in result


def test_inject_negative_examples_empty_returns_unchanged():
    result = inject_negative_examples("original prompt", [])
    assert result == "original prompt"


# ---------------------------------------------------------------------------
# Receipt with retry_count
# ---------------------------------------------------------------------------

def test_receipt_includes_retry_count(sample_py, rules_path, clean_audit_result):
    content = sample_py.read_text()
    receipt = build_receipt(
        file_path=sample_py,
        file_content=content,
        audit_result=clean_audit_result,
        rules_path=rules_path,
        model="claude-opus-4-6",
        duration_seconds=1.0,
        previous_receipt_hash=None,
        retry_count=2,
    )
    assert receipt["result"]["retry_count"] == 2


# ---------------------------------------------------------------------------
# Failure store rotation
# ---------------------------------------------------------------------------

def test_failure_store_rotates_beyond_max(tmp_path, monkeypatch):
    """save_failure() should delete oldest files when count exceeds MAX_FAILURES."""
    monkeypatch.setattr("audit_agent.FAILURES_DIR", tmp_path / "failures")
    monkeypatch.setattr("audit_agent.MAX_FAILURES", 3)

    for i in range(5):
        save_failure("prompt", f"bad-{i}", f"reason-{i}")

    failures_dir = tmp_path / "failures"
    remaining = sorted(failures_dir.glob("failure.*.json"))
    assert len(remaining) <= 3


def test_failure_store_keeps_recent(tmp_path, monkeypatch):
    """After rotation, the most recent failure should still be loadable."""
    monkeypatch.setattr("audit_agent.FAILURES_DIR", tmp_path / "failures")
    monkeypatch.setattr("audit_agent.MAX_FAILURES", 2)

    save_failure("p", "old-response", "old-reason")
    save_failure("p", "new-response", "new-reason")

    examples = load_negative_examples(max_examples=10)
    responses = [e["raw_response"] for e in examples]
    assert "new-response" in responses


# ---------------------------------------------------------------------------
# Rule schema validation on load
# ---------------------------------------------------------------------------

def test_load_rules_rejects_non_dict_section(tmp_path):
    """A section that is a string instead of a mapping should raise ValueError."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.dump({"SPOT": "not-a-dict", "FORT": {"description": "x", "rules": []}}))
    with pytest.raises(ValueError, match="SPOT must be a mapping"):
        load_rules(bad)


def test_load_rules_rejects_missing_rules_list(tmp_path):
    """A section without a 'rules' key (or rules as non-list) should raise ValueError."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.dump({
        "SPOT": {"description": "x", "rules": "not-a-list"},
        "FORT": {"description": "y", "rules": []},
    }))
    with pytest.raises(ValueError, match="SPOT.rules must be a list"):
        load_rules(bad)


def test_load_rules_rejects_rule_missing_keys(tmp_path):
    """A rule missing id/name/description should raise ValueError at load time."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.dump({
        "SPOT": {
            "description": "x",
            "rules": [{"id": "SPOT-001", "name": "No eval"}],  # missing description
        },
        "FORT": {"description": "y", "rules": []},
    }))
    with pytest.raises(ValueError, match="missing required keys"):
        load_rules(bad)


def test_load_rules_accepts_valid_rules(rules_path):
    """Existing well-formed rules fixture should still load cleanly."""
    schema = load_rules(rules_path)
    assert len(schema["SPOT"]["rules"]) == 1
    assert schema["SPOT"]["rules"][0]["id"] == "SPOT-001"


# ---------------------------------------------------------------------------
# API timeout
# ---------------------------------------------------------------------------

def test_call_claude_timeout_raises_runtime_error():
    """A timeout from requests should surface as RuntimeError (fail closed)."""
    with patch("audit_agent.requests.post", side_effect=requests.exceptions.Timeout("timed out")):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            with pytest.raises(RuntimeError, match="timed out after"):
                call_claude("prompt")


def test_call_claude_passes_timeout_to_requests():
    """requests.post should receive the timeout kwarg."""
    mock_result = {"passed": True, "spot_violations": [], "fort_violations": [], "risk_level": "CLEAN", "summary": "ok"}

    with patch("audit_agent.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.json.return_value = {"content": [{"text": json.dumps(mock_result)}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("test prompt")

    _, kwargs = mock_post.call_args
    assert kwargs["timeout"] == API_TIMEOUT
