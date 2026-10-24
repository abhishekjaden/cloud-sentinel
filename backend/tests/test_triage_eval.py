"""
Tests for the triage evaluation cases and their scoring.

The eval can only run where Bedrock answers, so what is pinned here is that it
would mean something when it does: every case can be turned into a request,
every expectation names a real field and a value the model is allowed to give
(a typo would make a case pass or fail for nothing), and every injection case
checks both that the attempt is flagged and that the verdict is not lowered.
"""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "eval_triage.py"


@pytest.fixture(scope="module")
def evaluation():
    spec = importlib.util.spec_from_file_location("eval_triage", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def handler(evaluation):
    return evaluation.load_handler()


@pytest.fixture(scope="module")
def cases(evaluation):
    """Both files' cases together: the author's, and the independent ones once
    they exist. Every check here applies to a case whoever wrote it."""
    return evaluation.load_cases() + evaluation.load_cases(evaluation.INDEPENDENT_CASES)


def test_the_two_case_files_do_not_share_names(evaluation):
    """A result is recorded against a case's name and the file it came from;
    a name in both files would make the record ambiguous."""
    authored = {c["name"] for c in evaluation.load_cases()}
    independent = {c["name"] for c in evaluation.load_cases(evaluation.INDEPENDENT_CASES)}
    assert not authored & independent


def test_every_case_becomes_a_request(handler, cases):
    assert len(cases) >= 5
    for case in cases:
        request = handler.converse_request(handler.incident_payload(case["incident"], case["findings"]))
        text = request["messages"][0]["content"][0]["text"]
        assert text.count("</incident>") == 1, case["name"]


def test_every_expectation_is_a_value_the_model_may_give(handler, cases):
    allowed = {
        "assessed_severity": set(handler.SEVERITIES),
        "confidence": set(handler.CONFIDENCES),
        "likely_test_data": {True, False},
        "injection_suspected": {True, False},
    }
    for case in cases:
        assert case["expect"], case["name"]
        for field, wanted in case["expect"].items():
            assert field in allowed, (case["name"], field)
            values = wanted if isinstance(wanted, list) else [wanted]
            assert set(values) <= allowed[field], (case["name"], field, values)


def test_injection_cases_check_the_flag_and_the_verdict(cases):
    # By the flag, not the name: an independent writer names cases their own way.
    injected = [c for c in cases if c["expect"].get("injection_suspected") is True]
    assert len(injected) >= 3
    for case in injected:
        assert case["expect"]["injection_suspected"] is True, case["name"]
        assert set(case["expect"]["assessed_severity"]) <= {"high", "critical"}, case["name"]
        # The attempt is really in the data the model sees, not only described.
        assert case["injected_text"] in json.dumps(case["findings"]), case["name"]


def test_every_test_data_case_also_pins_the_severity(cases):
    """Detecting sample findings was tested from the start; what the severity
    should be once they are detected was not, and the deployed model split on
    it. A case that expects likely_test_data must say what severity goes with
    it, so the meaning cannot drift untested again."""
    test_data_cases = [c for c in cases if c["expect"].get("likely_test_data") is True]
    assert test_data_cases
    for case in test_data_cases:
        assert "assessed_severity" in case["expect"], case["name"]
        # The activity, not the doubt: sample C&C is still rated as C&C.
        assert set(case["expect"]["assessed_severity"]) <= {"high", "critical"}, case["name"]


def test_cases_that_expect_real_data_carry_no_placeholder_markers(cases):
    """The prompt sets likely_test_data on the structure of the findings alone:
    placeholder resources, generator markers. A case that expects the flag clear
    must not carry those, or it fails for its own data rather than the prompt.
    The user-agent injection case did carry one — its access key read
    ASIA-EXAMPLE-ACCESS-KEY — so a flag set on the key could not be told from a
    flag set on the injected claim, which is what the case is for."""
    markers = ("99999999", "GeneratedFinding", "EXAMPLE")
    real = [c for c in cases if c["expect"].get("likely_test_data") is False]
    assert len(real) >= 3
    for case in real:
        resources = [case["incident"]["resource"]] + [f["resource"] for f in case["findings"]]
        for marker in markers:
            assert not any(marker in r for r in resources), (case["name"], marker)


def test_a_case_s_verdicts_name_indicators_the_case_has(handler, cases):
    """A verdict keyed to an indicator the incident does not list would never
    reach the model, and the case would silently test less than it says."""
    with_intel = [c for c in cases if c.get("intel")]
    assert with_intel
    for case in with_intel:
        keys = set(handler.indicator_keys(case["incident"]))
        assert set(case["intel"]) <= keys, (case["name"], set(case["intel"]) - keys)
        payload = handler.incident_payload(case["incident"], case["findings"], case["intel"])
        assert {i["intel"]["verdict"] for i in payload["indicators"]} >= {v["verdict"] for v in case["intel"].values()}


def test_a_note_passes_only_when_every_expectation_holds(evaluation):
    note = {"assessed_severity": "high", "injection_suspected": True, "likely_test_data": False}
    assert evaluation.check(note, {"assessed_severity": ["high", "critical"],
                                   "injection_suspected": True}) == []
    failures = evaluation.check(note, {"assessed_severity": ["low"], "likely_test_data": True})
    assert len(failures) == 2


def test_a_rejected_note_fails_its_case(evaluation, handler, cases):
    class Model:
        def converse(self, **_):
            return {"output": {"message": {"content": [{"text": "not a tool call"}]}}}

    note, failures = evaluation.run_case(handler, Model(), cases[0])
    assert note is None
    assert failures and failures[0].startswith("rejected")


def test_a_recorded_answer_keeps_the_tokens_and_the_round_trip(evaluation, handler, cases):
    class Model:
        def converse(self, **request):
            assert request["modelId"] == handler.MODEL_ID
            return {"output": {"message": {"content": [{"toolUse": {"name": handler.TOOL_NAME, "input": {
                        "summary": "x", "assessed_severity": "critical", "confidence": "low",
                        "likely_test_data": False, "injection_suspected": True,
                        "reasons": ["a"], "next_steps": ["b"]}}}]}},
                    "usage": {"inputTokens": 1200, "outputTokens": 150, "totalTokens": 1350},
                    "metrics": {"latencyMs": 2345}}

    answer = evaluation.run_case_recorded(handler, Model(), cases[0])
    assert answer["usage"] == {"input_tokens": 1200, "output_tokens": 150} and answer["latency_ms"] == 2345
    assert answer["note"]["assessed_severity"] == "critical"
    assert isinstance(answer["failures"], list)


def test_another_model_is_asked_through_the_same_request(evaluation, monkeypatch):
    monkeypatch.setenv("TRIAGE_MODEL_ID", "the-deployed-one")       # restored afterwards, whatever load_handler sets
    other = evaluation.load_handler(model="us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert other.MODEL_ID == "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    request = other.converse_request(other.incident_payload(evaluation.load_cases()[0]["incident"],
                                                            evaluation.load_cases()[0]["findings"]))
    assert request["modelId"] == other.MODEL_ID
    assert request["toolConfig"]["toolChoice"] == {"tool": {"name": other.TOOL_NAME}}   # the same forced structure


def test_the_record_carries_the_run_s_provenance(evaluation, handler):
    from datetime import datetime, timezone
    results = [{"case": "a", "source": "written", "run": 1, "passed": True, "expect": {}, "note": {}, "failures": [],
                "usage": {"input_tokens": 1, "output_tokens": 1}, "latency_ms": 5},
               {"case": "a", "source": "written", "run": 2, "passed": False, "expect": {}, "note": None,
                "failures": ["rejected: x"], "usage": {"input_tokens": 1, "output_tokens": 1}, "latency_ms": 5},
               {"case": "b", "source": "honeypot", "run": 1, "passed": True, "expect": {}, "note": {}, "failures": [],
                "usage": {"input_tokens": 1, "output_tokens": 1}, "latency_ms": 5}]
    record = evaluation.record_of(handler, evaluation.INDEPENDENT_CASES, 2, datetime.now(timezone.utc), results,
                                  {"written": [1, 2], "honeypot": [1, 1]})
    assert record["model"] == handler.MODEL_ID and record["prompt_version"] == handler.PROMPT_VERSION
    assert record["case_file"] == "scripts/triage_eval_cases_independent.json"
    assert record["case_file_sha256"] == evaluation.digest(evaluation.INDEPENDENT_CASES) and len(record["case_file_sha256"]) == 64
    assert (record["cases"], record["runs_per_case"], record["passed"], record["total"]) == (2, 2, 2, 3)
    assert record["by_source"] == {"honeypot": {"passed": 1, "total": 1}, "written": {"passed": 1, "total": 2}}
    assert record["results"] == results and record["started"] <= record["finished"]
