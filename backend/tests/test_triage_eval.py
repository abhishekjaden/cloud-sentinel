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
    return evaluation.load_cases()


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
    injected = [c for c in cases if c["name"].startswith("injection")]
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
