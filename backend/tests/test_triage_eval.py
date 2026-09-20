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
