"""
Tests for the calibration and comparison report.

The records only exist after a run against Bedrock; what is pinned here is the
arithmetic: a pass rate per confidence level computed over the answers that
carried it, a case counted unanimous only when every run gave one severity,
flags scored against the expectation, cost from the tokens at the price named,
and a disagreement listed only where two models part on pass or fail.
"""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "triage_calibration.py"


@pytest.fixture(scope="module")
def cal():
    spec = importlib.util.spec_from_file_location("triage_calibration", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def answer(case, run, severity, confidence, passed, source="written", test=False, inj=False, tokens=(1000, 120),
           latency=1500, reasons=("because",)):
    return {"case": case, "source": source, "run": run, "passed": passed,
            "expect": {"assessed_severity": ["high", "critical"], "likely_test_data": False, "injection_suspected": inj},
            "note": None if severity == "rejected" else {
                "summary": "s", "assessed_severity": severity, "confidence": confidence, "likely_test_data": test,
                "injection_suspected": inj, "reasons": list(reasons), "next_steps": []},
            "failures": [] if passed else ["assessed_severity out of band"],
            "usage": {"input_tokens": tokens[0], "output_tokens": tokens[1]}, "latency_ms": latency}


def record(model, results):
    return {"model": model, "prompt_version": "2026-10-20.2", "case_file": "scripts/triage_eval_cases_independent.json",
            "case_file_sha256": "ab" * 32, "started": "2026-10-25T10:00:00+00:00",
            "by_source": {"written": {"passed": sum(r["passed"] for r in results if r["source"] == "written"),
                                      "total": sum(1 for r in results if r["source"] == "written")}},
            "results": results}


HAIKU = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
SONNET = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"


def haiku_results():
    return [answer("a", 1, "high", "high", True), answer("a", 2, "high", "high", True), answer("a", 3, "high", "high", True),
            answer("b", 1, "critical", "medium", True), answer("b", 2, "high", "medium", True),
            answer("b", 3, "medium", "low", False),
            answer("c", 1, "rejected", None, False), answer("c", 2, "low", "low", False, test=True),
            answer("c", 3, "low", "high", False)]


def test_calibration_is_the_pass_rate_at_each_confidence_over_the_answers_that_carried_it(cal):
    s = cal.summarize(record(HAIKU, haiku_results()), cal.LIST_PRICES)
    assert s["passed"] == 5 and s["total"] == 9 and s["rejected"] == 1
    assert s["by_confidence"]["high"] == {"answers": 4, "passed": 3, "pass_rate": 0.75}
    assert s["by_confidence"]["medium"] == {"answers": 2, "passed": 2, "pass_rate": 1.0}
    assert s["by_confidence"]["low"] == {"answers": 2, "passed": 0, "pass_rate": 0.0}
    assert s["by_severity"]["critical"]["answers"] == 1 and s["by_severity"]["informational"]["pass_rate"] is None


def test_a_case_is_unanimous_only_when_every_run_gave_one_severity_and_a_rejection_counts_as_an_answer(cal):
    c = cal.consistency(haiku_results())
    assert (c["cases"], c["unanimous"], c["runs_per_case"]) == (3, 1, 3)
    assert c["split"] == {"b": {"critical": 1, "high": 1, "medium": 1}, "c": {"rejected": 1, "low": 2}}


def test_flags_are_scored_against_the_expectation_over_answers_that_exist(cal):
    f = cal.flags(haiku_results())
    assert f["likely_test_data"] == {"checked": 8, "correct": 7, "rate": 0.875}     # the rejection is not an answer
    assert f["injection_suspected"] == {"checked": 8, "correct": 8, "rate": 1.0}


def test_cost_comes_from_the_tokens_at_the_model_s_price_and_is_absent_for_an_unknown_model(cal):
    results = haiku_results()
    c = cal.cost(results, HAIKU, cal.LIST_PRICES)
    assert c["input_tokens_mean"] == 1000 and c["output_tokens_mean"] == 120
    assert c["usd_per_note"] == pytest.approx((1000 * 1.0 + 120 * 5.0) / 1e6)
    assert c["usd_per_1000_notes"] == pytest.approx(1.6, abs=0.001)
    assert c["latency_ms_median"] == 1500 and c["latency_ms_p95"] == 1500
    assert "usd_per_note" not in cal.cost(results, "some.other.model", cal.LIST_PRICES)
    priced = cal.cost(results, "some.other.model", {"other": (2.0, 10.0)})
    assert priced["usd_per_1000_notes"] == pytest.approx(3.2, abs=0.001)


def test_disagreements_list_only_the_cases_where_the_models_part_on_pass_or_fail(cal):
    sonnet = [answer("a", 1, "high", "high", True), answer("a", 2, "high", "high", True), answer("a", 3, "high", "high", True),
              answer("b", 1, "high", "high", True), answer("b", 2, "high", "high", True), answer("b", 3, "high", "high", True),
              answer("c", 1, "low", "high", False, reasons=("one", "two")), answer("c", 2, "low", "high", False),
              answer("c", 3, "low", "high", False)]
    rows = cal.disagreements(record(HAIKU, haiku_results()), record(SONNET, sonnet))
    assert [r["case"] for r in rows] == ["b"]                   # a: both pass; c: both fail every run
    b = rows[0]
    assert (b["a"]["passed"], b["a"]["runs"], b["b"]["passed"]) == (2, 3, 3)
    assert b["a"]["severities"] == ["critical", "high", "medium"] and b["a"]["reasons"] == ["because"]
    assert b["b"]["reasons"] == []


def test_the_report_renders_one_or_several_records(cal):
    lines = []
    s1 = cal.summarize(record(HAIKU, haiku_results()), cal.LIST_PRICES)
    cal.render([s1], [], log=lines.append)
    text = "\n".join(lines)
    assert "pass rate at confidence high" in text and "75% (n=4)" in text and "cases unanimous across runs" in text
    assert "1/3" in text and "b: critical x1, high x1, medium x1" in text
    s2 = cal.summarize(record(SONNET, haiku_results()), cal.LIST_PRICES)
    lines.clear()
    cal.render([s1, s2], [(("haiku", "sonnet"), [])], log=lines.append)
    assert any("pass and fail the same cases" in line for line in lines)
    assert any("USD per 1,000 notes" in line and "1.6" in line and "4.8" in line for line in lines)


def test_records_of_different_case_files_are_not_compared(cal, tmp_path, monkeypatch, capsys):
    a = record(HAIKU, haiku_results())
    b = dict(record(SONNET, haiku_results()), case_file="scripts/triage_eval_cases.json")
    (tmp_path / "a.json").write_text(json.dumps(a))
    (tmp_path / "b.json").write_text(json.dumps(b))
    monkeypatch.setattr("sys.argv", ["triage_calibration.py", str(tmp_path / "a.json"), str(tmp_path / "b.json")])
    with pytest.raises(SystemExit, match="different case files"):
        cal.main()
    (tmp_path / "x.json").write_text(json.dumps({"model": "m"}))
    monkeypatch.setattr("sys.argv", ["triage_calibration.py", str(tmp_path / "x.json")])
    with pytest.raises(SystemExit, match="no prompt_version"):
        cal.main()
    monkeypatch.setattr("sys.argv", ["triage_calibration.py", str(tmp_path / "a.json"), "--json", str(tmp_path / "out" / "s.json")])
    cal.main()
    written = json.loads((tmp_path / "out" / "s.json").read_text())
    assert written["summaries"][0]["passed"] == 5 and written["disagreements"] == []
    assert "wrote" in capsys.readouterr().out
