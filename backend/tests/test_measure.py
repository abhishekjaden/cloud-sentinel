"""
Tests for the measurement script's arithmetic.

The script reads the tables and Cost Explorer, which only exist where the
platform runs; what is pinned here is that the figures it prints mean what
the write-up will say they mean: nearest-rank percentiles of real gaps, a
record missing a stamp left out rather than counted as zero, clock skew
shown rather than hidden, and cost per thousand findings as plain division.
"""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "measure.py"


@pytest.fixture(scope="module")
def measure():
    spec = importlib.util.spec_from_file_location("measure", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding(event="2026-10-03T09:00:00Z", queued="2026-10-03T09:00:02.500+00:00",
            stored="2026-10-03T09:00:04.100+00:00", created="2026-10-03T08:55:00.000Z"):
    return {"event_time": event, "queued_at": queued, "stored_at": stored, "created_at": created}


def test_timestamps_in_every_source_s_spelling_are_read(measure):
    for value in ("2026-10-03T09:00:00Z", "2026-10-03T09:00:00.250Z", "2026-10-03T09:00:00+00:00",
                  "2026-10-03T09:00:00.250+00:00", "2026-10-03T09:00:00"):
        assert measure.moment(value).hour == 9, value
    assert measure.moment(None) is None and measure.moment("yesterday") is None


def test_a_gap_is_seconds_between_two_stamps_and_absent_when_one_is_missing(measure):
    assert measure.gap(finding(), "event_time", "stored_at") == pytest.approx(4.1)
    assert measure.gap(finding(), "queued_at", "stored_at") == pytest.approx(1.6)
    assert measure.gap(finding(queued=None), "queued_at", "stored_at") is None
    # Clock skew between sources shows as a negative gap, not as zero.
    assert measure.gap(finding(stored="2026-10-03T08:59:59Z"), "event_time", "stored_at") == -1.0


def test_percentiles_are_nearest_rank_values_that_occurred(measure):
    assert measure.percentiles([]) == {"n": 0}
    assert measure.percentiles([7.0]) == {"n": 1, "p50": 7.0, "p95": 7.0, "max": 7.0}
    twenty = list(range(1, 21))
    assert measure.percentiles(twenty) == {"n": 20, "p50": 10, "p95": 19, "max": 20}
    # None is a missing stamp, not a zero.
    assert measure.percentiles([3.0, None, 1.0, 2.0]) == {"n": 3, "p50": 2.0, "p95": 3.0, "max": 3.0}


def test_latency_reads_each_stage_from_the_records_that_carry_it(measure):
    findings = [finding(), finding(stored="2026-10-03T09:00:10.000+00:00"), {"created_at": "old", "title": "no stamps"}]
    incidents = [
        {"incident_id": "a", "first_seen": "2026-10-03T09:00:00+00:00", "created_at": "2026-10-03T09:12:00+00:00"},
        {"incident_id": "b", "first_seen": "2026-10-03T09:00:00+00:00", "created_at": "2026-10-03T09:03:00+00:00"},
        {"incident_id": "c", "first_seen": "2026-10-03T09:00:00+00:00"},  # not yet created? no stamp
    ]
    notes = [
        {"incident_id": "a", "status": "complete", "triaged_at": "2026-10-03T09:20:00+00:00"},
        {"incident_id": "b", "status": "invalid_output", "triaged_at": "2026-10-03T09:30:00+00:00"},
    ]
    figures = measure.latency(findings, incidents, notes)
    assert figures["ingested"] == {"n": 2, "p50": pytest.approx(4.1), "p95": 10.0, "max": 10.0}
    assert figures["stored"]["n"] == 2 and figures["detected"]["n"] == 2
    assert figures["correlated"] == {"n": 2, "p50": 180.0, "p95": 720.0, "max": 720.0}
    # Only a completed note is a triage latency; a rejected one is not a note.
    assert figures["triaged"] == {"n": 1, "p50": 480.0, "p95": 480.0, "max": 480.0}


def test_cost_per_thousand_is_plain_division(measure):
    assert measure.cost_per_thousand(18.40, 2300) == 8.0
    assert measure.cost_per_thousand(5.0, 0) is None


def test_the_report_states_counts_beside_every_figure(measure):
    figures = measure.latency([finding()], [], [])
    text = measure.report(figures, {"total": 12.5, "by_service": {"AWS Lambda": 4.0, "Amazon DynamoDB": 3.0}}, 500, None)
    assert "| ingested | 1 | 4.1s | 4.1s | 4.1s |" in text
    assert "| triaged | 0 | — | — | — |" in text
    assert "$12.50 for the period, 500 findings stored, $25.0 per 1,000 findings" in text
    assert "Cost: unavailable; 500 findings stored" in measure.report(figures, None, 500, None)


def test_durations_read_in_the_unit_that_fits(measure):
    assert measure.seconds(4.1) == "4.1s" and measure.seconds(90) == "1.5m" and measure.seconds(7200) == "2.0h"
    assert measure.seconds(None) == "—"
