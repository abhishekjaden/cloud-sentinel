"""
Tests for incident correlation.

The correlator runs every fifteen minutes over a lookback window, so it sees
the same findings on every run. Two properties are pinned here because both
failed silently in production before they were tested:

  - identity: re-running over the same findings must update existing incidents,
    not add copies of them;
  - ownership: a run must never overwrite state the analyst set, such as
    closing an incident.

The module is loaded by file path under its own name. The normalizer's handler
is also called `handler`, so importing this one by module name would return
whichever was cached first.
"""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

HANDLER_PATH = (Path(__file__).resolve().parents[2]
                / "cdk" / "lambda" / "correlator" / "handler.py")


@pytest.fixture
def correlator():
    spec = importlib.util.spec_from_file_location("correlator_handler", HANDLER_PATH)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"):
        spec.loader.exec_module(module)
    return module


def _finding(minutes_ago, finding_type, instance="i-0abc", finding_id=None):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return {
        "pk": "guardduty#111122223333",
        "account_id": "111122223333",
        "source": "guardduty",
        "finding_id": finding_id or f"{finding_type}-{minutes_ago}",
        "finding_type": finding_type,
        "severity": 80,
        "created_at": ts.isoformat(),
        "resource": json.dumps({"instanceDetails": {"instanceId": instance}}),
    }


def _serve(correlator, items):
    """Return `items` for the GuardDuty scan and nothing for Inspector."""
    def scan(**kwargs):
        prefix = kwargs.get("ExpressionAttributeValues", {}).get(":p", "")
        return {"Items": list(items) if prefix == "guardduty#" else []}
    correlator._findings.scan.side_effect = scan


def _written_keys(correlator):
    """Incident IDs written by a run, whichever write call was used.

    Reading both calls keeps the identity tests about identity: a version that
    went back to put_item with stable IDs would still pass them, and one that
    kept update_item with random IDs would still fail them.
    """
    table = correlator._incidents
    return ([c.kwargs["Key"]["incident_id"] for c in table.update_item.call_args_list]
            + [c.kwargs["Item"]["incident_id"] for c in table.put_item.call_args_list])


def _clauses(update_expression):
    """Split a SET expression into its assignments.

    Splitting on every comma would cut `if_not_exists(#a, :a)` in half, so only
    commas outside parentheses separate clauses.
    """
    body = update_expression.removeprefix("SET ")
    clauses, depth, current = [], 0, ""
    for ch in body:
        depth += ch == "("
        depth -= ch == ")"
        if ch == "," and depth == 0:
            clauses.append(current.strip())
            current = ""
        else:
            current += ch
    clauses.append(current.strip())
    return clauses


# ------------------------------------------------------------------- identity
def test_incident_id_is_stable_for_the_same_attack(correlator):
    start = datetime(2026, 7, 19, 13, 47, 58, tzinfo=timezone.utc)
    a = correlator._incident_id("111122223333", "i-0abc", start)
    b = correlator._incident_id("111122223333", "i-0abc", start)
    assert a == b


@pytest.mark.parametrize("account,resource,offset", [
    ("999988887777", "i-0abc", 0),   # a different account
    ("111122223333", "i-0def", 0),   # a different resource
    ("111122223333", "i-0abc", 1),   # a different attack on the same resource
])
def test_incident_id_distinguishes_different_attacks(correlator, account, resource, offset):
    start = datetime(2026, 7, 19, 13, 47, 58, tzinfo=timezone.utc)
    base = correlator._incident_id("111122223333", "i-0abc", start)
    other = correlator._incident_id(account, resource, start + timedelta(seconds=offset))
    assert base != other


def test_rerun_over_same_findings_updates_rather_than_duplicates(correlator):
    """The regression: a random ID made each scheduled run add every incident again."""
    _serve(correlator, [_finding(20, "Recon:EC2/PortProbeUnprotectedPort"),
                        _finding(15, "UnauthorizedAccess:EC2/SSHBruteForce")])

    correlator.handler({}, None)
    first_run = _written_keys(correlator)
    correlator._incidents.reset_mock()
    correlator.handler({}, None)
    second_run = _written_keys(correlator)

    assert len(first_run) == 1
    assert first_run == second_run


def test_write_is_an_upsert_not_a_replace(correlator):
    """put_item replaces the whole record, which would discard analyst state."""
    _serve(correlator, [_finding(10, "Recon:EC2/PortProbeUnprotectedPort")])
    correlator.handler({}, None)

    correlator._incidents.put_item.assert_not_called()
    correlator._incidents.update_item.assert_called_once()


def test_growing_cluster_keeps_its_identity(correlator):
    """A new finding extends the end of an attack, not its start, so the incident
    it joins must keep the same ID rather than being recorded as a new one."""
    early = [_finding(20, "Recon:EC2/PortProbeUnprotectedPort")]
    _serve(correlator, early)
    correlator.handler({}, None)
    before = _written_keys(correlator)

    correlator._incidents.reset_mock()
    _serve(correlator, early + [_finding(5, "Backdoor:EC2/C&CActivity.B!DNS")])
    correlator.handler({}, None)
    after = _written_keys(correlator)

    assert len(before) == 1
    assert before == after


# ------------------------------------------------------------------ ownership
def test_status_is_set_only_when_the_incident_is_created(correlator):
    _serve(correlator, [_finding(10, "Recon:EC2/PortProbeUnprotectedPort")])
    correlator.handler({}, None)

    call = correlator._incidents.update_item.call_args
    names = call.kwargs["ExpressionAttributeNames"]
    expr = call.kwargs["UpdateExpression"]
    status_ref = next(ref for ref, name in names.items() if name == "status")

    status_clauses = [c for c in _clauses(expr) if c.startswith(status_ref + " ")]
    # exactly one assignment to status, and it is guarded
    assert len(status_clauses) == 1
    assert status_clauses[0].startswith(f"{status_ref} = if_not_exists({status_ref},")


def test_every_attribute_name_is_a_placeholder(correlator):
    """status and resource are DynamoDB reserved words; a bare name fails the write."""
    _serve(correlator, [_finding(10, "Recon:EC2/PortProbeUnprotectedPort")])
    correlator.handler({}, None)

    expr = correlator._incidents.update_item.call_args.kwargs["UpdateExpression"]
    clauses = _clauses(expr)
    assert clauses, "expected at least one assignment"
    for clause in clauses:
        assert clause.startswith("#"), clause


# ---------------------------------------------------------------------- scope
def test_only_guardduty_findings_are_correlated(correlator):
    """Security Hub posture checks and Inspector CVEs are standing weaknesses,
    not attack events. Grouping an image's CVEs by resource would present one
    vulnerability scan as a multi-finding "attack"."""
    requested = []

    def scan(**kwargs):
        requested.append(kwargs.get("ExpressionAttributeValues", {}).get(":p"))
        return {"Items": []}

    correlator._findings.scan.side_effect = scan
    correlator.handler({}, None)

    assert requested == ["guardduty#"]


# ----------------------------------------------------------------- clustering
def test_attacks_separated_by_more_than_the_window_are_separate_incidents(correlator):
    _serve(correlator, [_finding(300, "Recon:EC2/PortProbeUnprotectedPort"),
                        _finding(10, "CryptoCurrency:EC2/BitcoinTool.B!DNS")])
    result = correlator.handler({}, None)

    assert result["incidents"] == 2
    assert len(set(_written_keys(correlator))) == 2


def test_stages_are_ordered_along_the_kill_chain_not_by_arrival(correlator):
    _serve(correlator, [_finding(20, "CryptoCurrency:EC2/BitcoinTool.B!DNS"),
                        _finding(15, "Recon:EC2/PortProbeUnprotectedPort"),
                        _finding(10, "Backdoor:EC2/C&CActivity.B!DNS")])
    correlator.handler({}, None)

    call = correlator._incidents.update_item.call_args
    names = call.kwargs["ExpressionAttributeNames"]
    values = call.kwargs["ExpressionAttributeValues"]
    ref = next(r for r, n in names.items() if n == "attack_stages")
    stages = values[":" + ref[1:]]

    assert stages == ["reconnaissance", "command-and-control", "impact"]


def test_the_cloudtrail_derived_purposes_have_a_stage(correlator):
    """GuardDuty's newer detections name their purpose after the ATT&CK tactic
    itself (InitialAccess, DefenseImpairment, LateralMovement); until these
    were mapped, a disabled database authentication read as "unknown"."""
    assert correlator._stage("DefenseImpairment:RDS/ModifyAuthenticationProcess") == "defense-evasion"
    assert correlator._stage("InitialAccess:RDS/ExploitPublicFacingApplication") == "initial-access"
    assert correlator._stage("LateralMovement:EC2/RemoteServices") == "lateral-movement"
    assert correlator._stage("ResourceDevelopment:SES/CompromiseAccounts") == "resource-development"
    # A sequence finding summarises several stages; it gets none of its own.
    assert correlator._stage("AttackSequence:IAM/CompromisedCredentials") == "unknown"
    # Every stage a purpose maps to has a place in the order, and the two new
    # ones sit where the chain puts them: tooling before access, movement
    # before the callback.
    assert set(correlator.STAGE_BY_PURPOSE.values()) <= set(correlator.STAGE_ORDER)
    order = correlator.STAGE_ORDER
    assert order.index("resource-development") < order.index("initial-access")
    assert order.index("defense-evasion") < order.index("lateral-movement") < order.index("command-and-control")


# ------------------------------------------------------------------- liveness
# The incidents-current alarm treats silence as failure: a run publishes one
# count as its last act, and 45 minutes without one raises the alarm.
def _metric_lines(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.startswith("{") and '"_aws"' in line]


def test_a_completed_run_publishes_its_heartbeat(correlator, capsys):
    _serve(correlator, [_finding(10, "Recon:EC2/PortProbeUnprotectedPort")])
    correlator.handler({}, None)

    (line,) = _metric_lines(capsys)
    (spec,) = line["_aws"]["CloudWatchMetrics"]
    assert spec["Namespace"] == "CloudSentinel"
    assert spec["Dimensions"] == [["Component"]]
    assert spec["Metrics"] == [{"Name": "CorrelationRunsCompleted", "Unit": "Count"}]
    assert line["Component"] == "correlator"
    assert line["CorrelationRunsCompleted"] == 1


def test_a_run_with_nothing_to_correlate_still_counts_as_completed(correlator, capsys):
    """No findings is a normal quiet period, not a stalled correlator."""
    _serve(correlator, [])
    correlator.handler({}, None)

    (line,) = _metric_lines(capsys)
    assert line["CorrelationRunsCompleted"] == 1


def test_a_run_that_fails_publishes_nothing(correlator, capsys):
    """A heartbeat from a run that failed part-way would hide the failure."""
    _serve(correlator, [_finding(10, "Recon:EC2/PortProbeUnprotectedPort")])
    correlator._incidents.update_item.side_effect = RuntimeError("throttled")

    with pytest.raises(RuntimeError):
        correlator.handler({}, None)
    assert _metric_lines(capsys) == []


def test_an_incident_carries_its_findings_indicators_once_each(correlator):
    """Every public address or domain the findings named, in the order seen,
    each once: the enricher looks them up per incident, not per finding."""
    probe = _finding(30, "Recon:EC2/PortProbeUnprotectedPort")
    probe["indicators"] = {"ips": ["45.33.32.156", "185.220.101.4"]}
    brute = _finding(20, "UnauthorizedAccess:EC2/SSHBruteForce")
    brute["indicators"] = {"ips": ["185.220.101.4"]}
    c2 = _finding(10, "Backdoor:EC2/C&CActivity.B!DNS")
    c2["indicators"] = {"domains": ["evil.example.net"]}
    plain = _finding(5, "Trojan:EC2/DropPoint")  # no indicators at all

    entries = sorted(((correlator._parse_ts(f["created_at"]), f) for f in (probe, brute, c2, plain)),
                     key=lambda e: e[0])
    incident = correlator._build_incident("111122223333", "i-0abc", entries)
    assert incident["indicators"] == {"ips": ["45.33.32.156", "185.220.101.4"],
                                      "domains": ["evil.example.net"]}


def test_an_incident_without_indicators_still_has_the_shape(correlator):
    entries = [(correlator._parse_ts(f["created_at"]), f) for f in [_finding(5, "Trojan:EC2/DropPoint")]]
    assert correlator._build_incident("111122223333", "i-0abc", entries)["indicators"] == {"ips": [], "domains": []}


def test_indicators_are_capped_per_incident(correlator):
    findings = []
    for n in range(30):
        f = _finding(30 - n, "Recon:EC2/PortProbeUnprotectedPort", finding_id=f"p{n}")
        f["indicators"] = {"ips": [f"45.33.32.{n + 1}"]}
        findings.append(f)
    entries = [(correlator._parse_ts(f["created_at"]), f) for f in findings]
    incident = correlator._build_incident("111122223333", "i-0abc", entries)
    assert len(incident["indicators"]["ips"]) == correlator.MAX_INDICATORS
    assert incident["indicators"]["ips"][0] == "45.33.32.1"
