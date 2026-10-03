"""
Tests for the threat-intelligence enricher.

The providers are not called: their responses are recorded shapes, and the
HTTP seam is replaced. What is pinned is everything around the call — which
indicators are asked about and which are refused, what the cache saves, how
long a verdict holds against how long a failure holds, the per-run budget,
the verdict thresholds, and the metrics line the dashboard reads.

boto3 is stubbed before import because the handler builds its tables and the
secrets client at import time.
"""
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

HANDLER_PATH = Path(__file__).resolve().parents[2] / "cdk" / "lambda" / "enricher" / "handler.py"
NOW = datetime(2026, 10, 3, 6, 0, tzinfo=timezone.utc)

ABUSEIPDB_RESPONSE = {"data": {
    "ipAddress": "45.33.32.156", "isPublic": True, "ipVersion": 4, "isWhitelisted": False,
    "abuseConfidenceScore": 100, "countryCode": "US", "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Linode, LLC", "domain": "linode.com", "hostnames": ["scanme.nmap.org"], "isTor": False,
    "totalReports": 412, "numDistinctUsers": 97, "lastReportedAt": "2026-10-02T21:14:09+00:00",
}}
OTX_RESPONSE = {"indicator": "45.33.32.156", "type": "IPv4", "reputation": 0,
                "pulse_info": {"count": 7, "pulses": [{"name": "Mass scanners", "description": "..."}]}}


@pytest.fixture
def enricher():
    spec = importlib.util.spec_from_file_location("enricher_handler", HANDLER_PATH)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"), mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    module._secrets.get_secret_value.return_value = {
        "SecretString": json.dumps({"abuseipdb_api_key": "abuse-key", "otx_api_key": "otx-key"})}
    module._ddb.batch_get_item.return_value = {"Responses": {module.INTEL_TABLE: []}}
    module._incidents.scan.return_value = {"Items": []}
    return module


def answers(enricher, **by_host):
    """Replace the HTTP seam with recorded responses, keyed by host; a value
    that is an exception is raised, as a failed call would."""
    calls = []

    def get_json(host, path, headers):
        calls.append((host, path, headers))
        answer = by_host[host]
        if isinstance(answer, Exception):
            raise answer
        return answer
    enricher._get_json = get_json
    return calls


def incident(**over):
    base = {"incident_id": "inc-1", "status": "open", "last_seen": "2026-10-03T05:00:00+00:00",
            "indicators": {"ips": ["45.33.32.156"], "domains": ["evil.example.net"]}}
    return {**base, **over}


# ------------------------------------------------------------------- providers
def test_the_providers_are_asked_with_their_keys_and_nothing_else(enricher):
    calls = answers(enricher, **{"api.abuseipdb.com": ABUSEIPDB_RESPONSE, "otx.alienvault.com": OTX_RESPONSE})
    row = enricher.lookup("ip", "45.33.32.156", now=NOW)

    assert [(host, path) for host, path, _ in calls] == [
        ("api.abuseipdb.com", "/api/v2/check?ipAddress=45.33.32.156&maxAgeInDays=90"),
        ("otx.alienvault.com", "/api/v1/indicators/IPv4/45.33.32.156/general"),
    ]
    assert calls[0][2] == {"Key": "abuse-key"} and calls[1][2] == {"X-OTX-API-KEY": "otx-key"}

    assert row["indicator"] == "ip:45.33.32.156" and row["verdict"] == "malicious"
    assert row["abuseipdb"] == {"confidence": 100, "reports": 412, "country": "US", "isp": "Linode, LLC",
                                "usage_type": "Data Center/Web Hosting/Transit", "tor": False,
                                "last_reported_at": "2026-10-02T21:14:09+00:00"}
    # A count, not the pulses' prose: community text stays out of the record.
    assert row["otx"] == {"pulses": 7}
    assert row["providers_asked"] == ["abuseipdb", "otx"] and row["providers_failed"] == []
    assert row["looked_up_at"] == "2026-10-03T06:00:00+00:00"
    assert row["expires_at"] == int(NOW.timestamp()) + 7 * 24 * 3600


def test_a_domain_goes_to_otx_only_with_its_path_quoted(enricher):
    calls = answers(enricher, **{"otx.alienvault.com": {"pulse_info": {"count": 0}}})
    row = enricher.lookup("domain", "evil.example.net", now=NOW)
    assert [(host, path) for host, path, _ in calls] == [
        ("otx.alienvault.com", "/api/v1/indicators/domain/evil.example.net/general")]
    assert row["verdict"] == "not-listed" and "abuseipdb" not in row


def test_a_failed_provider_is_recorded_and_the_row_expires_within_the_hour(enricher):
    answers(enricher, **{"api.abuseipdb.com": RuntimeError("api.abuseipdb.com answered 429"),
                         "otx.alienvault.com": OTX_RESPONSE})
    row = enricher.lookup("ip", "45.33.32.156", now=NOW)
    assert row["providers_failed"] == ["abuseipdb"] and "abuseipdb" not in row
    assert row["verdict"] == "malicious"  # seven pulses are enough on their own
    assert row["expires_at"] == int(NOW.timestamp()) + 3600


def test_an_unconfigured_provider_is_skipped_not_failed(enricher):
    enricher._secrets.get_secret_value.return_value = {"SecretString": json.dumps({"otx_api_key": "otx-key"})}
    calls = answers(enricher, **{"otx.alienvault.com": {"pulse_info": {"count": 0}}})
    row = enricher.lookup("ip", "45.33.32.156", now=NOW)
    assert [host for host, _, _ in calls] == ["otx.alienvault.com"]
    assert row["providers_asked"] == ["otx"] and row["providers_failed"] == []
    assert row["expires_at"] == int(NOW.timestamp()) + 7 * 24 * 3600


def test_the_keys_are_read_once_per_container(enricher):
    answers(enricher, **{"api.abuseipdb.com": ABUSEIPDB_RESPONSE, "otx.alienvault.com": OTX_RESPONSE})
    enricher.lookup("ip", "45.33.32.156", now=NOW)
    enricher.lookup("ip", "45.33.32.156", now=NOW)
    assert enricher._secrets.get_secret_value.call_count == 1


def test_keys_filled_in_after_deployment_take_effect_on_the_next_run(enricher):
    """The stack deploys the secret empty. A container that read it empty must
    not remember that for its lifetime, or the keys would take effect at some
    unknowable later cold start."""
    enricher._secrets.get_secret_value.return_value = {"SecretString": "{}"}
    assert enricher.keys() == {"abuseipdb": None, "otx": None}
    enricher._secrets.get_secret_value.return_value = {
        "SecretString": json.dumps({"abuseipdb_api_key": "abuse-key", "otx_api_key": ""})}
    assert enricher.keys() == {"abuseipdb": "abuse-key", "otx": None}
    enricher.keys()
    assert enricher._secrets.get_secret_value.call_count == 2


# --------------------------------------------------------------------- verdict
@pytest.mark.parametrize("abuse, otx, expected", [
    (None, None, "unknown"),
    ({"confidence": 0}, {"pulses": 0}, "not-listed"),
    ({"confidence": 0}, None, "not-listed"),
    ({"confidence": 25}, {"pulses": 0}, "suspicious"),
    ({"confidence": 0}, {"pulses": 1}, "suspicious"),
    ({"confidence": 75}, {"pulses": 0}, "malicious"),
    ({"confidence": 0}, {"pulses": 5}, "malicious"),
    ({"confidence": 100}, {"pulses": 40}, "malicious"),
])
def test_the_verdict_follows_the_thresholds(enricher, abuse, otx, expected):
    assert enricher.verdict(abuse, otx) == expected


# ------------------------------------------------------------------- validity
@pytest.mark.parametrize("kind, value, ok", [
    ("ip", "45.33.32.156", True),
    ("ip", "10.0.0.5", False), ("ip", "203.0.113.9", False), ("ip", "not-an-ip", False),
    ("domain", "evil.example.net", True), ("domain", "a-b.example", True),
    ("domain", "localhost", False), ("domain", "-bad.example", False), ("domain", "Evil.Example", False),
    ("domain", "evil.example/../../etc", False), ("domain", "evil.example?x=1", False),
    ("domain", "a" * 64 + ".example", False), ("domain", "", False),
    ("url", "https://evil.example", False),
])
def test_only_public_addresses_and_plain_domains_are_sent_anywhere(enricher, kind, value, ok):
    assert enricher.wellformed(kind, value) is ok


# ---------------------------------------------------------------------- the run
def test_open_incidents_indicators_are_gathered_newest_first_each_once(enricher):
    enricher._incidents.scan.return_value = {"Items": [
        incident(incident_id="old", last_seen="2026-10-01T00:00:00+00:00",
                 indicators={"ips": ["45.33.32.156", "198.51.100.9"], "domains": []}),
        incident(incident_id="closed", status="closed", indicators={"ips": ["8.8.8.8"], "domains": []}),
        incident(incident_id="new", last_seen="2026-10-03T00:00:00+00:00",
                 indicators={"ips": ["185.220.101.4", "45.33.32.156"], "domains": ["evil.example.net"]}),
    ]}
    assert enricher.open_indicators() == [
        ("ip", "185.220.101.4"), ("ip", "45.33.32.156"), ("domain", "evil.example.net"),
    ]  # the closed incident's address and the documentation address are left out


def test_cached_rows_are_used_and_expired_ones_are_not(enricher):
    enricher._ddb.batch_get_item.return_value = {"Responses": {enricher.INTEL_TABLE: [
        {"indicator": "ip:45.33.32.156", "expires_at": int(NOW.timestamp()) + 100},
        {"indicator": "domain:evil.example.net", "expires_at": int(NOW.timestamp()) - 1},
    ]}}
    rows = enricher.cached([("ip", "45.33.32.156"), ("domain", "evil.example.net")], now=NOW)
    assert set(rows) == {"ip:45.33.32.156"}


def test_a_run_looks_up_the_misses_within_its_budget_and_reports(enricher, capsys):
    enricher.MAX_LOOKUPS_PER_RUN = 2
    enricher._incidents.scan.return_value = {"Items": [incident(indicators={
        "ips": ["45.33.32.156", "185.220.101.4", "91.108.4.1"], "domains": ["evil.example.net"]})]}
    enricher._ddb.batch_get_item.return_value = {"Responses": {enricher.INTEL_TABLE: [
        {"indicator": "ip:45.33.32.156", "expires_at": 2 ** 40}]}}
    answers(enricher, **{"api.abuseipdb.com": ABUSEIPDB_RESPONSE, "otx.alienvault.com": OTX_RESPONSE})

    summary = enricher.handler({}, None)

    written = [c.kwargs["Item"]["indicator"] for c in enricher._intel.put_item.call_args_list]
    assert written == ["ip:185.220.101.4", "ip:91.108.4.1"]  # the cached one skipped, the domain next run
    assert summary == {"indicators": 4, "cached": 1, "looked_up": 2, "provider_failures": 0,
                       "awaiting": 1, "providers": ["abuseipdb", "otx"]}

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["Component"] == "enricher"
    assert line["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "CloudSentinel"
    assert {m["Name"] for m in line["_aws"]["CloudWatchMetrics"][0]["Metrics"]} == {
        "IntelLookups", "IntelCacheHits", "IntelProviderErrors", "IntelAwaitingLookup",
        "IntelProvidersConfigured", "IntelRunsCompleted"}
    assert (line["IntelLookups"], line["IntelCacheHits"], line["IntelAwaitingLookup"],
            line["IntelProvidersConfigured"], line["IntelRunsCompleted"]) == (2, 1, 1, 2, 1)


def test_with_no_provider_configured_nothing_is_looked_up_and_nothing_is_written(enricher, capsys):
    enricher._secrets.get_secret_value.return_value = {"SecretString": "{}"}
    enricher._incidents.scan.return_value = {"Items": [incident()]}
    calls = answers(enricher)

    summary = enricher.handler({}, None)

    assert calls == [] and enricher._intel.put_item.call_count == 0
    assert summary["providers"] == [] and summary["awaiting"] == 2
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["IntelProvidersConfigured"] == 0 and line["IntelRunsCompleted"] == 1


def test_an_unreadable_secret_counts_as_no_provider(enricher):
    enricher._secrets.get_secret_value.side_effect = RuntimeError("AccessDenied")
    assert enricher.keys() == {"abuseipdb": None, "otx": None}
