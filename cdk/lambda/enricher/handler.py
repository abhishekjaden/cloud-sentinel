"""
Threat-intelligence enrichment.

An incident names the other end of what GuardDuty saw: the address that
brute-forced an instance, the domain it then queried. Two public feeds say
whether that address or domain has been reported before — AbuseIPDB, which
scores addresses by abuse reports, and AlienVault OTX, whose pulses are
community-curated indicator sets covering both addresses and domains. This
function asks them about the indicators on open incidents and keeps the
answers in a cache table, where the dashboard, the report and the triage
model read them.

Three things bound it. The cache: an indicator is looked up once a week, not
once per run, because the feeds' free tiers allow about a thousand checks a
day and the same attacker appears across many incidents. The budget: at most
MAX_LOOKUPS_PER_RUN indicators a run, so a flood of new addresses spreads its
lookups over hours rather than exhausting the day's quota in one. And the
scope: only public addresses and well-formed domains are sent, and nothing
else about the incident goes with them. What leaves the account is the
indicator itself — which the threat model records, because it tells a third
party what this organisation is seeing.

The verdict is indicative. "Malicious" means the feeds have many reports of
the indicator, "not listed" means they have none, and neither is proof: a
scanner's address can be reported a thousand times and a targeted attacker's
never. The note the triage model writes is told the same.

Enrichment is best-effort: a provider that is down, throttled or unconfigured
leaves the indicator marked unknown and tried again sooner, and an incident
without intelligence is still correlated, triaged and reported.
"""
import http.client
import ipaddress
import json
import logging
import os
import ssl
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

INCIDENTS_TABLE = os.environ.get("INCIDENTS_TABLE", "cloudsentinel-incidents")
INTEL_TABLE = os.environ.get("INTEL_TABLE", "cloudsentinel-intel")
SECRET_ID = os.environ.get("INTEL_SECRET_ID", "cloudsentinel/threat-intel")
MAX_LOOKUPS_PER_RUN = int(os.environ.get("MAX_LOOKUPS_PER_RUN", "10"))
CACHE_DAYS = int(os.environ.get("INTEL_CACHE_DAYS", "7"))
RETRY_HOURS = int(os.environ.get("INTEL_RETRY_HOURS", "1"))
TIMEOUT_SECONDS = 6

# The two hosts this function talks to, fixed here: the indicator becomes
# part of a path, never a host or a scheme.
ABUSEIPDB_HOST = "api.abuseipdb.com"
OTX_HOST = "otx.alienvault.com"
USER_AGENT = "CloudSentinel-enricher/1.0"

# Thresholds behind the verdict. AbuseIPDB's confidence is its own 0–100
# score; an OTX pulse is one curated set naming the indicator.
MALICIOUS_CONFIDENCE = 75
SUSPICIOUS_CONFIDENCE = 25
MALICIOUS_PULSES = 5

_ddb = boto3.resource("dynamodb")
_incidents = _ddb.Table(INCIDENTS_TABLE)
_intel = _ddb.Table(INTEL_TABLE)
_secrets = boto3.client("secretsmanager")

# Pinned on both sides: the observability stack's dashboard reads these names.
_METRIC_NAMESPACE = "CloudSentinel"
_COMPONENT = "enricher"

_keys = None


# ------------------------------------------------------------------ providers
def keys():
    """The providers' API keys. An empty or missing key means that provider is
    not configured and is skipped, not failed. Keys are held for the life of
    the container once any is present; while none is, the secret is read
    again every run, so the keys take effect on the run after the operator
    fills them in rather than whenever Lambda happens to recycle the
    container."""
    global _keys
    if _keys is None:
        try:
            raw = json.loads(_secrets.get_secret_value(SecretId=SECRET_ID).get("SecretString") or "{}")
        except Exception:  # noqa: BLE001 — no keys is a configuration state, not a crash
            logger.exception("threat-intel keys could not be read")
            raw = {}
        found = {"abuseipdb": (raw.get("abuseipdb_api_key") or "").strip() or None,
                 "otx": (raw.get("otx_api_key") or "").strip() or None}
        if not any(found.values()):
            return found
        _keys = found
    return _keys


def _get_json(host, path, headers):
    """One HTTPS GET to a fixed host, parsed as JSON. Raises on a non-2xx
    status or a network error; the caller decides what a failed provider
    means."""
    # Certificate and hostname verification are explicit here rather than
    # relied on as the default, which is the concern the audit rule names.
    connection = http.client.HTTPSConnection(  # nosemgrep: python.lang.security.audit.httpsconnection-detected
        host, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context())
    try:
        connection.request("GET", path, headers={**headers, "Accept": "application/json",
                                                 "User-Agent": USER_AGENT})
        response = connection.getresponse()
        body = response.read()
        if response.status // 100 != 2:
            raise RuntimeError(f"{host} answered {response.status}")
        return json.loads(body.decode("utf-8"))
    finally:
        connection.close()


def abuseipdb(ip, key):
    """AbuseIPDB's view of an address: its abuse confidence and report count,
    plus where it is and who announces it."""
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    data = _get_json(ABUSEIPDB_HOST, f"/api/v2/check?{query}", {"Key": key}).get("data") or {}
    return {
        "confidence": int(data.get("abuseConfidenceScore") or 0),
        "reports": int(data.get("totalReports") or 0),
        "country": str(data.get("countryCode") or "")[:8],
        "isp": str(data.get("isp") or "")[:120],
        "usage_type": str(data.get("usageType") or "")[:60],
        "tor": bool(data.get("isTor")),
        "last_reported_at": str(data.get("lastReportedAt") or "")[:40],
    }


def otx(kind, value, key):
    """How many OTX pulses name the indicator. Pulse names and descriptions
    are community text and are not kept: a count is evidence, prose is not."""
    section = "IPv4" if kind == "ip" else "domain"
    data = _get_json(OTX_HOST, f"/api/v1/indicators/{section}/{urllib.parse.quote(value, safe='')}/general",
                     {"X-OTX-API-KEY": key})
    return {"pulses": int(((data.get("pulse_info") or {}).get("count")) or 0)}


# -------------------------------------------------------------------- verdict
def verdict(abuse, pulses_seen):
    """One word an analyst can act on, from whichever providers answered."""
    if abuse is None and pulses_seen is None:
        return "unknown"
    confidence = (abuse or {}).get("confidence", 0)
    pulses = (pulses_seen or {}).get("pulses", 0)
    if confidence >= MALICIOUS_CONFIDENCE or pulses >= MALICIOUS_PULSES:
        return "malicious"
    if confidence >= SUSPICIOUS_CONFIDENCE or pulses >= 1:
        return "suspicious"
    return "not-listed"


def _plain_domain(value):
    """A hostname of two or more labels, each letters, digits and inner
    hyphens: nothing that could be read as a path, a query or a scheme."""
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not 1 <= len(label) <= 63 or label[0] == "-" or label[-1] == "-":
            return False
        if any(not (c.isascii() and (c.isalnum() or c == "-")) or c.isupper() for c in label):
            return False
    return True


def wellformed(kind, value):
    """Only a public address or a plain domain name is sent anywhere: the
    value becomes part of a URL to a third party, and the normalizer's
    filtering is repeated here rather than trusted."""
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        # is_global is a property of the address, not a method.
        return address.is_global  # nosemgrep: python.lang.maintainability.is-function-without-parentheses
    return kind == "domain" and _plain_domain(value)


def lookup(kind, value, now=None):
    """Ask every configured provider about one indicator and shape the cache
    row. A provider that fails is recorded as failed and the row expires
    early, so the indicator is asked about again within the hour rather than
    carrying an unknown verdict for a week."""
    now = now or datetime.now(timezone.utc)
    available = keys()
    row = {"indicator": f"{kind}:{value}", "kind": kind, "value": value, "providers_failed": []}
    asked = []
    if kind == "ip" and available["abuseipdb"]:
        asked.append("abuseipdb")
        try:
            row["abuseipdb"] = abuseipdb(value, available["abuseipdb"])
        except Exception as exc:  # noqa: BLE001 — a provider failure is a result, not a crash
            logger.warning("abuseipdb failed for %s: %s", value, exc)
            row["providers_failed"].append("abuseipdb")
    if available["otx"]:
        asked.append("otx")
        try:
            row["otx"] = otx(kind, value, available["otx"])
        except Exception as exc:  # noqa: BLE001
            logger.warning("otx failed for %s: %s", value, exc)
            row["providers_failed"].append("otx")
    row["providers_asked"] = asked
    row["verdict"] = verdict(row.get("abuseipdb"), row.get("otx"))
    row["looked_up_at"] = now.isoformat(timespec="seconds")
    ttl = timedelta(hours=RETRY_HOURS) if row["providers_failed"] else timedelta(days=CACHE_DAYS)
    row["expires_at"] = int((now + ttl).timestamp())
    return row


# ---------------------------------------------------------------- the run
def _scan_all(table, **kwargs):
    items = []
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def open_indicators():
    """Every indicator on an open incident, each once, newest incident first:
    when the budget runs out, what was seen last is what gets looked up."""
    incidents = [i for i in _scan_all(_incidents) if i.get("status", "open") == "open"]
    incidents.sort(key=lambda i: str(i.get("last_seen", "")), reverse=True)
    seen, ordered = set(), []
    for incident in incidents:
        found = incident.get("indicators") or {}
        for kind, plural in (("ip", "ips"), ("domain", "domains")):
            for value in found.get(plural) or []:
                value = str(value)
                if (kind, value) not in seen and wellformed(kind, value):
                    seen.add((kind, value))
                    ordered.append((kind, value))
    return ordered


def cached(indicators, now=None):
    """The cache rows that still hold for the given indicators. A row past
    its expiry is treated as absent: TTL deletion lags by up to two days."""
    now_ts = int((now or datetime.now(timezone.utc)).timestamp())
    rows = {}
    keys_wanted = [{"indicator": f"{kind}:{value}"} for kind, value in indicators]
    for start in range(0, len(keys_wanted), 100):
        request = {INTEL_TABLE: {"Keys": keys_wanted[start:start + 100]}}
        for _ in range(3):
            resp = _ddb.batch_get_item(RequestItems=request)
            for row in resp.get("Responses", {}).get(INTEL_TABLE, []):
                if int(row.get("expires_at") or 0) > now_ts:
                    rows[row["indicator"]] = row
            request = resp.get("UnprocessedKeys") or {}
            if not request.get(INTEL_TABLE, {}).get("Keys"):
                break
    return rows


def _metrics_line(**counts):
    """One record in CloudWatch Embedded Metric Format; the tests pin the
    shape because CloudWatch drops a malformed line without a word."""
    return json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": _METRIC_NAMESPACE,
                "Dimensions": [["Component"]],
                "Metrics": [{"Name": name, "Unit": "Count"} for name in counts],
            }],
        },
        "Component": _COMPONENT,
        **counts,
    })


def handler(event, context):
    wanted = open_indicators()
    have = cached(wanted)
    misses = [(kind, value) for kind, value in wanted if f"{kind}:{value}" not in have]
    configured = [name for name, key in keys().items() if key]

    looked_up, failures = 0, 0
    if configured:
        for kind, value in misses[:MAX_LOOKUPS_PER_RUN]:
            row = lookup(kind, value)
            _intel.put_item(Item=row)
            looked_up += 1
            failures += len(row["providers_failed"])
    else:
        logger.warning("no threat-intel provider is configured; %d indicators await lookup", len(misses))

    summary = {"indicators": len(wanted), "cached": len(have), "looked_up": looked_up,
               "provider_failures": failures, "awaiting": max(len(misses) - looked_up, 0),
               "providers": configured}
    logger.info("ENRICHMENT_COMPLETE %s", json.dumps(summary))
    # Printed rather than logged: CloudWatch reads EMF only from a line that is
    # JSON from its first character, and the log handler adds a prefix.
    print(_metrics_line(IntelLookups=looked_up, IntelCacheHits=len(have),
                        IntelProviderErrors=failures, IntelAwaitingLookup=summary["awaiting"],
                        IntelProvidersConfigured=len(configured), IntelRunsCompleted=1))
    return summary
