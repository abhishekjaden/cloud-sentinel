"""
The restore rehearsal: both tables restored to one instant, each copy checked
against the live table's stamps, the live tables only ever read, and nothing
but a copy ever deleted.

The restore itself happens where the tables are; what is pinned here is the
arithmetic the record will quote and the two things the script must never do.
"""
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "restore_rehearsal.py"
POINT = datetime(2026, 10, 21, 17, 30, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def drill():
    spec = importlib.util.spec_from_file_location("restore_rehearsal", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_instant_is_the_earlier_of_the_tables_latest_restorable_times(drill):
    client = mock.MagicMock()
    client.describe_continuous_backups.side_effect = lambda TableName: {"ContinuousBackupsDescription": {
        "PointInTimeRecoveryDescription": {
            "PointInTimeRecoveryStatus": "ENABLED",
            "LatestRestorableDateTime": POINT if "findings" in TableName else POINT.replace(second=40)}}}
    assert drill.restore_point(client, drill.TABLES) == POINT
    assert drill.restore_point(client, drill.TABLES, at=POINT.replace(hour=16)) == POINT.replace(hour=16)


def test_a_table_without_recovery_stops_the_rehearsal_before_it_starts(drill):
    client = mock.MagicMock()
    client.describe_continuous_backups.return_value = {"ContinuousBackupsDescription": {
        "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}}}
    with pytest.raises(SystemExit):
        drill.restore_point(client, drill.TABLES)
    client.restore_table_to_point_in_time.assert_not_called()


def test_a_copy_is_named_after_its_source_and_its_instant(drill):
    name = drill.copy_name("cloudsentinel-findings", POINT)
    assert name == "cloudsentinel-findings-restored-20261021T173000Z"
    assert drill.is_copy(name) and not drill.is_copy("cloudsentinel-findings")
    assert not drill.is_copy("cloudsentinel-approvals-restored-20261021T173000Z")


def test_stamps_in_every_spelling_are_tallied_against_the_instant(drill):
    counts = drill.tally([
        "2026-10-21T17:29:59.999Z",            # before, GuardDuty's spelling
        "2026-10-21T17:30:00+00:00",           # at the instant counts as before
        "2026-10-21T17:30:00.000001+00:00",    # after, by a microsecond
        "2026-10-21T17:31:00",                 # after, no zone: read as UTC
        None, "yesterday",                     # neither side
    ], POINT)
    assert counts == {"at_or_before": 2, "after": 2, "unstamped": 2}


def test_counts_are_summed_across_scan_pages_not_read_off_the_describe(drill):
    client = mock.MagicMock()
    client.scan.side_effect = [{"Count": 1000, "LastEvaluatedKey": {"pk": {"S": "x"}}}, {"Count": 37}]
    assert drill.count_items(client, "cloudsentinel-findings-restored-20261021T173000Z") == 1037
    assert client.scan.call_args_list[1].kwargs["ExclusiveStartKey"] == {"pk": {"S": "x"}}
    client.describe_table.assert_not_called()


def test_the_copy_may_exceed_the_stamps_by_the_items_rewritten_since_and_never_fall_short(drill):
    live = {"at_or_before": 1000, "after": 3, "unstamped": 2}
    assert drill.compare(1002, live)["verdict"] == "matches"
    assert drill.compare(1004, live)["verdict"].startswith("2 more than the stamps say, within the 3")
    assert drill.compare(1006, live)["verdict"].endswith("unexplained")
    assert drill.compare(999, live)["verdict"].startswith("short by 3")


def test_only_copies_are_ever_deleted(drill):
    client = mock.MagicMock()
    with pytest.raises(ValueError):
        drill.delete_copies(client, ["cloudsentinel-findings-restored-20261021T173000Z", "cloudsentinel-findings"])
    client.delete_table.assert_not_called()

    deleted = drill.delete_copies(client, ["cloudsentinel-incidents-restored-20261021T173000Z"], wait=False)
    assert deleted == ["cloudsentinel-incidents-restored-20261021T173000Z"]
    client.delete_table.assert_called_once_with(TableName="cloudsentinel-incidents-restored-20261021T173000Z")


def test_leftover_copies_are_found_by_name_and_nothing_else_is(drill):
    client = mock.MagicMock()
    client.list_tables.side_effect = [
        {"TableNames": ["cloudsentinel-findings", "cloudsentinel-findings-restored-20261021T173000Z"],
         "LastEvaluatedTableName": "cloudsentinel-findings-restored-20261021T173000Z"},
        {"TableNames": ["cloudsentinel-incidents-restored-20261021T173000Z", "cloudsentinel-triage"]},
    ]
    assert drill.find_copies(client) == ["cloudsentinel-findings-restored-20261021T173000Z",
                                         "cloudsentinel-incidents-restored-20261021T173000Z"]


def _client(copy_items, live_stamps):
    """A DynamoDB that restores instantly and holds the given items."""
    client = mock.MagicMock()
    client.describe_continuous_backups.return_value = {"ContinuousBackupsDescription": {
        "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED", "LatestRestorableDateTime": POINT}}}
    client.restore_table_to_point_in_time.side_effect = lambda **kw: {"TableDescription": {
        "TableName": kw["TargetTableName"], "RestoreSummary": {"RestoreDateTime": kw["RestoreDateTime"]}}}
    client.describe_table.side_effect = lambda TableName: {"Table": {
        "TableStatus": "ACTIVE", "RestoreSummary": {"RestoreInProgress": False},
        "GlobalSecondaryIndexes": [{"IndexName": "source-time-index", "IndexStatus": "ACTIVE"}]}}

    def scan(TableName, **kw):
        if kw.get("Select") == "COUNT":
            return {"Count": copy_items[TableName]}
        attr = kw["ExpressionAttributeNames"]["#t"]
        return {"Items": [({attr: {"S": s}} if s else {}) for s in live_stamps[TableName]]}
    client.scan.side_effect = scan
    return client


def test_the_rehearsal_restores_both_tables_to_one_instant_reads_the_live_ones_and_deletes_only_the_copies(drill):
    client = _client(
        copy_items={"cloudsentinel-findings-restored-20261021T173000Z": 3,
                    "cloudsentinel-incidents-restored-20261021T173000Z": 1},
        live_stamps={"cloudsentinel-findings": ["2026-10-21T17:00:00.000+00:00", "2026-10-21T17:29:00.000+00:00",
                                                None, "2026-10-21T17:31:00.000+00:00"],
                     "cloudsentinel-incidents": ["2026-10-21T17:15:00.000000+00:00"]})

    result = drill.rehearse(client, sleep=lambda s: None, clock=lambda: 0.0)

    restores = {c.kwargs["SourceTableName"]: c.kwargs for c in client.restore_table_to_point_in_time.call_args_list}
    assert set(restores) == set(drill.TABLES)
    assert all(kw["RestoreDateTime"] == POINT for kw in restores.values())
    assert result["restore_point"] == "2026-10-21T17:30:00+00:00"

    findings = result["tables"]["cloudsentinel-findings"]
    assert findings["copy_items"] == 3
    assert findings["live"] == {"stamp": "stored_at", "at_or_before": 2, "after": 1, "unstamped": 1, "total_now": 4}
    assert findings["comparison"]["verdict"] == "matches"
    assert findings["indexes"] == ["source-time-index"]
    assert result["tables"]["cloudsentinel-incidents"]["comparison"]["verdict"] == "matches"

    # The live tables were read and nothing else; only the copies were deleted.
    touched = {c.kwargs["TableName"] for c in client.scan.call_args_list}
    assert touched == set(drill.TABLES) | set(copy_items_of(result))
    deleted = [c.kwargs["TableName"] for c in client.delete_table.call_args_list]
    assert sorted(deleted) == sorted(copy_items_of(result)) == sorted(result["copies_deleted"])
    assert not any(name in drill.TABLES for name in deleted)
    for forbidden in ("put_item", "update_item", "delete_item", "batch_write_item", "update_table"):
        getattr(client, forbidden).assert_not_called()


def copy_items_of(result):
    return [r["copy"] for r in result["tables"].values()]


def test_keep_leaves_the_copies_and_the_report_says_how_to_remove_them(drill):
    client = _client(copy_items={"cloudsentinel-findings-restored-20261021T173000Z": 0,
                                 "cloudsentinel-incidents-restored-20261021T173000Z": 0},
                     live_stamps={"cloudsentinel-findings": [], "cloudsentinel-incidents": []})
    result = drill.rehearse(client, keep=True, sleep=lambda s: None, clock=lambda: 0.0)
    client.delete_table.assert_not_called()
    text = drill.report(result)
    assert "copies kept" in text and "--delete-copies" in text
    assert "copy holds 0 items" in text and "matches" in text


def test_the_report_quotes_the_time_to_active_and_both_counts(drill):
    result = {"rehearsed_at": "2026-10-21T17:40:00+00:00", "restore_point": "2026-10-21T17:30:00+00:00",
              "copies_deleted": ["cloudsentinel-findings-restored-20261021T173000Z"],
              "tables": {"cloudsentinel-findings": {
                  "copy": "cloudsentinel-findings-restored-20261021T173000Z",
                  "requested_at": "2026-10-21T17:40:01+00:00", "active_at": "2026-10-21T17:52:13+00:00",
                  "seconds_to_active": 732.4, "indexes": ["severity-index", "source-time-index"],
                  "copy_items": 1037,
                  "live": {"stamp": "stored_at", "at_or_before": 1035, "after": 4, "unstamped": 2, "total_now": 1041},
                  "comparison": {"expected": 1037, "excess": 0, "verdict": "matches"}}}}
    text = drill.report(result)
    assert "732.4 s" in text and "severity-index, source-time-index" in text
    assert "copy holds 1037 items" in text
    assert "1035 stamped at or before the instant, 4 after it, 2 without a stored_at" in text
    assert "copies deleted: cloudsentinel-findings-restored-20261021T173000Z" in text
