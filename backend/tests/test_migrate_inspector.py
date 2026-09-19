"""
Tests for the one-off Inspector findings migration.

It rewrites sort keys and deletes rows, so the properties that keep it from
losing or damaging data are pinned: only rows the old normalizer wrote are
touched, a newer corrected row is never overwritten, every write lands before
any delete, and a second run changes nothing.
"""
import importlib.util
from decimal import Decimal
from pathlib import Path
from unittest import mock

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "migrate_inspector_findings.py"
PK = "inspector#777788889999"


@pytest.fixture(scope="module")
def migrate():
    spec = importlib.util.spec_from_file_location("migrate_inspector", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def normalizer(migrate):
    return migrate.load_normalizer()


def _row(fid, created, severity, label):
    return {"pk": PK, "sk": f"{created}#{fid}", "finding_id": fid, "created_at": created,
            "severity": Decimal(severity), "severity_bucket": "INFO" if not severity else "HIGH",
            "raw_severity_label": label, "source": "inspector", "title": f"CVE for {fid}"}


OLD_HIGH = _row("arn/high", "Wed Sep 04 16:59:44.356 UTC 2024", 0, "HIGH")
OLD_INFO = _row("arn/info", "Thu Sep 05 08:00:00 UTC 2024", 0, "INFORMATIONAL")
FIXED_NORMALIZER = {**_row("arn/new", "2026-09-19T05:40:00.000Z", 74, "HIGH"),
                    "severity_bucket": "HIGH"}
OLD_ISO_CRITICAL = _row("arn/iso", "2024-09-04T17:00:37Z", 0, "CRITICAL")
UNREADABLE = _row("arn/bad", "sometime last week", 0, "HIGH")


def _by_fid(items):
    return {i["finding_id"]: i for i in items}


def test_old_row_is_rewritten_under_its_corrected_key(migrate, normalizer):
    puts, deletes, _ = migrate.plan([OLD_HIGH], normalizer)

    [fixed] = puts
    assert fixed["sk"] == "2024-09-04T16:59:44.356Z#arn/high"
    assert fixed["created_at"] == "2024-09-04T16:59:44.356Z"
    assert fixed["severity_bucket"] == "HIGH"
    assert fixed["title"] == "CVE for arn/high"           # the rest of the row is kept
    assert deletes == [{"pk": PK, "sk": OLD_HIGH["sk"]}]


def test_informational_finding_moves_but_stays_info(migrate, normalizer):
    puts, _, _ = migrate.plan([OLD_INFO], normalizer)
    assert puts[0]["severity_bucket"] == "INFO"
    assert puts[0]["sk"].startswith("2024-09-05T08:00:00.000Z#")


def test_rows_written_by_the_fixed_normalizer_are_not_touched(migrate, normalizer):
    """Its 74 comes from the precise inspectorScore; the word-based estimate
    for "HIGH" is 80 and must not replace it."""
    puts, deletes, report = migrate.plan([FIXED_NORMALIZER], normalizer)
    assert puts == [] and deletes == []
    assert report["counts"]["already correct"] == 1


def test_severity_is_corrected_in_place_when_the_key_is_already_right(migrate, normalizer):
    puts, deletes, _ = migrate.plan([OLD_ISO_CRITICAL], normalizer)
    assert deletes == []
    assert puts[0]["sk"] == OLD_ISO_CRITICAL["sk"]
    assert puts[0]["severity_bucket"] == "CRITICAL"


def test_a_newer_corrected_row_is_kept_and_only_the_old_row_removed(migrate, normalizer):
    newer = {**OLD_HIGH, "sk": "2024-09-04T16:59:44.356Z#arn/high",
             "created_at": "2024-09-04T16:59:44.356Z", "severity": Decimal(74),
             "severity_bucket": "HIGH", "title": "re-sent after the fix"}
    puts, deletes, _ = migrate.plan([OLD_HIGH, newer], normalizer)

    assert puts == []
    assert deletes == [{"pk": PK, "sk": OLD_HIGH["sk"]}]


def test_unreadable_timestamps_are_reported_and_left_alone(migrate, normalizer):
    puts, deletes, report = migrate.plan([UNREADABLE], normalizer)
    assert puts == [] and deletes == []
    assert report["counts"]["unreadable timestamp, left as is"] == 1


def test_a_second_run_changes_nothing(migrate, normalizer):
    table = {(r["pk"], r["sk"]): r for r in
             [OLD_HIGH, OLD_INFO, FIXED_NORMALIZER, OLD_ISO_CRITICAL, UNREADABLE]}
    puts, deletes, _ = migrate.plan(list(table.values()), normalizer)
    for item in puts:
        table[(item["pk"], item["sk"])] = item
    for key in deletes:
        del table[(key["pk"], key["sk"])]

    again_puts, again_deletes, _ = migrate.plan(list(table.values()), normalizer)
    assert again_puts == [] and again_deletes == []
    assert len(table) == 5                                  # nothing lost


def _fake_table(rows, log):
    table = mock.MagicMock()
    table.scan.return_value = {"Items": rows}

    def batch_writer(**_):
        batch = mock.MagicMock()
        batch.put_item.side_effect = lambda Item: log.append(("put", Item["sk"]))
        batch.delete_item.side_effect = lambda Key: log.append(("delete", Key["sk"]))
        ctx = mock.MagicMock()
        ctx.__enter__.return_value = batch
        return ctx

    table.batch_writer.side_effect = batch_writer
    return table


def _run(migrate, argv, rows):
    log = []
    session = mock.MagicMock()
    session.resource.return_value.Table.return_value = _fake_table(rows, log)
    with mock.patch.object(migrate.boto3, "Session", return_value=session) as sess:
        migrate.main(argv)
    return log, sess


def test_report_only_by_default(migrate):
    log, sess = _run(migrate, [], [OLD_HIGH, OLD_INFO])
    assert log == []
    sess.assert_called_once_with(profile_name="cs-audit", region_name="us-east-1")


def test_every_write_lands_before_any_delete(migrate):
    log, _ = _run(migrate, ["--yes"], [OLD_HIGH, OLD_INFO, OLD_ISO_CRITICAL])
    kinds = [kind for kind, _ in log]
    assert kinds.count("put") == 3 and kinds.count("delete") == 2
    assert kinds == sorted(kinds, key=lambda k: k != "put")  # all puts, then all deletes
