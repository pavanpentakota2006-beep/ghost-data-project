"""End-to-end test on a tiny synthetic dataset (fictional data only). Run: python3 code/tests/test_pipeline.py"""
import csv, json, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
import logging
import main as app
logging.disable(logging.CRITICAL)
from evaluate import evaluate, load


def w(p, header, rows):
    with open(p, "w", newline="", encoding="utf-8") as f:
        c = csv.writer(f); c.writerow(header); c.writerows(rows)


def build(d):
    ev = d / "evidence"; ev.mkdir(parents=True)
    w(d / "user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
      [["u1", "Asha Rao", "asha.new@example.com", "+91 90000 11111", "hash_new_1", "2026-01-01T00:00:00Z"],
       ["u2", "Ben Cole", "ben@example.com", "+1 555 0100", "hash_b", "2026-01-01T00:00:00Z"]])
    w(d / "user_audit_log.csv", ["audit_id", "user_id", "field", "old_value", "new_value", "changed_at"],
      [["audit_1", "u1", "email", "asha.old@example.com", "asha.new@example.com", "2026-01-01T00:00:00Z"]])
    w(d / "deletion_rules.csv", ["category", "condition", "action"],
      [["support attachment", "", "DELETE"], ["account", "tombstone", "REDACT"], ["invoice", "tax", "RETAIN"]])
    w(d / "system_activity.csv", ["activity_id", "timestamp", "system_id", "resource_id", "operation", "status", "details"],
      [["act_1", "2026-02-01T00:00:00Z", "search_sync", "job_7", "sync_job", "running", "indexes user u1 email asha.old@example.com"],
       ["act_2", "2026-02-02T00:00:00Z", "account_service", "account_u2", "delete", "ok", "deleted u2"]])
    (ev / "db.sql").write_text(
        "create table support_attachment(id text, user_id text, email text);"
        "insert into support_attachment values('att_1','u1','asha.old@example.com');"
        "create table account(id text, user_id text, email text, name text);"
        "insert into account values('account_u1','u1',NULL,NULL);"
        "insert into account values('account_u2x','u9','z@example.com','Z');")
    w(d / "evidence_files.csv", ["file_id", "path", "source_origin", "captured_at"],
      [["evidence_01", "evidence/db.sql", "primary_db", "2026-02-03T00:00:00Z"]])
    hdr = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
    rows = [["case_000", "asha.old@example.com", "2026-02-01", "COMPLETE", "2026-02-02", "2026-02-10T00:00:00Z", "Please delete all my data."],
            ["case_001", "ben@example.com", "2026-02-01", "COMPLETE", "2026-02-02", "2026-02-10T00:00:00Z", "Send me a copy of my data."],
            ["case_002", "ben@example.com", "2026-02-01", "COMPLETE", "2026-02-02", "2026-02-10T00:00:00Z", "Bitte löschen Sie mein Konto."]]
    w(d / "deletion_requests.csv", hdr, rows)


def run_test():
    with tempfile.TemporaryDirectory() as t:
        d = Path(t) / "dataset"; build(d)
        out = Path(t) / "output.csv"
        app.run(d, "deletion_requests.csv", out)
        res = load(out)
        assert list(res) == sorted(res)
        s0, st0 = res["case_000"]
        ops = [(s["operation"], s["resource_id"]) for s in st0]
        assert s0 == "INCOMPLETE", s0
        assert ("REPORT_REMAINING_RECORD", "att_1") in ops, ops   # historical email resolved
        assert ("REPORT_ACTIVE_DATA_FLOW", "job_7") in ops, ops
        assert [s["step_no"] for s in st0] == list(range(1, len(st0) + 1))
        assert all(s["evidence_id"] == "" for s in st0 if s["phase"] != "FINDING")
        assert res["case_001"] == ("NOT_APPLICABLE", [])
        assert res["case_002"][0] != "NOT_APPLICABLE"            # German deletion request detected
        m = evaluate(res, res)
        assert m["status_accuracy"] == 1.0 and m["sequence_accuracy"] == 1.0
        print("all pipeline tests passed")


import unittest


class PipelineTest(unittest.TestCase):
    def test_end_to_end(self):
        run_test()


if __name__ == "__main__":
    unittest.main()
