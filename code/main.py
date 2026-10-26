#!/usr/bin/env python3
"""Ghost Data audit agent. Usage: python3 code/main.py [--dataset DIR] [--output FILE] [--sample]"""
import argparse, csv, logging, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from audit.util import read_csv
from audit.intent import requests_deletion
from audit.identity import IdentityResolver
from audit.planner import Planner
from audit.contract import serialize, validate_row
from audit.schema import check_dataset

log = logging.getLogger("ghost_audit")


def run(ds, requests_file, out_path):
    for w in check_dataset(ds):
        log.warning("schema: %s", w)
    resolver, planner = IdentityResolver(ds), Planner(ds)
    rows, errors = [], []
    for req in read_csv(ds / requests_file):
        cid, at = req["case_id"], req["audit_at"]
        if not requests_deletion(req.get("request_text", "")):
            status, steps = "NOT_APPLICABLE", []
        else:
            ident = resolver.resolve(req["email"], at)
            if ident is None:
                status, steps = "INCOMPLETE", []  # unresolved identity: flagged for manual review
                log.warning("%s: identity unresolved; flagged for manual review", cid)
            else:
                status, steps = planner.audit(ident, req)
        errors += validate_row(cid, status, steps) if steps or status != "INCOMPLETE" else []
        rows.append((cid, status, serialize(steps)))
    rows.sort()
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)
    for e in errors[:20]:
        log.error("contract: %s", e)
    log.info("wrote %d rows to %s; contract errors: %d", len(rows), out_path, len(errors))


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(root / "dataset"))
    ap.add_argument("--output", default=None)
    ap.add_argument("--sample", action="store_true", help="run on sample_deletion_requests.csv")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(message)s")
    out = a.output or str(root / ("sample_pred.csv" if a.sample else "output.csv"))
    run(Path(a.dataset), "sample_deletion_requests.csv" if a.sample else "deletion_requests.csv", out)
