# Architecture and Design Decisions

## Pipeline
```
deletion_requests.csv ─▶ intent ─▶ (not a deletion request) ─▶ NOT_APPLICABLE, []
                           │
                           ▼
          identity (user_identities + user_audit_log, cut off at audit_at)
                           │  all current + historical identifiers
        ┌──────────────────┼───────────────────┐
        ▼                  ▼                   ▼
   evidence scan     system_activity      deletion_rules
 (SQL/log/JSON/OCR)  (flows, restores)    (treatment per category)
        └──────────────────┼───────────────────┘
                           ▼
              planner: findings → remediation → verification
                           ▼
        contract: order, number, validate → output.csv
```

## Decisions
- **Deterministic first.** Every verdict is derived from evidence and rules, so runs are reproducible, free, and auditable. An LLM, if added, should only extract text from images/PDFs; it must not decide status.
- **Claims are not evidence.** `reported_status` and activity `status/result` are never trusted; state comes from snapshots captured at or before `audit_at`.
- **Time-bounded.** Evidence, audit entries and activity after `audit_at` are ignored, so later rewrites cannot change an earlier audit.
- **Safe ordering.** Flows are disabled and restores blocked before records change, otherwise sync or restore could recreate deleted data.
- **Retention honoured.** `RETAIN` records generate `VERIFY_RECORD_PRESENT`, never a deletion; tombstones are redacted, keeping only the `user_id`.
- **One contract module.** `contract.py` is the single source for operations, states, ordering and validation; every row is validated before it is written.
- **Calibration surface.** Dataset-specific guesses live in `audit/config.py` (aliases, keywords) and `audit/rules.py` (category matching). `inspect_dataset.py` and `audit/schema.py` show what to adjust.

## Known limitations
- Heuristics were authored without the real dataset; run `make sample` and tune.
- An unresolved identity yields `INCOMPLETE` with no steps and a logged warning for manual review.
- PDF/image evidence needs `pdftotext` / `tesseract`; otherwise it is skipped.
