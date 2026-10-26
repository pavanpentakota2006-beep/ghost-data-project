# Ghost Data Still Exists — Deletion Audit Agent

Deterministic, evidence-driven pipeline that audits whether a user's personal data was truly deleted.
Pure Python 3.9+ standard library (no API keys, no network). Optional: `pdftotext` / `tesseract` on PATH for PDF/image evidence.

## Run
One command (needs `dataset/` in the repo root) — scores the sample set, writes `output.csv`, validates it, refreshes the
reports, and builds `code.zip`:
```bash
python3 code/run_all.py
```
Individual steps:
```bash
python3 code/main.py                 # reads dataset/, writes ./output.csv (518 rows, sorted)
python3 code/main.py --sample        # runs sample_deletion_requests.csv -> ./sample_pred.csv
python3 code/evaluation/evaluate.py --pred sample_pred.csv --gold dataset/sample_output.csv
python3 code/tests/test_pipeline.py  # synthetic end-to-end test (fictional data)
```
`make inspect` shows dataset schemas and column warnings; `make test` runs unit + end-to-end tests (see `Makefile`).
Design notes: `docs/ARCHITECTURE.md`.

## Architecture (`code/audit/`)
| Module | Role |
| --- | --- |
| `intent.py` | Multilingual deletion-intent classifier; non-deletion requests -> `NOT_APPLICABLE`, `[]` |
| `identity.py` | Request email -> `user_id`; collects current + historical emails/phones/hashes/names, ignoring audit entries after `audit_at` |
| `evidence.py` | Scans evidence captured at/before `audit_at`: executes `.sql` snapshots in SQLite (all replicas), text/JSON/logs, optional OCR |
| `rules.py` | Maps each record to its `deletion_rules.csv` treatment (DELETE / REDACT / ANONYMIZE / RETAIN / TOMBSTONE) |
| `activity.py` | Derives still-active sync/import flows and unblocked backup/restore paths from `system_activity.csv` (statuses treated as claims) |
| `planner.py` | Builds findings -> remediation (flows, restores, then records) -> verification; `COMPLETE` only when no violations |
| `contract.py` | Allowed ops/states, ordering (phase, op table order, system_id, resource_id), numbering, validation |

Remediation and future verification steps use `evidence_id=""`; findings and `COMPLETE` verifications cite a `file_id`/`activity_id`.

## Calibration status
`audit/config.py` holds the heuristics (column aliases, keyword lists, resource-ID columns). They were written from the
challenge contract and tested only on synthetic data; tune them against `dataset/sample_output.csv` before the final run
(see `code/evaluation/evaluation_report.md`).

## Submission helpers
- `python3 code/run_all.py` -> `output.csv`, `code.zip`, auto-filled sample metrics in `evaluation_report.md`, `usage_report.md`.
- `python3 code/stage_trace.py claude-code=<session folder> [codex=<dir>]` -> `agent-trace.zip` (skips auth/config files; review before upload).
- `log.txt` (repo root) is the chat transcript required by `AGENTS.md`; append to it each turn if you continue in another agent.
