"""Interpret system_activity.csv: active data flows, restore risks, deletion claims."""
from .util import read_csv, pick, norm, parse_ts
from .config import FLOW_WORDS, RESTORE_WORDS, STOP_WORDS, BLOCK_WORDS, DELETE_EVENT_WORDS


class Activity:
    def __init__(self, ds):
        self.rows = []
        for r in read_csv(ds / "system_activity.csv"):
            self.rows.append({
                "id": pick(r, "activity_id"), "ts": parse_ts(pick(r, "ts")),
                "system": pick(r, "system_id"), "resource": pick(r, "resource_id"),
                "text": norm(" ".join([pick(r, "operation"), pick(r, "status"), pick(r, "details")])),
                "blob": norm(" ".join(str(v) for v in r.values())),
            })
        self.rows.sort(key=lambda r: (r["ts"] is None, r["ts"]))

    def _refs_user(self, row, ident, resources):
        b = row["blob"]
        return (norm(ident.user_id) in b or any(e in b for e in ident.emails) or any(h in b for h in ident.hashes)
                or (row["resource"] and (row["system"], row["resource"]) in resources))

    def _latest_state(self, audit_at, ident, resources, words, stop_words):
        cutoff = parse_ts(audit_at)
        latest = {}
        for r in self.rows:
            if cutoff and r["ts"] and r["ts"] > cutoff:
                continue
            if not self._refs_user(r, ident, resources):
                continue
            if any(w in r["text"] for w in words) or any(w in r["text"] for w in stop_words):
                latest[(r["system"], r["resource"])] = (r, any(w in r["text"] for w in stop_words))
        return latest

    def active_flows(self, audit_at, ident, resources):
        st = self._latest_state(audit_at, ident, resources, FLOW_WORDS, STOP_WORDS)
        return [(k, r) for k, (r, stopped) in st.items() if not stopped and any(w in r["text"] for w in FLOW_WORDS)]

    def restore_risks(self, audit_at, ident, resources):
        st = self._latest_state(audit_at, ident, resources, RESTORE_WORDS, BLOCK_WORDS)
        return [(k, r) for k, (r, blocked) in st.items() if not blocked and any(w in r["text"] for w in RESTORE_WORDS)]

    def deletion_claims(self, audit_at, ident):
        cutoff = parse_ts(audit_at)
        return [r for r in self.rows if (not cutoff or not r["ts"] or r["ts"] <= cutoff)
                and any(w in r["text"] for w in DELETE_EVENT_WORDS) and self._refs_user(r, ident, set())]
