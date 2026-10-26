"""Deletion-rule lookup: maps a record's hint text to the required treatment."""
import re
from .util import read_csv, pick, norm

ACTIONS = ["DELETE", "REDACT", "ANONYMIZE", "RETAIN", "TOMBSTONE"]


def norm_action(a):
    a = (a or "").upper()
    if "TOMB" in a:
        return "TOMBSTONE"
    for x in ("ANONYM", "REDACT", "RETAIN", "DELETE"):
        if x in a:
            return {"ANONYM": "ANONYMIZE"}.get(x, x)
    return "DELETE"


class RuleBook:
    def __init__(self, ds):
        self.rules = []
        for r in read_csv(ds / "deletion_rules.csv"):
            cat = norm(pick(r, "category"))
            self.rules.append({"category": cat, "tokens": [t for t in re.split(r"[^a-z0-9]+", cat) if t],
                               "action": norm_action(pick(r, "rule_action")), "raw": r})

    def action_for(self, hint):
        h = norm(hint)
        best, score = None, 0
        for r in self.rules:
            if not r["tokens"]:
                continue
            s = sum(1 for t in r["tokens"] if t in h)
            if s == len(r["tokens"]) and s > score:
                best, score = r, s
        return (best["action"], best["category"]) if best else ("DELETE", "unmatched")
