#!/usr/bin/env python3
"""Score predictions against gold: status, step-level, field-level and sequence accuracy.
Usage: python3 code/evaluation/evaluate.py --pred sample_pred.csv --gold dataset/sample_output.csv"""
import argparse, csv, json

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(p):
    with open(p, newline="", encoding="utf-8-sig") as f:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"] or "[]")) for r in csv.DictReader(f)}


def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[-1][-1]


def key(s):
    return tuple(s[f] for f in FIELDS)


def evaluate(pred, gold):
    n = len(gold)
    status_ok = exact = 0
    tp = fp = fn = 0
    fld_ok = fld_tot = 0
    seq_num = seq_den = 0
    for cid, (gs, gsteps) in gold.items():
        ps, psteps = pred.get(cid, ("", []))
        status_ok += gs == ps
        exact += (gs == ps and [key(s) for s in gsteps] == [key(s) for s in psteps])
        gk, pk = [key(s) for s in gsteps], [key(s) for s in psteps]
        gset, pset = set(gk), set(pk)
        tp += len(gset & pset); fp += len(pset - gset); fn += len(gset - pset)
        for i, g in enumerate(gsteps):
            for f in FIELDS:
                fld_tot += 1
                fld_ok += i < len(psteps) and psteps[i].get(f) == g.get(f)
        seq_num += lcs(gk, pk); seq_den += max(len(gk), len(pk), 1) if (gk or pk) else 0
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {"cases": n, "status_accuracy": status_ok / n, "row_exact_match": exact / n,
            "step_precision": prec, "step_recall": rec, "step_f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "field_accuracy": fld_ok / fld_tot if fld_tot else 1.0,
            "sequence_accuracy": seq_num / seq_den if seq_den else 1.0}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", required=True)
    ap.add_argument("--gold", required=True)
    a = ap.parse_args()
    for k, v in evaluate(load(a.pred), load(a.gold)).items():
        print(f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}")
