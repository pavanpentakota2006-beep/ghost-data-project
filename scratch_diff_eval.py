import csv, json

gold = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
pred = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('sample_pred.csv', encoding='utf-8-sig'))}

for cid, g in sorted(gold.items()):
    p = pred[cid]
    if g[1] != p[1]:
        g_ops = [(s['phase'], s['operation'], s['resource_id'], s['evidence_id']) for s in g[1]]
        p_ops = [(s['phase'], s['operation'], s['resource_id'], s['evidence_id']) for s in p[1]]
        missing = [x for x in g_ops if (x[0], x[1], x[2]) not in [(y[0], y[1], y[2]) for y in p_ops]]
        extra = [y for y in p_ops if (y[0], y[1], y[2]) not in [(x[0], x[1], x[2]) for x in g_ops]]
        ev_diff = [(x[2], x[3], y[3]) for x in g_ops for y in p_ops if x[:3] == y[:3] and x[3] != y[3]]
        print(f"\n{cid} ({g[0]} vs {p[0]}):")
        if missing: print(f"  Missing: {missing}")
        if extra:   print(f"  Extra:   {extra}")
        if ev_diff: print(f"  Ev diff: {ev_diff}")
