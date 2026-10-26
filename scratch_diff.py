import csv, json, sys
sys.path.insert(0, 'code')

FIELDS = ['phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id']

gold = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'] or '[]'))
        for r in csv.DictReader(open('dataset/sample_output.csv', newline='', encoding='utf-8-sig'))}
pred = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'] or '[]'))
        for r in csv.DictReader(open('sample_pred.csv', newline='', encoding='utf-8-sig'))}

for cid in sorted(gold):
    gs, gsteps = gold[cid]
    ps, psteps = pred.get(cid, ('', []))
    if [tuple(g[f] for f in FIELDS) for g in gsteps] != [tuple(p[f] for f in FIELDS) for p in psteps] or gs != ps:
        print(f'=== {cid}: gold={gs}({len(gsteps)}) pred={ps}({len(psteps)}) ===')
        for i, g in enumerate(gsteps):
            p = psteps[i] if i < len(psteps) else None
            m = '==' if p and all(g.get(f) == p.get(f) for f in FIELDS) else '!!'
            op = g['operation']
            sys_ = g['system_id']
            res = g['resource_id']
            ev = g['evidence_id']
            print(f'  G{i+1} {m} {op} {sys_} {res} ev={ev}')
            if p and m == '!!':
                pop = p['operation']
                psys = p['system_id']
                pres = p['resource_id']
                pev = p['evidence_id']
                print(f'  P{i+1}    {pop} {psys} {pres} ev={pev}')
        for i in range(len(gsteps), len(psteps)):
            p = psteps[i]
            print(f'  P{i+1} ++ {p["operation"]} {p["system_id"]} {p["resource_id"]}')
