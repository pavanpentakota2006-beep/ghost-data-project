import csv, json

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
manifest = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8-sig'))}

for cid, (stat, steps) in sorted(gold_rows.items()):
    req = samples[cid]
    ev_ids = [s['evidence_id'] for s in steps if s['evidence_id']]
    print(f"{cid} | req={req['requested_at'][:10]} rep={req['reported_at'][:10]} aud={req['audit_at'][:10]} | stat={stat:10} | ev={set(ev_ids)}")
    for eid in set(ev_ids):
        info = manifest[eid]
        print(f"    -> {eid}: cap={info['captured_at'][:10]} path={info['file_path']}")
