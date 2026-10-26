import csv, json
from collections import defaultdict
from pathlib import Path

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
manifest = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8-sig'))}

# Look at evidence cited by gold
ev_cited = defaultdict(list)
for cid, (stat, steps) in gold_rows.items():
    ev_ids = {s['evidence_id'] for s in steps if s['evidence_id']}
    for eid in ev_ids:
        ev_cited[eid].append(cid)

print(f"Total distinct evidence files cited in gold: {len(ev_cited)}")
for eid, cases in sorted(ev_cited.items()):
    info = manifest.get(eid, {})
    print(f"  {eid} ({len(cases)} cases: {cases[:5]}): path={info.get('file_path')} origin={info.get('origin')} ts={info.get('captured_at')}")
