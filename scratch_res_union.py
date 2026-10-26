import csv, json
from collections import defaultdict
from pathlib import Path

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
manifest = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8-sig'))}
acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))

# For each case, check its cited evidence file(s)
for cid in sorted(gold_rows):
    stat, steps = gold_rows[cid]
    ev_ids = sorted(set(s['evidence_id'] for s in steps if s['evidence_id']))
    gold_res = {s['resource_id'] for s in steps}
    
    # Check if the resources are mentioned in the cited evidence file(s)
    found_in_ev = set()
    for eid in ev_ids:
        fpath = Path('dataset') / manifest[eid]['file_path']
        try:
            txt = fpath.read_text(encoding='utf-8', errors='ignore')
            for r in gold_res:
                if r in txt:
                    found_in_ev.add(r)
        except Exception:
            pass
            
    # Check if resources are in system_activity
    found_in_act = {r for r in gold_res if any(a['resource_id'] == r for a in acts)}
    
    print(f"{cid} ({len(gold_res)} res): cited={ev_ids} | in_ev={len(found_in_ev)}/{len(gold_res)} | in_act={len(found_in_act)}/{len(gold_res)} | union={len(found_in_ev | found_in_act)}/{len(gold_res)}")
    missing = gold_res - (found_in_ev | found_in_act)
    if missing:
        print(f"   MISSING: {missing}")
