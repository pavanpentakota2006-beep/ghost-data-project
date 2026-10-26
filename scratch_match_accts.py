import csv, json
from datetime import datetime

samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig')))
gold_rows = {r['case_id']: json.loads(r['steps_json']) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
acts = [a for a in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')) 
        if a['source_system'] == 'deletion_worker' and a['target_system'] == 'account_service']

print(f"Total account_service deletion acts: {len(acts)}")
# For each sample request, find the closest account_service deletion act to reported_at
matches = 0
for r in samples:
    cid = r['case_id']
    rep_dt = datetime.fromisoformat(r['reported_at'].replace('Z', '+00:00'))
    gold_accts = [s['resource_id'] for s in gold_rows[cid] if s['system_id'] == 'account_service']
    expected = gold_accts[0] if gold_accts else None
    
    # find closest act
    best_act, best_diff = None, float('inf')
    for a in acts:
        adt = datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
        diff = abs((adt - rep_dt).total_seconds())
        if diff < best_diff:
            best_diff = diff
            best_act = a
            
    matched = (best_act['resource_id'] == expected) if expected else False
    if matched:
        matches += 1
    print(f"{cid}: expected={expected} closest={best_act['resource_id']} (diff={best_diff/60:.1f}m, res={best_act['reported_result']}) -> {'MATCH' if matched else 'MISMATCH'}")

print(f"\nTotal matches: {matches} of {len(samples)}")
