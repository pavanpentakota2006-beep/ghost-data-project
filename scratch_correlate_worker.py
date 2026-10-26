import csv
from datetime import datetime

requests = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig')))
worker_acts = [a for a in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')) if a['source_system'] == 'deletion_worker']

# For each sample request, check which worker activities happened near reported_at
for r in requests[:10]:
    cid = r['case_id']
    rep_at = r['reported_at']
    rep_dt = datetime.fromisoformat(rep_at.replace('Z', '+00:00'))
    print(f"\n=== {cid}: reported_at={rep_at} status={r['reported_status']} ===")
    matches = []
    for a in worker_acts:
        adt = datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
        diff_mins = (adt - rep_dt).total_seconds() / 60.0
        # If within 3 hours before reported_at or slightly after
        if -180 <= diff_mins <= 5:
            matches.append((diff_mins, a))
    for diff, a in matches:
        print(f"  [{diff:6.1f}m] {a['event_time']} | {a['event_type']} | {a['target_system']} | res={a['resource_id']} | {a['reported_result']}")
