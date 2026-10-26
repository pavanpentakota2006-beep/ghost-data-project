import csv, json

cids = ['case_27', 'case_28', 'case_29', 'case_30', 'case_31', 'case_32']
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}

# Print the sample requests
for cid in cids:
    r = samples[cid]
    print(f"{cid}: req_at={r['requested_at']} rep_at={r['reported_at']} email={r['email']}")

# Print system activity for each case's resources
gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
for cid in cids:
    r = samples[cid]
    stat, steps = gold_rows[cid]
    res_set = {s['resource_id'] for s in steps}
    print(f"\n--- System activity for {cid} ({r['email']}) res={res_set} ---")
    for a in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')):
        if a['resource_id'] in res_set or r['email'] in a['details']:
            print(f"  {a['event_time']} | {a['event_type']} | {a['target_system']} | res={a['resource_id']} | {a['reported_result']} | {a['details']}")

