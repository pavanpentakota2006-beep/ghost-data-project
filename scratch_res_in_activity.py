import csv, json, re
from collections import defaultdict
from pathlib import Path

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
email_to_uid = {r['email']: r['user_id'] for r in users.values()}
for r in csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')):
    if r['field_name'] == 'email':
        email_to_uid[r['old_value']] = r['user_id']
        email_to_uid[r['new_value']] = r['user_id']

# Collect all resources for all sample cases
all_resources = set()
for stat, steps in gold_rows.values():
    for s in steps:
        all_resources.add(s['resource_id'])

print(f"Total unique resources in gold samples: {len(all_resources)}")

# Check system_activity.csv
activity_res = defaultdict(list)
for r in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')):
    activity_res[r['resource_id']].append(r)

found_in_act = {r for r in all_resources if r in activity_res}
print(f"Resources found in system_activity.csv: {len(found_in_act)} of {len(all_resources)}")
missing_from_act = all_resources - found_in_act
print(f"Resources NOT in system_activity.csv: {len(missing_from_act)} -> {sorted(missing_from_act)[:15]}")
