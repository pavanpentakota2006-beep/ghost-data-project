import csv

for r in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')):
    if '2026-09-15T10:' in r['event_time'] or '2026-09-15T09:' in r['event_time']:
        print(f"{r['event_time']} | {r['event_type']} | {r['target_system']} | {r['resource_id']} | {r['details']}")
