import csv

acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))
for target in ['account_7566', 'account_3960', 'account_4248', 'account_9797', 'account_9335', 'account_3677']:
    print(f"\nTarget: {target}")
    for a in acts:
        if a['resource_id'] == target:
            print(f"  {a['event_time']} | {a['event_type']} | {a['target_system']} | res={a['resource_id']} | {a['reported_result']} | {a['details']}")
