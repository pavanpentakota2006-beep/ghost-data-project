import csv

acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))
for i, a in enumerate(acts):
    if a['resource_id'] == 'account_3866':
        for j in range(max(0, i-5), min(len(acts), i+15)):
            print(f"{acts[j]['event_time']} | {acts[j]['event_type']} | {acts[j]['target_system']} | {acts[j]['resource_id']} | {acts[j]['reported_result']} | {acts[j]['details']}")
        break
