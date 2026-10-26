import csv
from datetime import datetime

acts = [a for a in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig'))
        if a['source_system'] == 'deletion_worker']

# Check how deletion worker events follow each other
print(f"Total deletion worker events: {len(acts)}")
# For each event, print time, type, target_system, resource_id
for a in acts[20:40]:
    print(f"{a['event_time']} | {a['event_type']:20} | {a['target_system']:20} | {a['resource_id']}")
