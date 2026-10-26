import csv
from datetime import datetime
from collections import defaultdict

samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig')))
acts = [a for a in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig'))
        if a['source_system'] == 'deletion_worker']

print(f"Total deletion_worker events: {len(acts)}")

# Group events that occur in tight clusters (e.g. within 2 hours of each other)
acts.sort(key=lambda a: a['event_time'])

clusters = []
curr_cluster = []
for a in acts:
    adt = datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
    if not curr_cluster:
        curr_cluster.append((adt, a))
    else:
        last_dt = curr_cluster[-1][0]
        if (adt - last_dt).total_seconds() <= 3600:  # within 1 hour of previous event
            curr_cluster.append((adt, a))
        else:
            clusters.append(curr_cluster)
            curr_cluster = [(adt, a)]
if curr_cluster:
    clusters.append(curr_cluster)

print(f"Total activity clusters: {len(clusters)}")
for i, cl in enumerate(clusters[:10]):
    start_t = cl[0][1]['event_time']
    end_t = cl[-1][1]['event_time']
    print(f"Cluster {i+1}: {len(cl)} events from {start_t} to {end_t}")
    for _, a in cl[:5]:
        print(f"   {a['event_time']} | {a['event_type']:20} | {a['target_system']:18} | {a['resource_id']:15} | {a['reported_result']}")
