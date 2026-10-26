import csv, collections

acts = [a for a in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')) if a['source_system'] == 'deletion_worker']
print(f"Total deletion_worker events: {len(acts)}")
types = collections.Counter(a['event_type'] for a in acts)
for t, c in types.most_common():
    print(f"  {t:25}: {c}")

# What target systems?
targets = collections.Counter(a['target_system'] for a in acts)
print("\nTargets:")
for t, c in targets.most_common():
    print(f"  {t:25}: {c}")

# Look at details of deletion_worker events
print("\nSample details:")
for a in acts[:10]:
    print(f"  {a['event_time']} | {a['event_type']} | {a['target_system']} | res={a['resource_id']} | res={a['reported_result']} | {a['details']}")
