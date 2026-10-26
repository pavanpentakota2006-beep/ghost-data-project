import csv, collections

acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))
print(f"Total system activities: {len(acts)}")
types = collections.Counter(a['event_type'] for a in acts)
for t, c in types.most_common():
    print(f"  {t:25}: {c}")

print("\nSources:")
srcs = collections.Counter(a['source_system'] for a in acts)
for s, c in srcs.most_common():
    print(f"  {s:25}: {c}")

print("\nTargets:")
tgts = collections.Counter(a['target_system'] for a in acts)
for t, c in tgts.most_common():
    print(f"  {t:25}: {c}")
