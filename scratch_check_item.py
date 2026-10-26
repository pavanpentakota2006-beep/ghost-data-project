import json

data = json.load(open('dataset/evidence/records/service_resource_export_20260915_114455.json', encoding='utf-8'))
for target in ['account_3866', 'support_4707', 'data_flow_2295', 'backup_5970', 'analytics_4574', 'audit_record_3830']:
    print(f"\nTarget: {target}")
    for svc, content in data['service_exports'].items():
        if target in json.dumps(content):
            print(f"  Service: {svc}")
            for k, v in content.items():
                for item in v:
                    if target in json.dumps(item):
                        print("   ", item)

