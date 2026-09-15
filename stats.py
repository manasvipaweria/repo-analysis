import json

with open('report.json', 'r') as f:
    data = json.load(f)

findings = data.get('findings', [])
groups = data.get('finding_groups', [])
grouped_findings = [f for f in findings if f.get('group_id')]
standalone = len(findings) - len(grouped_findings)

print(f'Total individual findings: {len(findings)}')
print(f'Total groups: {len(groups)}')
print(f'Findings assigned to groups: {len(grouped_findings)}')
print(f'Standalone findings: {standalone}')

for g in groups:
    print('-'*40)
    print(f'Group ID: {g.get("group_id")}')
    print(f'Number of findings: {len(g.get("fingerprints", []))}')
    print(f'Group title: {g.get("title")}')
    print(f'Confidence: {g.get("confidence")}')
    print(f'Grouping reason: {g.get("grouping_reason")}')
