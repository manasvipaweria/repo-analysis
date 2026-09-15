import re

with open('src/core/models.py', 'r') as f:
    text = f.read()

# 1. imports
text = text.replace(
    'from typing import List, Dict, Any, Optional\nfrom enum import Enum',
    'from typing import List, Dict, Any, Optional\nfrom enum import Enum\n\nclass GroupConfidence(str, Enum):\n    HIGH = "HIGH"\n    MEDIUM = "MEDIUM"\n    LOW = "LOW"'
)

# 2. Finding.group_id
text = text.replace(
    'fingerprint: Optional[str] = None',
    'fingerprint: Optional[str] = None,\n        group_id: Optional[str] = None'
)
text = text.replace(
    'self.fingerprint = fingerprint',
    'self.fingerprint = fingerprint\n        self.group_id = group_id'
)

# 3. FindingGroup class
finding_group = '''
@dataclass
class FindingGroup:
    group_id: str
    title: str
    confidence: GroupConfidence
    grouping_reason: str
    fingerprints: List[str] = field(default_factory=list)
    category: Optional[str] = None
    severity: Optional[str] = None
    rule_id: Optional[str] = None

class CategorySummary:'''
text = text.replace('class CategorySummary:', finding_group)

# 4. Report.finding_groups
text = text.replace(
    'data_flow: Optional[Dict[str, Any]] = None',
    'data_flow: Optional[Dict[str, Any]] = None\n    finding_groups: List[FindingGroup] = field(default_factory=list)'
)

# 5. Finding.from_dict
text = text.replace(
    'eprivacy_references=fd.get("eprivacy_references", []),\n                fingerprint=fd.get("fingerprint"),\n                file=None',
    'eprivacy_references=fd.get("eprivacy_references", []),\n                fingerprint=fd.get("fingerprint"),\n                group_id=fd.get("group_id"),\n                file=None'
)

# 6. Report.from_dict
from_dict_patch = '''
        groups_list = []
        for gd in data.get("finding_groups", []):
            groups_list.append(FindingGroup(
                group_id=gd.get("group_id", ""),
                title=gd.get("title", ""),
                confidence=GroupConfidence(gd.get("confidence", "LOW")),
                grouping_reason=gd.get("grouping_reason", ""),
                fingerprints=gd.get("fingerprints", []),
                category=gd.get("category"),
                severity=gd.get("severity"),
                rule_id=gd.get("rule_id")
            ))

        return cls(
            repo=data.get("repo", ""),
            timestamp=data.get("timestamp", ""),
            summary=summary_dict,
            findings=findings_list,
            data_flow=data.get("data_flow"),
            finding_groups=groups_list
        )
'''
text = re.sub(r'return cls\(\s*repo=.*$', from_dict_patch.strip(), text, flags=re.DOTALL)

with open('src/core/models.py', 'w') as f:
    f.write(text)
