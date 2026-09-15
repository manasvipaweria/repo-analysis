with open('src/core/models.py', 'r') as f:
    text = f.read()

# Add fields to Finding
patch = '''    group_id: Optional[str] = None
    priority_score: Optional[int] = None
    priority_level: Optional[str] = None
    priority_reasons: List[str] = field(default_factory=list)'''
text = text.replace('    group_id: Optional[str] = None', patch, 1)

patch_init = '''        group_id: Optional[str] = None,
        priority_score: Optional[int] = None,
        priority_level: Optional[str] = None,
        priority_reasons: Optional[List[str]] = None
    ):'''
text = text.replace('        group_id: Optional[str] = None\n    ):', patch_init, 1)

patch_assign = '''        self.fingerprint = fingerprint
        self.group_id = group_id
        self.priority_score = priority_score
        self.priority_level = priority_level
        self.priority_reasons = priority_reasons or []'''
text = text.replace('        self.fingerprint = fingerprint\n        self.group_id = group_id', patch_assign, 1)

patch_from_dict = '''                fingerprint=fd.get("fingerprint"),
                group_id=fd.get("group_id"),
                priority_score=fd.get("priority_score"),
                priority_level=fd.get("priority_level"),
                priority_reasons=fd.get("priority_reasons", []),
                file=None,'''
text = text.replace('                fingerprint=fd.get("fingerprint"),\n                group_id=fd.get("group_id"),\n                file=None,', patch_from_dict, 1)

with open('src/core/models.py', 'w') as f:
    f.write(text)
