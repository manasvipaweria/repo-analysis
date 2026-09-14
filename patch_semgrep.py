import re
with open("src/adapters/semgrep_adapter.py", "r", encoding="utf-8") as f:
    text = f.read()

old_cmd = '["semgrep", "scan", "--config=auto", "--json", "."]'
new_cmd = '["semgrep", "scan", "--config=auto", "--json", "--exclude", "dist/", "--exclude", "build/", "--exclude", "coverage/", "--exclude", "node_modules/", "--exclude", ".next/", "."]'

text = text.replace(old_cmd, new_cmd)

with open("src/adapters/semgrep_adapter.py", "w", encoding="utf-8") as f:
    f.write(text)
