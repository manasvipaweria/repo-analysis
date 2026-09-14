import re
with open("src/adapters/codex_architecture_adapter.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("f = Finding(", "findings.append(Finding(")

with open("src/adapters/codex_architecture_adapter.py", "w", encoding="utf-8") as f:
    f.write(text)
