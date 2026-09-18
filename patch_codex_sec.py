import re
with open("src/adapters/codex_security_adapter.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace('"--max-cost", "3.00"', '"--max-cost", "5.00"')

with open("src/adapters/codex_security_adapter.py", "w", encoding="utf-8") as f:
    f.write(text)
