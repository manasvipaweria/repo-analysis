import re
with open("src/compliance/data_flow.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace('replace("\\", "/")', 'replace("\\\\", "/")')

with open("src/compliance/data_flow.py", "w", encoding="utf-8") as f:
    f.write(text)
