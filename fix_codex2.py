import re
with open("src/adapters/codex_architecture_adapter.py", "r", encoding="utf-8") as f:
    text = f.read()

# Fix the summary finding's code_context
text = text.replace('code_context=context_str\n            ))\n            \n            for', 'code_context="Analyzed from project structure."\n            ))\n            \n            for')

with open("src/adapters/codex_architecture_adapter.py", "w", encoding="utf-8") as f:
    f.write(text)
