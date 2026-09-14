import re
with open("src/compliance/data_flow.py", "r", encoding="utf-8") as f:
    text = f.read()

new_block = """        for pii in res.get("unprotected_storage", []):
            pii["file"] = os.path.relpath(res["file"], repo_path).replace("\\", "/")
            compiled["unprotected_storage"].append(pii)
        for pii in res.get("db_destinations", []):
            pii["file"] = os.path.relpath(res["file"], repo_path).replace("\\", "/")
            compiled["db_destinations"].append(pii)"""

text = text.replace("""        for pii in res.get("unprotected_storage", []):
            pii["file"] = os.path.relpath(res["file"], repo_path).replace("\\\\", "/")
            compiled["unprotected_storage"].append(pii)""", new_block)

with open("src/compliance/data_flow.py", "w", encoding="utf-8") as f:
    f.write(text)
