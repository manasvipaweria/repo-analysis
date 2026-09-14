import re

with open("src/core/models.py", "r", encoding="utf-8") as f:
    content = f.read()

new_enum = """class Category(str, Enum):
    SECURITY = "security"
    DEPENDENCIES = "dependency_security"
    PRIVACY = "privacy"
    ARCHITECTURE = "architecture"
    UI_DESIGN = "ui_design"
    AI_DESIGN = "ai_design"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    TESTING = "testing"
    TYPING = "typing"
"""

content = re.sub(r'class Category\(str, Enum\):.*?TYPING = "typing"', new_enum, content, flags=re.DOTALL)

with open("src/core/models.py", "w", encoding="utf-8") as f:
    f.write(content)
