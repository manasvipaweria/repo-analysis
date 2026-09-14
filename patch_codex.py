import re
with open("src/adapters/codex_architecture_adapter.py", "r", encoding="utf-8") as f:
    text = f.read()

# Replace dirs filter to allow .github
old_filter = "dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'dist', 'build', '__pycache__')]"
new_filter = "dirs[:] = [d for d in dirs if (not d.startswith('.') or d == '.github') and d not in ('node_modules', 'dist', 'build', '__pycache__')]"
text = text.replace(old_filter, new_filter)

# Also need to read structural files from .github/workflows/*.yml
old_struct = """        structural_files = [
            'package.json', 'pom.xml', 'docker-compose.yml', 
            'README.md', 'architecture.md', 'requirements.txt'
        ]"""
new_struct = """        structural_files = [
            'package.json', 'pom.xml', 'docker-compose.yml', 
            'README.md', 'architecture.md', 'requirements.txt'
        ]
        import glob
        wf_files = glob.glob(os.path.join(repo_path, '.github', 'workflows', '*.yml'))
        wf_files.extend(glob.glob(os.path.join(repo_path, '.github', 'workflows', '*.yaml')))
        for wf in wf_files:
            structural_files.append(os.path.relpath(wf, repo_path))"""
text = text.replace(old_struct, new_struct)

# Add code context to findings to ensure they aren't empty (Point 12)
old_append = """            for raw_f in findings_data:
                findings.append(Finding("""
new_append = """            for raw_f in findings_data:
                context_str = raw_f.get("code_context", "Analyzed from project structure.")
                f = Finding("""
text = text.replace(old_append, new_append)
text = text.replace('code_context=""', 'code_context=context_str')

with open("src/adapters/codex_architecture_adapter.py", "w", encoding="utf-8") as f:
    f.write(text)
