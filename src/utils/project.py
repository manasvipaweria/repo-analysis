import os
import json

def has_python_files(repo_path: str) -> bool:
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py') or file == 'requirements.txt' or file == 'Pipfile' or file == 'pyproject.toml':
                return True
    return False

def has_js_ts_files(repo_path: str) -> bool:
    manifests = {'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'tsconfig.json'}
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.js', '.jsx', '.ts', '.tsx')) or file in manifests:
                return True
    return False

def is_react_project(repo_path: str) -> bool:
    # Check for jsx/tsx files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.jsx', '.tsx')):
                return True
                
    # Check package.json for react dependencies
    for root, _, files in os.walk(repo_path):
        if 'package.json' in files:
            try:
                with open(os.path.join(root, 'package.json'), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                    if 'react' in deps or 'react-dom' in deps:
                        return True
            except (json.JSONDecodeError, FileNotFoundError):
                continue
                
    return False
