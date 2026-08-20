import os

def has_python_files(repo_path: str) -> bool:
    for root, _, files in os.walk(repo_path):
        if any(f.endswith('.py') for f in files):
            return True
    return False

def has_js_ts_files(repo_path: str) -> bool:
    js_ts_extensions = {'.js', '.jsx', '.ts', '.tsx'}
    js_ts_manifests = {'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'tsconfig.json'}
    for root, _, files in os.walk(repo_path):
        for f in files:
            if any(f.endswith(ext) for ext in js_ts_extensions) or f in js_ts_manifests:
                return True
    return False
