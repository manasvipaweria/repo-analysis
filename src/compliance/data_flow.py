import os
import json
import subprocess
from typing import Dict, List, Any

def run_js_ast_extractor(repo_path: str) -> List[Dict[str, Any]]:
    results = []
    extractor_path = os.path.join(os.path.dirname(__file__), "js_ast_extractor.js")
    
    for root, _, files in os.walk(repo_path):
        if "node_modules" in root or ".git" in root:
            continue
        for file in files:
            if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                file_path = os.path.join(root, file)
                try:
                    cmd = ["node", extractor_path, file_path]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    if proc.returncode == 0 and proc.stdout:
                        try:
                            data = json.loads(proc.stdout)
                            if "error" not in data:
                                results.append(data)
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass
    return results

def extract_data_flow(repo_path: str) -> Dict[str, Any]:
    """Phase 2: Shared Data Flow Extraction."""
    ast_results = run_js_ast_extractor(repo_path)
    
    compiled = {
        "outbound_domains": set(),
        "api_endpoints": [],
        "pii_fields": [],
        "db_destinations": [],
        "dependencies": []
    }
    
    for res in ast_results:
        for out in res.get("outbound_calls", []):
            compiled["outbound_domains"].add(out)
        for api in res.get("api_endpoints", []):
            api["file"] = os.path.relpath(res["file"], repo_path).replace("\\", "/")
            compiled["api_endpoints"].append(api)
        for pii in res.get("pii_fields", []):
            pii["file"] = os.path.relpath(res["file"], repo_path).replace("\\", "/")
            compiled["pii_fields"].append(pii)
            
    # Run dependency-cruiser to supplement
    try:
        cmd = ["npx", "dependency-cruiser", "--include-only", "^src", "--output-type", "json", "src"]
        proc = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout:
            dc_data = json.loads(proc.stdout)
            compiled["dependencies"] = dc_data.get("modules", [])
    except Exception:
        pass
        
    compiled["outbound_domains"] = list(compiled["outbound_domains"])
    return compiled
