import os
import json
import subprocess
import pytest

def test_pipeline_persistence():
    cmd = ['python', 'analyze_repo.py', '../dakiya.apnimandi.us', '--tools', 'ruff', '--output', 'json']
    subprocess.run(cmd, check=True)
    
    assert os.path.exists('report.json'), "report.json was not created"
    
    with open('report.json', 'r') as f:
        data = json.load(f)
        
    findings = data.get('findings', [])
    assert findings, "No findings produced. Cannot verify fields."
        
    missing_fingerprint = sum(1 for f in findings if f.get('fingerprint') is None)
    missing_priority = sum(1 for f in findings if f.get('priority_score') is None)
    
    assert missing_fingerprint == 0, f"{missing_fingerprint} findings missing fingerprint"
    assert missing_priority == 0, f"{missing_priority} findings missing priority_score"
