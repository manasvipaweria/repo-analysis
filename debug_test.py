from unittest.mock import patch, MagicMock
from src.adapters.codex_security_adapter import CodexSecurityAdapter
from src.adapters.codex_architecture_adapter import CodexArchitectureAdapter
import os
import json

with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
    with patch("src.adapters.codex_security_adapter.subprocess.run") as mock_run:
        adapter = CodexSecurityAdapter()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"repositoryFindings": [{"severity": "High", "title": "SQL Injection", "description": "Found a SQL injection"}]}'
        mock_run.return_value = mock_result
        res = adapter.run(".")
        print("Security:", res.status)
        print("Security Error:", res.error_message)
        
    with patch("src.adapters.codex_architecture_adapter.openai") as mock_openai:
        adapter = CodexArchitectureAdapter()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "hld_summary": "Monolithic application",
            "lld_summary": "Python scripts",
            "recommended_target_architecture": "Microservices",
            "findings": [
                {
                    "category": "architecture",
                    "severity": "high",
                    "file": "main.py",
                    "line": 10,
                    "message": "God class detected",
                    "rule_id": "ARCH-001"
                }
            ]
        })
        mock_client.chat.completions.create.return_value = mock_response
        res = adapter.run(".")
        print("Arch:", res.status)
        print("Arch Error:", res.error_message)
