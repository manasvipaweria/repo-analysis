from unittest.mock import patch, MagicMock
import os, json
from src.adapters.codex_architecture_adapter import CodexArchitectureAdapter
with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
    with patch("src.adapters.codex_architecture_adapter.openai") as mock_openai:
        adapter = CodexArchitectureAdapter()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({"hld_summary": "Mono", "lld_summary": "Py", "recommended_target_architecture": "Micro", "findings": [{"category": "architecture", "severity": "high", "file": "main.py", "line": 10, "message": "God class", "rule_id": "ARCH-001"}]})
        mock_client.chat.completions.create.return_value = mock_response
        res = adapter.run(".")
        print(res.status.name, res.error_message)
