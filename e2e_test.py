import json
import os
import sys
from unittest.mock import patch, MagicMock

# Inject fake environment variable so adapters don't skip
os.environ["OPENAI_API_KEY"] = "mock-key-for-e2e"

# Mock Codex Security CLI output
mock_security_result = MagicMock()
mock_security_result.returncode = 0
mock_security_result.stdout = '''
{
  "repositoryFindings": [
    {
      "severity": "High",
      "title": "SQL Injection in POS",
      "description": "Found a SQL injection in payment processing",
      "ruleId": "CWE-89",
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "backend/controllers/paymentController.js"}, "region": {"startLine": 45}}}]
    }
  ]
}
'''

# Mock Codex Architecture API output
mock_arch_response = MagicMock()
mock_arch_response.choices[0].message.content = json.dumps({
    "hld_summary": "MERN Stack Application",
    "lld_summary": "Express backend, React frontend",
    "recommended_target_architecture": "Microservices",
    "findings": [
        {
            "category": "architecture",
            "severity": "medium",
            "file": "backend/server.js",
            "line": 15,
            "message": "Monolithic router setup",
            "rule_id": "ARCH-002"
        }
    ]
})
mock_openai_client = MagicMock()
mock_openai_client.chat.completions.create.return_value = mock_arch_response

with patch("src.adapters.codex_security_adapter.subprocess.run", return_value=mock_security_result):
    with patch("src.adapters.codex_architecture_adapter.openai") as mock_openai:
        mock_openai.OpenAI.return_value = mock_openai_client
        
        # Override sys.argv to simulate CLI execution
        sys.argv = [
            "analyze_repo.py", 
            "C:\\Users\\dell\\.gemini\\antigravity\\scratch\\pos_revenue_automation_mern", 
            "--tools", "codex-security,codex-architecture", 
            "--output", "json,csv"
        ]
        
        from analyze_repo import main
        print("Running E2E Mock Execution...")
        main()
