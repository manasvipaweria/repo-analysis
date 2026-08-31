import pytest
from unittest.mock import patch, MagicMock
import os
import subprocess

from src.adapters.codex_security_adapter import CodexSecurityAdapter

@pytest.fixture
def mock_env():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
        yield

def test_codex_security_adapter_no_key():
    with patch.dict(os.environ, clear=True):
        adapter = CodexSecurityAdapter()
        result = adapter.run(".")
        assert result.status.name == "SKIPPED"
        assert len(result.findings) == 0

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_success(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '''
    Some npx download logs
    {
      "repositoryFindings": [
        {
          "severity": "High",
          "title": "SQL Injection",
          "description": "Found a SQL injection",
          "ruleId": "CWE-89",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/db.py"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ]
        }
      ]
    }
    '''
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "COMPLETED"
    findings = res.findings
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "security"
    assert f.severity == "high"
    assert f.location.file == "src/db.py"
    assert f.location.line == 42
    assert "Found a SQL injection" in f.description
    assert f.rule_id == "CWE-89"
    assert "codex-security" in f.detected_by

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_auth_failure(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Error: Unauthorized - you don't have Codex Security access"
    mock_result.stdout = ""
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "SKIPPED"
    assert len(res.findings) == 0

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_timeout(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="npx", timeout=900)
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0
