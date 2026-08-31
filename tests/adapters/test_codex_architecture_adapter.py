import pytest
from unittest.mock import patch, MagicMock
import os
import json

from src.adapters.codex_architecture_adapter import CodexArchitectureAdapter
from src.core.models import Category

@pytest.fixture
def mock_env():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
        yield

def test_codex_architecture_adapter_no_key():
    with patch.dict(os.environ, clear=True):
        adapter = CodexArchitectureAdapter()
        res = adapter.run(".")
        assert res.status.name == "SKIPPED"
        assert len(res.findings) == 0

@patch("src.adapters.codex_architecture_adapter.openai")
def test_codex_architecture_adapter_success(mock_openai, mock_env):
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
    assert res.status.name == "COMPLETED"
    findings = res.findings
    assert len(findings) == 2  # 1 summary + 1 finding
    
    summary = findings[0]
    assert summary.category == "architecture"
    assert "HLD: Monolithic application" in summary.description
    assert summary.rule_id == "arch-summary"
    
    f1 = findings[1]
    assert f1.category == "architecture"
    assert f1.severity == "high"
    assert f1.location.file == "main.py"
    assert f1.location.line == 10
    assert "God class detected" in f1.description
    assert f1.rule_id == "ARCH-001"
    assert "codex-architecture" in f1.detected_by

@patch("src.adapters.codex_architecture_adapter.openai")
def test_codex_architecture_adapter_api_error(mock_openai, mock_env):
    adapter = CodexArchitectureAdapter()
    
    mock_client = MagicMock()
    mock_openai.OpenAI.return_value = mock_client
    mock_client.chat.completions.create.side_effect = Exception("API Rate Limit")
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0
