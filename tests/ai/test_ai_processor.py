import os
import json
import pytest
from unittest.mock import patch, MagicMock

from src.ai.report_processor import redact_secrets, process_report
from src.ai.ai_adapter import AIAdapter

def test_redact_secrets():
    text = "Here is my api_key: 'abcdef1234567890xyz' and my password=supersecretpass"
    redacted = redact_secrets(text)
    assert "abcdef1234567890xyz" not in redacted
    assert "supersecretpass" not in redacted
    assert "[REDACTED_SECRET]" in redacted
    
    aws_text = "aws_access_key = AKIAIOSFODNN7EXAMPLE"
    redacted_aws = redact_secrets(aws_text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted_aws
    assert "[REDACTED_SECRET]" in redacted_aws
    
    mongodb_text = "mongodb+srv://user:pass123@cluster0.mongodb.net/test"
    redacted_mongo = redact_secrets(mongodb_text)
    assert "pass123" not in redacted_mongo
    assert "mongodb+srv://user:[REDACTED_SECRET]@cluster0.mongodb.net/test" in redacted_mongo

def test_process_report_empty(tmp_path):
    report_file = tmp_path / "report.json"
    ai_input_file = tmp_path / "ai_input.json"
    
    report_data = {
        "repo": "test-repo",
        "timestamp": "2023-01-01",
        "findings": [],
        "summary": {}
    }
    report_file.write_text(json.dumps(report_data))
    
    process_report(str(report_file), str(ai_input_file))
    
    with open(ai_input_file, 'r') as f:
        ai_input = json.load(f)
        
    assert ai_input["repository"] == "test-repo"
    assert len(ai_input["findings"]) == 0

def test_process_report_with_findings(tmp_path):
    report_file = tmp_path / "report.json"
    ai_input_file = tmp_path / "ai_input.json"
    
    report_data = {
        "repo": "test-repo",
        "timestamp": "2023-01-01",
        "summary": {
            "security": {"count": 1}
        },
        "findings": [
            {
                "finding_id": "123",
                "category": "security",
                "severity": "high",
                "priority": "P1",
                "file": "test.py",
                "line": 10,
                "rule_id": "rule-1",
                "message": "Found secret AKIAIOSFODNN7EXAMPLE",
                "detected_by": ["bandit"],
                "code_context": "password='mysecretpassword123'",
                "merge_blocking": True
            }
        ]
    }
    report_file.write_text(json.dumps(report_data))
    
    process_report(str(report_file), str(ai_input_file))
    
    with open(ai_input_file, 'r') as f:
        ai_input = json.load(f)
        
    findings = ai_input["findings"]
    assert len(findings) == 1
    f1 = findings[0]
    assert f1["finding_id"] == "123"
    assert f1["category"] == "security"
    assert f1["file"] == "test.py"
    assert f1["line"] == 10
    
    # Check redaction
    assert "AKIAIOSFODNN7EXAMPLE" not in f1["message"]
    assert "[REDACTED_SECRET]" in f1["message"]
    
    assert "mysecretpassword123" not in f1["code_context"]
    assert "[REDACTED_SECRET]" in f1["code_context"]

def test_ai_adapter_mock_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [{"finding_id": "f1"}]
    }
    ai_input.write_text(json.dumps(ai_data))
    
    report_data = {
        "findings": [{"finding_id": "f1"}]
    }
    report_file.write_text(json.dumps(report_data))
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "COMPLETED"
    assert result["analyzed"] == 1
    
    with open(str(report_file), 'r') as f:
        updated_report = json.load(f)
        
    f1 = next(f for f in updated_report["findings"] if f["finding_id"] == "f1")
    assert "ai_fields" in f1
    assert "[MOCK AI]" in f1["ai_fields"]["analysis_summary"]

def test_ai_adapter_missing_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [{"finding_id": "f1"}]
    }
    ai_input.write_text(json.dumps(ai_data))
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "SKIPPED"
    assert "AI credentials missing" in result["error_message"]

@patch("src.ai.providers.openai_provider.requests.post")
def test_ai_adapter_openai_success(mock_post, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("AI_API_KEY", "dummy")
    monkeypatch.setenv("AI_BATCH_SIZE", "2")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [
            {"finding_id": "f1"},
            {"finding_id": "f2"},
            {"finding_id": "f3"} # Should be skipped due to batch_size
        ]
    }
    ai_input.write_text(json.dumps(ai_data))
    
    report_data = {
        "findings": [
            {"finding_id": "f1"},
            {"finding_id": "f2"},
            {"finding_id": "f3"}
        ]
    }
    report_file.write_text(json.dumps(report_data))
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "results": [
                            {
                                "finding_id": "f1",
                                "analysis_summary": "AI says this is bad.",
                                "remediation_suggestion": "Fix it.",
                                "is_false_positive_prediction": False
                            }
                        ]
                    })
                }
            }
        ]
    }
    mock_post.return_value = mock_resp
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "COMPLETED"
    assert result["analyzed"] == 1
    assert result["selected"] == 2
    
    with open(str(report_file), 'r') as f:
        updated_report = json.load(f)
        
    f1 = next(f for f in updated_report["findings"] if f["finding_id"] == "f1")
    assert "ai_fields" in f1
    assert f1["ai_fields"]["analysis_summary"] == "AI says this is bad."
    
    f2 = next(f for f in updated_report["findings"] if f["finding_id"] == "f2")
    assert "ai_fields" not in f2

@patch("src.ai.providers.openai_provider.requests.post")
def test_ai_adapter_openai_http_error(mock_post, tmp_path, monkeypatch):
    import requests
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("AI_API_KEY", "dummy")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [
            {"finding_id": "f1"}
        ]
    }
    ai_input.write_text(json.dumps(ai_data))
    
    # Mock requests.exceptions.HTTPError
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.json.return_value = {
        "error": {
            "message": "Too Many Requests - Rate limit exceeded."
        }
    }
    mock_err = requests.exceptions.HTTPError("429 Client Error")
    mock_err.response = mock_resp
    
    # Make raise_for_status throw the error
    mock_resp.raise_for_status.side_effect = mock_err
    mock_post.return_value = mock_resp
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "ERROR"
    assert "HTTP 429" in result["error_message"]
    assert "Too Many Requests - Rate limit exceeded." in result["error_message"]

def test_gemini_missing_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [{"finding_id": "f1"}]
    }
    ai_input.write_text(json.dumps(ai_data))
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "SKIPPED"
    assert "GEMINI_API_KEY not set" in result["error_message"]

@patch("src.ai.providers.gemini_provider.requests.post")
def test_ai_adapter_gemini_success(mock_post, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [{"finding_id": "f1"}]
    }
    ai_input.write_text(json.dumps(ai_data))
    
    report_data = {
        "findings": [{"finding_id": "f1"}]
    }
    report_file.write_text(json.dumps(report_data))
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "results": [
                                    {
                                        "finding_id": "f1",
                                        "analysis_summary": "Gemini analyzed this.",
                                        "remediation_suggestion": "Fix.",
                                        "is_false_positive_prediction": True
                                    }
                                ]
                            })
                        }
                    ]
                }
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 20,
            "totalTokenCount": 30
        }
    }
    mock_post.return_value = mock_resp
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "COMPLETED"
    assert result["analyzed"] == 1
    
    with open(str(report_file), 'r') as f:
        updated_report = json.load(f)
        
    f1 = next(f for f in updated_report["findings"] if f["finding_id"] == "f1")
    assert "ai_fields" in f1
    assert f1["ai_fields"]["analysis_summary"] == "Gemini analyzed this."
    assert result["usage"]["total_tokens"] == 30

def test_estimate_tokens_gemini(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [{"finding_id": "f1"}]
    }
    ai_input.write_text(json.dumps(ai_data))
    report_file.write_text("{}")
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file), estimate_only=True)
    
    assert result["status"] == "COMPLETED"
    
    captured = capsys.readouterr()
    assert "AI TOKEN ESTIMATE" in captured.out
    assert "Provider: Gemini" in captured.out
    assert "No API request was made." in captured.out

