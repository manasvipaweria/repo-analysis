import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.ai.ai_adapter import AIAdapter
from src.ai.providers.gemini_provider import GeminiProvider

def test_a_one_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {"findings": [{"finding_id": "f1"}]}
    ai_input.write_text(json.dumps(ai_data))
    
    report_data = {"findings": [{"finding_id": "f1"}]}
    report_file.write_text(json.dumps(report_data))
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "COMPLETED"
    assert result["analyzed"] == 1

@patch("src.ai.providers.mock.MockAIProvider.analyze")
def test_b_multiple_findings_batch_size_1(mock_analyze, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    monkeypatch.setenv("AI_BATCH_SIZE", "1")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    findings = [{"finding_id": f"f{i}"} for i in range(1, 6)]
    ai_input.write_text(json.dumps({"findings": findings}))
    report_file.write_text(json.dumps({"findings": findings}))
    
    def mock_analyze_side_effect(chunk, skill_content, max_tokens):
        f = chunk[0]
        return {
            "status": "COMPLETED",
            "results": [
                {
                    "finding_id": f["finding_id"],
                    "analysis_summary": "ok",
                    "remediation_suggestion": "fix",
                    "is_false_positive_prediction": False,
                    "security_impact": "high"
                }
            ],
            "usage": {"input_tokens": 10, "cached_tokens": 5, "output_tokens": 20, "total_tokens": 35}
        }
    
    mock_analyze.side_effect = mock_analyze_side_effect
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "COMPLETED"
    assert result["selected"] == 5
    assert result["analyzed"] == 5
    assert mock_analyze.call_count == 5
    
    assert result["usage"]["input_tokens"] == 50
    assert result["usage"]["cached_tokens"] == 25
    assert result["usage"]["output_tokens"] == 100
    assert result["usage"]["total_tokens"] == 175


@patch("src.ai.providers.mock.MockAIProvider.analyze")
def test_c_multiple_findings_batch_size_2(mock_analyze, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    monkeypatch.setenv("AI_BATCH_SIZE", "2")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    findings = [{"finding_id": f"f{i}"} for i in range(1, 6)]
    ai_input.write_text(json.dumps({"findings": findings}))
    report_file.write_text(json.dumps({"findings": findings}))
    
    def mock_analyze_side_effect(chunk, skill_content, max_tokens):
        return {
            "status": "COMPLETED",
            "results": [{"finding_id": f["finding_id"]} for f in chunk],
            "usage": {"input_tokens": 10, "cached_tokens": 0, "output_tokens": 20, "total_tokens": 30}
        }
    
    mock_analyze.side_effect = mock_analyze_side_effect
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "COMPLETED"
    assert result["selected"] == 5
    assert result["analyzed"] == 5
    assert mock_analyze.call_count == 3


@patch("src.ai.providers.mock.MockAIProvider.analyze")
def test_d_and_e_simulated_quota_failure(mock_analyze, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    monkeypatch.setenv("AI_BATCH_SIZE", "1")
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    findings = [{"finding_id": f"f{i}"} for i in range(1, 6)]
    ai_input.write_text(json.dumps({"findings": findings}))
    report_file.write_text(json.dumps({"findings": findings}))
    
    call_counts = {"count": 0}
    def mock_analyze_side_effect(chunk, skill_content, max_tokens):
        call_counts["count"] += 1
        if call_counts["count"] == 3:
            return {
                "status": "ERROR",
                "error_message": "429 Quota Exceeded",
                "usage": {"input_tokens": 0, "cached_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            }
            
        f = chunk[0]
        return {
            "status": "COMPLETED",
            "results": [
                {
                    "finding_id": f["finding_id"],
                    "analysis_summary": "ok",
                }
            ],
            "usage": {"input_tokens": 10, "cached_tokens": 5, "output_tokens": 20, "total_tokens": 35}
        }
    
    mock_analyze.side_effect = mock_analyze_side_effect
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "QUOTA_LIMIT_REACHED"
    assert result["selected"] == 5
    assert result["analyzed"] == 2
    assert result["rejected"] == 0
    assert mock_analyze.call_count == 3
    
    with open(str(report_file), 'r') as f:
        updated_report = json.load(f)
    
    f1 = next(f for f in updated_report["findings"] if f["finding_id"] == "f1")
    f2 = next(f for f in updated_report["findings"] if f["finding_id"] == "f2")
    f3 = next(f for f in updated_report["findings"] if f["finding_id"] == "f3")
    
    assert "ai_fields" in f1
    assert "ai_fields" in f2
    assert "ai_fields" not in f3


def test_gemini_missing_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    
    ai_input = tmp_path / "ai_input.json"
    report_file = tmp_path / "report.json"
    
    ai_data = {
        "findings": [{"finding_id": "f1"}]
    }
    ai_input.write_text(json.dumps(ai_data))
    report_file.write_text(json.dumps({"findings": []}))
    
    adapter = AIAdapter()
    result = adapter.run(str(ai_input), str(report_file))
    
    assert result["status"] == "ERROR"
    assert "GEMINI_API_KEY not set" in result["error_message"]


@patch("src.ai.providers.gemini_provider.requests.post")
def test_f_invalid_json(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Not JSON at all"}]
                }
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 10,
            "cachedContentTokenCount": 5,
            "candidatesTokenCount": 20,
            "totalTokenCount": 35
        }
    }
    mock_post.return_value = mock_resp
    
    provider = GeminiProvider()
    response = provider.analyze([{"finding_id": "f1"}], "skill", 1000)
    
    assert response["status"] == "ERROR"
    assert "invalid JSON" in response["error_message"]
    assert response["raw_response"] == "Not JSON at all"
    assert response["usage"]["input_tokens"] == 10
    assert response["usage"]["cached_tokens"] == 5
    assert response["usage"]["total_tokens"] == 35


@patch("src.ai.providers.gemini_provider.requests.post")
def test_g_empty_candidates_and_parts(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    
    # Test Empty Parts
    mock_resp_parts = MagicMock()
    mock_resp_parts.json.return_value = {
        "candidates": [
            {
                "finishReason": "SAFETY",
                "content": {"parts": []}
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 10,
            "totalTokenCount": 10
        }
    }
    mock_post.return_value = mock_resp_parts
    
    provider = GeminiProvider()
    response_parts = provider.analyze([{"finding_id": "f1"}], "skill", 1000)
    
    assert response_parts["status"] == "ERROR"
    assert response_parts["error_message"] == "Gemini returned empty parts."
    assert response_parts["finish_reason"] == "SAFETY"
    assert response_parts["usage"]["input_tokens"] == 10

    # Test No Candidates
    mock_resp_cands = MagicMock()
    mock_resp_cands.json.return_value = {
        "candidates": [],
        "usageMetadata": {
            "promptTokenCount": 10,
            "totalTokenCount": 10
        }
    }
    mock_post.return_value = mock_resp_cands
    
    response_cands = provider.analyze([{"finding_id": "f1"}], "skill", 1000)
    
    assert response_cands["status"] == "ERROR"
    assert response_cands["error_message"] == "Gemini returned no candidates."
    assert "debug_response" in response_cands


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

import requests

@patch("src.ai.providers.gemini_provider.time.sleep")
@patch("src.ai.providers.gemini_provider.requests.post")
def test_h_gemini_retry_503_success(mock_post, mock_sleep, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    
    # 1st call: 503
    mock_503 = MagicMock()
    mock_503.raise_for_status.side_effect = requests.exceptions.HTTPError(response=MagicMock(status_code=503))
    mock_503.status_code = 503
    
    # 2nd call: success
    mock_success = MagicMock()
    mock_success.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": '{"results": [{"finding_id": "f1"}]}'}]}}]
    }
    mock_success.raise_for_status.return_value = None
    
    mock_post.side_effect = [mock_503, mock_success]
    
    provider = GeminiProvider()
    response = provider.analyze([{"finding_id": "f1"}], "skill", 1000)
    
    assert response["status"] == "COMPLETED"
    assert response["results"][0]["finding_id"] == "f1"
    assert mock_post.call_count == 2
    mock_sleep.assert_called_once_with(2.0) # base_delay * 2^0


@patch("src.ai.providers.gemini_provider.time.sleep")
@patch("src.ai.providers.gemini_provider.requests.post")
def test_i_gemini_retry_429_success(mock_post, mock_sleep, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    
    mock_429 = MagicMock()
    mock_429.raise_for_status.side_effect = requests.exceptions.HTTPError(response=MagicMock(status_code=429))
    mock_429.status_code = 429
    
    mock_success = MagicMock()
    mock_success.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": '{"results": [{"finding_id": "f1"}]}'}]}}]
    }
    mock_success.raise_for_status.return_value = None
    
    mock_post.side_effect = [mock_429, mock_429, mock_success]
    
    provider = GeminiProvider()
    response = provider.analyze([{"finding_id": "f1"}], "skill", 1000)
    
    assert response["status"] == "COMPLETED"
    assert mock_post.call_count == 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(2.0)
    mock_sleep.assert_any_call(4.0)


@patch("src.ai.providers.gemini_provider.time.sleep")
@patch("src.ai.providers.gemini_provider.requests.post")
def test_j_gemini_retry_503_exhausted(mock_post, mock_sleep, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy")
    
    mock_error_resp = MagicMock()
    mock_error_resp.status_code = 503
    mock_error_resp.json.return_value = {"error": {"message": "Service Unavailable"}}
    mock_error_resp.text = '{"error": {"message": "Service Unavailable"}}'
    
    mock_503 = MagicMock()
    mock_503.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_error_resp)
    mock_503.status_code = 503
    
    # 4 calls total: 1 initial + 3 retries
    mock_post.side_effect = [mock_503, mock_503, mock_503, mock_503]
    
    provider = GeminiProvider()
    response = provider.analyze([{"finding_id": "f1"}], "skill", 1000)
    
    assert response["status"] == "ERROR"
    assert "AI API request failed (HTTP 503): Service Unavailable" in response["error_message"]
    assert mock_post.call_count == 4
    assert mock_sleep.call_count == 3
