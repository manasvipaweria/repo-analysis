import os
import json
import requests
from typing import Dict, Any, List
from .base import AIProvider

class GeminiProvider(AIProvider):
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        # Ensure we default to a model that supports JSON mode and system instructions
        self.model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
        
    def _build_url(self):
        return f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

    def analyze(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "SKIPPED", "error_message": "AI credentials missing (GEMINI_API_KEY not set)."}

        payload = {
            "system_instruction": {
                "parts": [{"text": skill_content}]
            },
            "contents": [
                {
                    "parts": [{"text": json.dumps({"findings": findings}, indent=2)}]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "maxOutputTokens": max_tokens
            }
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(self._build_url(), json=payload, headers=headers, timeout=60)
            response.raise_for_status()
            
            result_json = response.json()
            
            usage = result_json.get("usageMetadata", {})
            parsed_usage = {
                "input_tokens": usage.get("promptTokenCount"),
                "output_tokens": usage.get("candidatesTokenCount"),
                "cached_tokens": usage.get("cachedContentTokenCount", 0),
                "total_tokens": usage.get("totalTokenCount")
            } if usage else {"available": False}
            
            candidates = result_json.get("candidates", [])
            if not candidates:
                return {
                    "status": "ERROR", 
                    "error_message": "Gemini returned no candidates.",
                    "debug_response": result_json,
                    "usage": parsed_usage
                }
                
            content_parts = candidates[0].get("content", {}).get("parts", [])
            if not content_parts:
                return {
                    "status": "ERROR", 
                    "error_message": "Gemini returned empty parts.",
                    "finish_reason": candidates[0].get("finishReason"),
                    "debug_candidate": candidates[0],
                    "usage": parsed_usage
                }
                
            text_content = content_parts[0].get("text", "")
            
            try:
                ai_results = json.loads(text_content).get("results", [])
            except json.JSONDecodeError as e:
                return {
                    "status": "ERROR", 
                    "error_message": f"Gemini returned invalid JSON: {e}",
                    "raw_response": text_content,
                    "usage": parsed_usage
                }
                
            return {
                "status": "COMPLETED",
                "results": ai_results,
                "usage": parsed_usage
            }
            
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            try:
                error_body = e.response.json()
                provider_msg = error_body.get("error", {}).get("message", e.response.text)
            except Exception:
                provider_msg = e.response.text
                
            return {"status": "ERROR", "error_message": f"AI API request failed (HTTP {status_code}): {provider_msg}"}
        except requests.exceptions.RequestException as e:
            return {"status": "ERROR", "error_message": f"AI API request failed: {e}"}
        except KeyError as e:
            return {"status": "ERROR", "error_message": f"Malformed AI response: {e}"}

    def estimate_tokens(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        # Approximate heuristic for Gemini if google-generativeai isn't available
        # It's an estimate, as strictly requested in Section 6.
        skill_tokens = len(skill_content) // 4
        finding_tokens = len(json.dumps(findings)) // 4
        
        return {
            "provider": "Gemini",
            "model": self.model,
            "skill_tokens": skill_tokens,
            "finding_tokens": finding_tokens,
            "estimated_input": skill_tokens + finding_tokens,
            "max_output": max_tokens,
            "estimated_total": skill_tokens + finding_tokens + max_tokens
        }
