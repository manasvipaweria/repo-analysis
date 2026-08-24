import os
import json
import requests
from typing import Dict, Any, List
from .base import AIProvider

class OpenAIProvider(AIProvider):
    def __init__(self):
        self.api_key = os.environ.get("AI_API_KEY")
        self.api_url = os.environ.get("AI_API_URL", "https://api.openai.com/v1/chat/completions")
        self.model = os.environ.get("AI_MODEL", "gpt-4-turbo-preview")

    def analyze(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "SKIPPED", "error_message": "AI credentials missing (AI_API_KEY not set)."}

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": skill_content},
                {"role": "user", "content": json.dumps({"findings": findings}, indent=2)}
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=60)
            response.raise_for_status()
            
            result_json = response.json()
            content = result_json["choices"][0]["message"]["content"]
            ai_results = json.loads(content).get("results", [])
            
            usage = result_json.get("usage", {})
            parsed_usage = {
                "input_tokens": usage.get("prompt_tokens"),
                "output_tokens": usage.get("completion_tokens"),
                "total_tokens": usage.get("total_tokens")
            } if usage else {"available": False}
            
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
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "ERROR", "error_message": f"Malformed AI response: {e}"}

    def estimate_tokens(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        # Very rough fallback character-based heuristic
        skill_tokens = len(skill_content) // 4
        finding_tokens = len(json.dumps(findings)) // 4
        
        return {
            "provider": "OpenAI",
            "model": self.model,
            "skill_tokens": skill_tokens,
            "finding_tokens": finding_tokens,
            "estimated_input": skill_tokens + finding_tokens,
            "max_output": max_tokens,
            "estimated_total": skill_tokens + finding_tokens + max_tokens
        }
