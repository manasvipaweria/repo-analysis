from typing import Dict, Any, List
from .base import AIProvider
import json

class MockAIProvider(AIProvider):
    def analyze(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        results = []
        for f in findings:
            results.append({
                "finding_id": f.get("finding_id"),
                "analysis_summary": f"[MOCK AI] Mock summary for {f.get('finding_id')}",
                "remediation_suggestion": "[MOCK AI] Mock remediation",
                "is_false_positive_prediction": False
            })
            
        return {
            "status": "COMPLETED",
            "results": results,
            "usage": {
                "input_tokens": len(skill_content) // 4 + len(json.dumps(findings)) // 4,
                "output_tokens": 50,
                "total_tokens": (len(skill_content) // 4 + len(json.dumps(findings)) // 4) + 50
            }
        }

    def estimate_tokens(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        skill_tokens = len(skill_content) // 4
        finding_tokens = len(json.dumps(findings)) // 4
        
        return {
            "provider": "Mock",
            "model": "mock-model",
            "skill_tokens": skill_tokens,
            "finding_tokens": finding_tokens,
            "estimated_input": skill_tokens + finding_tokens,
            "max_output": max_tokens,
            "estimated_total": skill_tokens + finding_tokens + max_tokens
        }
