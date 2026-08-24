from abc import ABC, abstractmethod
from typing import Dict, Any, List

class AIProvider(ABC):
    @abstractmethod
    def analyze(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        """
        Analyze findings using the AI skill.
        Must return a dict:
        {
            "status": "COMPLETED" | "SKIPPED" | "ERROR",
            "error_message": "...", (if error)
            "results": [ ... list of dicts mapping to ai_fields ... ],
            "usage": { "input_tokens": x, "output_tokens": y, "total_tokens": z } or { "available": False }
        }
        """
        pass

    @abstractmethod
    def estimate_tokens(self, findings: List[Dict[str, Any]], skill_content: str, max_tokens: int) -> Dict[str, Any]:
        """
        Estimate tokens locally without making an API call.
        Returns:
        {
            "provider": str,
            "model": str,
            "skill_tokens": int,
            "finding_tokens": int,
            "estimated_input": int,
            "max_output": int,
            "estimated_total": int
        }
        """
        pass
