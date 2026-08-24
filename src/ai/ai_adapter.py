import os
import json
import argparse
from typing import Dict, Any

from .providers.mock import MockAIProvider
from .providers.openai_provider import OpenAIProvider
from .providers.gemini_provider import GeminiProvider

class AIAdapter:
    def __init__(self):
        self.provider_name = os.environ.get("AI_PROVIDER", "openai").lower()
        self.batch_size = int(os.environ.get("AI_BATCH_SIZE", "5"))
        self.max_tokens = int(os.environ.get("AI_MAX_OUTPUT_TOKENS", "500"))
        
        if self.provider_name == "mock":
            self.provider = MockAIProvider()
        elif self.provider_name == "gemini":
            self.provider = GeminiProvider()
        else:
            self.provider = OpenAIProvider()
            
    def run(self, ai_input_file: str, report_file: str, estimate_only: bool = False) -> Dict[str, Any]:
        if not os.path.exists(ai_input_file):
            return {"status": "ERROR", "error_message": f"AI input file {ai_input_file} not found."}
            
        with open(ai_input_file, 'r', encoding='utf-8') as f:
            try:
                ai_data = json.load(f)
            except json.JSONDecodeError:
                return {"status": "ERROR", "error_message": "Invalid JSON in AI input file."}
                
        findings = ai_data.get("findings", [])
        if not findings:
            if estimate_only:
                print("No findings to estimate.")
                return {"status": "COMPLETED"}
            return {"status": "COMPLETED", "message": "No findings to analyze.", "analyzed": 0}
            
        findings_to_analyze = findings[:self.batch_size]
        
        skill_path = os.path.join(os.path.dirname(__file__), "skills", "ai_analysis_v1.txt")
        if not os.path.exists(skill_path):
            return {"status": "ERROR", "error_message": "AI skill file not found."}
            
        with open(skill_path, 'r', encoding='utf-8') as f:
            skill_content = f.read()
            
        if estimate_only:
            estimation = self.provider.estimate_tokens(findings_to_analyze, skill_content, self.max_tokens)
            print("\nAI TOKEN ESTIMATE")
            print("-----------------")
            print(f"Provider: {estimation['provider']}")
            print(f"Model: {estimation['model']}")
            print(f"Findings: {len(findings_to_analyze)}\n")
            print(f"Skill/instruction tokens: ~{estimation['skill_tokens']}")
            print(f"Finding/input tokens: ~{estimation['finding_tokens']}")
            print(f"Estimated input tokens: ~{estimation['estimated_input']}")
            print(f"Configured max output tokens: {estimation['max_output']}")
            print(f"Estimated maximum token budget: ~{estimation['estimated_total']}\n")
            print("No API request was made.")
            print("No API quota was consumed.")
            return {"status": "COMPLETED"}
            
        response = self.provider.analyze(findings_to_analyze, skill_content, self.max_tokens)
        
        if response["status"] != "COMPLETED":
            return response
            
        ai_results = response.get("results", [])
        
        # Map back to report.json
        if not os.path.exists(report_file):
            return {"status": "ERROR", "error_message": f"Original report {report_file} not found."}
            
        with open(report_file, 'r', encoding='utf-8') as f:
            full_report = json.load(f)
            
        finding_map = {f["finding_id"]: f for f in full_report.get("findings", [])}
        
        success_count = 0
        for ai_res in ai_results:
            fid = ai_res.get("finding_id")
            if fid and fid in finding_map:
                finding_map[fid]["ai_fields"] = {
                    "analysis_summary": ai_res.get("analysis_summary"),
                    "remediation_suggestion": ai_res.get("remediation_suggestion"),
                    "is_false_positive_prediction": ai_res.get("is_false_positive_prediction")
                }
                success_count += 1
                
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=2)
            
        return {
            "status": "COMPLETED", 
            "selected": len(findings_to_analyze), 
            "analyzed": success_count,
            "rejected": len(findings_to_analyze) - success_count,
            "usage": response.get("usage", {"available": False})
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ai_input", help="Path to ai_input.json")
    parser.add_argument("report", help="Path to report.json")
    parser.add_argument("--estimate-tokens", action="store_true", help="Estimate tokens without API call")
    args = parser.parse_args()
    
    adapter = AIAdapter()
    result = adapter.run(args.ai_input, args.report, estimate_only=args.estimate_tokens)
    if not args.estimate_tokens:
        print(json.dumps(result, indent=2))
