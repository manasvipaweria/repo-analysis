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
        self.max_tokens = int(os.environ.get("AI_MAX_OUTPUT_TOKENS", "1000"))
        
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
            
        skill_path = os.path.join(os.path.dirname(__file__), "skills", "ai_analysis_v1.txt")
        if not os.path.exists(skill_path):
            return {"status": "ERROR", "error_message": "AI skill file not found."}
            
        with open(skill_path, 'r', encoding='utf-8') as f:
            skill_content = f.read()
            
        if estimate_only:
            # Estimate on the whole set, or just sum it up
            estimation = self.provider.estimate_tokens(findings, skill_content, self.max_tokens)
            print("\nAI TOKEN ESTIMATE")
            print("-----------------")
            print(f"Provider: {estimation['provider']}")
            print(f"Model: {estimation['model']}")
            print(f"Findings: {len(findings)}\n")
            print(f"Skill/instruction tokens: ~{estimation['skill_tokens']}")
            print(f"Finding/input tokens: ~{estimation['finding_tokens']}")
            print(f"Estimated input tokens: ~{estimation['estimated_input']}")
            print(f"Configured max output tokens: {estimation['max_output']}")
            print(f"Estimated maximum token budget: ~{estimation['estimated_total']}\n")
            print("No API request was made.")
            print("No API quota was consumed.")
            return {"status": "COMPLETED"}
            
        import math
        total_findings = len(findings)
        total_steps = math.ceil(total_findings / self.batch_size)
        
        cumulative_usage = {
            "input_tokens": 0,
            "cached_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0
        }
        
        all_ai_results = []
        steps_completed = 0
        final_status = "COMPLETED"
        error_message = None

        print(f"\nAI ANALYSIS")
        
        for step in range(total_steps):
            start_idx = step * self.batch_size
            end_idx = start_idx + self.batch_size
            chunk = findings[start_idx:end_idx]
            
            response = self.provider.analyze(chunk, skill_content, self.max_tokens)
            
            usage = response.get("usage", {})
            new_input = usage.get("input_tokens", 0) or 0
            cached = usage.get("cached_tokens", 0) or 0
            output_tok = usage.get("output_tokens", 0) or 0
            total_tok = usage.get("total_tokens", 0) or 0
            
            cumulative_usage["input_tokens"] += new_input
            cumulative_usage["cached_tokens"] += cached
            cumulative_usage["output_tokens"] += output_tok
            cumulative_usage["total_tokens"] += total_tok
            
            steps_completed += 1
            
            print(f"[AI] Step {steps_completed}/{total_steps}")
            print(f"[AI] Findings in step: {len(chunk)}")
            print(f"[AI] New input tokens: {new_input}")
            print(f"[AI] Cached input tokens: {cached}")
            print(f"[AI] Output tokens: {output_tok}")
            print(f"[AI] Total tokens: {total_tok}")
            print(f"[AI] Cumulative total tokens: {cumulative_usage['total_tokens']}\n")

            if response["status"] != "COMPLETED":
                # Check for quota or limits
                err_str = str(response.get("error_message", "")).lower()
                if "429" in err_str or "quota" in err_str or "rate limit" in err_str:
                    final_status = "QUOTA_LIMIT_REACHED"
                else:
                    final_status = "ERROR"
                error_message = response.get("error_message")
                print(f"[AI] Error: {error_message}")
                if "raw_response" in response:
                    print(f"[AI] Raw Response Snippet: {repr(response['raw_response'])[:200]}")
                break
                
            all_ai_results.extend(response.get("results", []))

        print(f"AI ANALYSIS USAGE")
        print(f"-----------------")
        print(f"Steps completed: {steps_completed}/{total_steps}")
        print(f"Findings analyzed: {len(all_ai_results)}/{total_findings}")
        print(f"New input tokens: {cumulative_usage['input_tokens']}")
        print(f"Cached input tokens: {cumulative_usage['cached_tokens']}")
        print(f"Output tokens: {cumulative_usage['output_tokens']}")
        print(f"Total tokens: {cumulative_usage['total_tokens']}")
        print(f"Remaining findings: {total_findings - len(all_ai_results)}")
        if final_status != "COMPLETED":
            print(f"Status: {final_status}")

        # Map back to report.json regardless of completion status to save partial progress
        if not os.path.exists(report_file):
            return {"status": "ERROR", "error_message": f"Original report {report_file} not found."}
            
        with open(report_file, 'r', encoding='utf-8') as f:
            full_report = json.load(f)
            
        finding_map = {f["finding_id"]: f for f in full_report.get("findings", [])}
        
        success_count = 0
        for ai_res in all_ai_results:
            fid = ai_res.get("finding_id")
            if fid and fid in finding_map:
                finding_map[fid]["ai_fields"] = {
                    "analysis_summary": ai_res.get("analysis_summary"),
                    "security_impact": ai_res.get("security_impact"),
                    "remediation_suggestion": ai_res.get("remediation_suggestion"),
                    "is_false_positive_prediction": ai_res.get("is_false_positive_prediction")
                }
                success_count += 1
                
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=2)
            
        result = {
            "status": final_status, 
            "selected": total_findings, 
            "analyzed": success_count,
            "rejected": len(all_ai_results) - success_count,
            "usage": cumulative_usage
        }
        
        if error_message:
            result["error_message"] = error_message
            
        return result

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
