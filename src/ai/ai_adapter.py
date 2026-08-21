import os
import json
import requests
from typing import Dict, Any

class AIAdapter:
    def __init__(self):
        self.api_key = os.environ.get("AI_API_KEY")
        self.api_url = os.environ.get("AI_API_URL", "https://api.openai.com/v1/chat/completions")
        self.model = os.environ.get("AI_MODEL", "gpt-4-turbo-preview")
        self.batch_size = int(os.environ.get("AI_BATCH_SIZE", "5"))
        
    def run(self, ai_input_file: str, report_file: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "SKIPPED", "error_message": "AI credentials missing (AI_API_KEY not set)."}
            
        if not os.path.exists(ai_input_file):
            return {"status": "ERROR", "error_message": f"AI input file {ai_input_file} not found."}
            
        with open(ai_input_file, 'r', encoding='utf-8') as f:
            try:
                ai_data = json.load(f)
            except json.JSONDecodeError:
                return {"status": "ERROR", "error_message": "Invalid JSON in AI input file."}
                
        findings = ai_data.get("findings", [])
        if not findings:
            return {"status": "COMPLETED", "message": "No findings to analyze.", "analyzed": 0}
            
        findings_to_analyze = findings[:self.batch_size]
        
        skill_path = os.path.join(os.path.dirname(__file__), "skills", "ai_analysis_v1.txt")
        if not os.path.exists(skill_path):
            return {"status": "ERROR", "error_message": "AI skill file not found."}
            
        with open(skill_path, 'r', encoding='utf-8') as f:
            skill_content = f.read()
            
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": skill_content},
                {"role": "user", "content": json.dumps({"findings": findings_to_analyze}, indent=2)}
            ],
            "response_format": {"type": "json_object"}
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(self.api_url, json=payload, headers=headers)
            response.raise_for_status()
            
            result_json = response.json()
            content = result_json["choices"][0]["message"]["content"]
            ai_results = json.loads(content).get("results", [])
        except requests.exceptions.RequestException as e:
            return {"status": "ERROR", "error_message": f"AI API request failed: {e}"}
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "ERROR", "error_message": f"Malformed AI response: {e}"}
            
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
            "rejected": len(findings_to_analyze) - success_count
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python ai_adapter.py <ai_input.json> <report.json>")
        sys.exit(1)
        
    adapter = AIAdapter()
    result = adapter.run(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=2))
