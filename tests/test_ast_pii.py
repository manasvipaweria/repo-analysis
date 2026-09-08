import os
import json
import subprocess

def test_ast_pii_boundaries(tmp_path):
    js_code = """
    const test1 = { ssn: 123 };
    const test2 = { userSsn: 456 };
    const test3 = { socialSecurityNumber: 789 };
    const test4 = { className: "btn" };
    const test5 = { assignment: "math" };
    const test6 = { session: "123" };
    const test7 = { emailAddress: "test@test.com" };
    """
    js_file = tmp_path / "test_pii.js"
    js_file.write_text(js_code)
    
    script_path = os.path.join(os.path.dirname(__file__), "..", "src", "compliance", "js_ast_extractor.js")
    result = subprocess.run(["node", script_path, str(js_file)], capture_output=True, text=True)
    
    data = json.loads(result.stdout)
    fields = [f["field"] for f in data.get("pii_fields", [])]
    
    assert "ssn" in fields
    assert "userSsn" in fields
    assert "socialSecurityNumber" in fields
    assert "emailAddress" in fields
    
    assert "className" not in fields
    assert "assignment" not in fields
    assert "session" not in fields
