import os
import json
from src.compliance.gdpr_mapping import get_gdpr_articles_for_rule
from src.compliance.data_flow import extract_data_flow

def test_gdpr_mapping():
    # Test deterministic check matching
    articles = get_gdpr_articles_for_rule("excessive-pii-fields")
    assert "Art. 5(1)(c)" in articles
    
    # Test existing rule wildcard mapping
    articles = get_gdpr_articles_for_rule("semgrep/detect-eval")
    assert "Art. 32" in articles
    
    # Test specific deslint mapping
    articles = get_gdpr_articles_for_rule("deslint/no-default-checked")
    assert "Art. 7" in articles

def test_data_flow_extraction(tmp_path):
    # Create a dummy js file with fetch, defaultChecked, and PII
    dummy_js = tmp_path / "App.jsx"
    dummy_js.write_text('''
        import React from "react";
        const model = { email: "test@example.com", ssn: "123" };
        function handleSave() {
            fetch("https://analytics.thirdparty.com/track");
        }
        export default function App() {
            return <input type="checkbox" defaultChecked={true} />;
        }
    ''', encoding="utf-8")
    
    # Run the extractor
    flow_data = extract_data_flow(str(tmp_path))
    
    # Assert outbound domains extracted
    assert "https://analytics.thirdparty.com/track" in flow_data["outbound_domains"]
    
    # Assert PII fields detected
    fields = [p["field"] for p in flow_data["pii_fields"]]
    assert "email" in fields
    assert "ssn" in fields
    assert "defaultChecked_checkbox" in fields
