import os
from src.core.orchestrator import Orchestrator
from src.core.models import ComplianceFindingType
from src.compliance.suppression import save_suppression, get_suppression_file, generate_suppression_key

def test_inventory_default(tmp_path):
    # Just a PII field
    code = "const user = { phone: '123' }; console.log(user.phone);"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    
    # Should be an inventory finding
    pii = [f for f in report.findings if f.rule_id == "personal-data-field-detected"]
    assert len(pii) > 0
    assert pii[0].compliance_finding_type == ComplianceFindingType.INVENTORY
    # old mapping applies gdpr_references down the line
    assert "Art. 5(1)(c)" in pii[0].gdpr_references

def test_minimisation_dead_field(tmp_path):
    # Destructured PII never used
    code = "const { phone } = req.body;"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    
    dead = [f for f in report.findings if f.rule_id == "unused-personal-data"]
    assert len(dead) > 0
    assert dead[0].compliance_finding_type == ComplianceFindingType.MINIMISATION_FLAG

def test_third_party_risk(tmp_path):
    code = "const twilio = require('twilio'); twilio.send({ phone: '123' });"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    
    risk = [f for f in report.findings if f.rule_id == "third-party-transfer"]
    assert len(risk) > 0
    assert risk[0].compliance_finding_type == ComplianceFindingType.THIRD_PARTY_RISK

def test_unprotected_storage(tmp_path):
    code = "const mongoose = require('mongoose'); new mongoose.Schema({ phone: { type: String } });"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    
    storage = [f for f in report.findings if f.rule_id == "unprotected-pii-storage"]
    assert len(storage) > 0
    assert storage[0].compliance_finding_type == ComplianceFindingType.SECURITY_GAP

def test_suppression(tmp_path):
    code = "const user = { phone: '123' }; console.log(user.phone);"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    
    # First run without suppression
    orc = Orchestrator([])
    report1 = orc.analyze("local", str(tmp_path))
    
    pii = [f for f in report1.findings if f.rule_id == "personal-data-field-detected"]
    assert len(pii) == 1
    
    # Save suppression
    save_suppression(str(tmp_path), generate_suppression_key(pii[0]))
    
    # Run again
    report2 = orc.analyze("local", str(tmp_path))
    pii2 = [f for f in report2.findings if f.rule_id == "personal-data-field-detected"]
    assert len(pii2) == 0
