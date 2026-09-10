import os
import pytest
from src.core.orchestrator import Orchestrator
from src.core.models import ComplianceFindingType, Category

def test_twilio_wrapper_flow(tmp_path):
    code = """
    const twilio = require('twilio');
    const client = twilio('ACCOUNT', 'TOKEN');
    
    function sendWrapper(toPhone) {
        client.messages.create({ to: toPhone });
    }
    
    sendWrapper(user.phone);
    """
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    risk = [f for f in report.findings if f.rule_id == "third-party-transfer"]
    assert len(risk) > 0, "Wrapper flow should be detected"

def test_unrelated_twilio_import(tmp_path):
    code = """
    const twilio = require('twilio');
    function someOtherFunc(phone) {
        console.log(phone);
    }
    someOtherFunc(user.phone);
    """
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    risk = [f for f in report.findings if f.rule_id == "third-party-transfer"]
    assert len(risk) == 0, "Unrelated import should not trigger third-party transfer"

def test_consent_human_review(tmp_path):
    code = "function C() { return <input type='checkbox' defaultChecked />; }"
    js = tmp_path / "App.jsx"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    hr = [f for f in report.findings if f.rule_id == "human-review-consent"]
    assert len(hr) > 0

def test_report_categories(tmp_path):
    code = "const user = { phone: '123' };"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    
    # GDPR should be PRIVACY category
    pii = [f for f in report.findings if f.rule_id == "personal-data-field-detected"]
    assert len(pii) > 0
    assert pii[0].category == Category.PRIVACY.value

def test_human_review_dedup(tmp_path):
    code = """
    const twilio = require('twilio');
    twilio.send({ phone: '123' });
    twilio.send({ phone: '456' });
    twilio.send({ phone: '789' });
    """
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    hr = [f for f in report.findings if f.rule_id == "human-review-processor"]
    assert len(hr) == 1, "Should deduplicate human review for same processor"

def test_data_flow_storage_edge(tmp_path):
    code = "const mongoose = require('mongoose'); new mongoose.Schema({ phone: { type: String } });"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    
    # Check data flow output directly
    db_dests = report.data_flow.get("db_destinations", [])
    assert len(db_dests) > 0
    assert db_dests[0]["field"] == "phone"
    assert db_dests[0]["destination"] == "MongoDB"

def test_dakiya_twilio_multi_function_flow(tmp_path):
    code = """
    const twilio = require('twilio');

    const sendOne = async (recipient, phone, message) => {
        return client.messages.create({
            body: message,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: formatForSMS(phone)
        });
    };

    const sendMessageToRecipients = async (recipients, message) => {
        const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
        for (const r of recipients) {
            const phone = r.phone;
            await sendOne(r, phone, message);
        }
    };
    """
    js = tmp_path / "twilio.js"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    third_party = [f for f in report.findings if f.rule_id == "third-party-transfer"]
    assert len(third_party) == 1, f"Expected exactly 1 third-party-transfer finding, got {len(third_party)}"
    finding = third_party[0]
    assert "twilio" in finding.description
    assert "phone" in finding.description

def test_twilio_static_non_pii_negative(tmp_path):
    code = """
    const twilio = require('twilio');
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

    async function sendAlert() {
        await client.messages.create({
            body: "System reboot status OK",
            from: "+15550001111",
            to: "+15550002222"
        });
    }
    """
    js = tmp_path / "alert.js"
    js.write_text(code, encoding="utf-8")
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))
    third_party = [f for f in report.findings if f.rule_id == "third-party-transfer"]
    assert len(third_party) == 0, f"Expected 0 third-party-transfer findings for static non-PII, got {len(third_party)}"

