import os
import json
import pytest
from src.core.orchestrator import Orchestrator
from src.core.models import Finding, Report, Category, ComplianceFindingType
from src.compliance.dpdp_constants import get_dpdp_tier_info, get_dpdp_restricted_countries_config
from src.compliance.dpdp_basis import evaluate_dpdp_processing_basis
from src.compliance.dpdp_engine import run_dpdp_checks

# -----------------------------------------------------------------------------
# A. Tiering & Section-Level Effective Dates Tests
# -----------------------------------------------------------------------------
def test_dpdp_tiering_effective_dates():
    status_6_9, date_6_9 = get_dpdp_tier_info("6(9)")
    assert status_6_9 == "FUTURE_STATE"
    assert date_6_9 == "2026-11-13"

    status_6_1, date_6_1 = get_dpdp_tier_info("6(1)")
    assert status_6_1 == "FUTURE_STATE"
    assert date_6_1 == "2027-05-13"

    status_8_5, date_8_5 = get_dpdp_tier_info("8(5)")
    assert status_8_5 == "FUTURE_STATE"
    assert date_8_5 == "2027-05-13"

    status_16, date_16 = get_dpdp_tier_info("16")
    assert status_16 == "FUTURE_STATE"
    assert date_16 == "2027-05-13"

# -----------------------------------------------------------------------------
# B. Lawful Basis Isolation & Closed §7 Evaluation Tests
# -----------------------------------------------------------------------------
def test_dpdp_7_does_not_use_gdpr_legitimate_interest():
    """Verify DPDP §7 does NOT inherit GDPR open-ended legitimate interest logic."""
    context = {
        "purpose": "generic business need",
        "field": "email",
        "is_consent_flow": False
    }
    res = evaluate_dpdp_processing_basis(context)
    assert res["type"] == "unestablished"
    assert res["section"] is None
    assert res["subsection"] is None
    assert res["candidate_subsections"] == []
    assert res["human_review_required"] is True

def test_dpdp_7_closed_list_candidates():
    """Verify candidate §7 categories are identified for specific purposes."""
    # Transactional SMS / Voluntary disclosure -> 7(a)
    ctx_sms = {"purpose": "transactional order confirmation", "field": "phone", "processor": "twilio"}
    res_sms = evaluate_dpdp_processing_basis(ctx_sms)
    assert res_sms["type"] == "legitimate_use"
    assert "7(a)" in res_sms["candidate_subsections"]

    # Employee payroll -> 7(i)
    ctx_emp = {"purpose": "employee payroll processing", "field": "account_number"}
    res_emp = evaluate_dpdp_processing_basis(ctx_emp)
    assert res_emp["type"] == "legitimate_use"
    assert "7(i)" in res_emp["candidate_subsections"]

# -----------------------------------------------------------------------------
# C. Breach Notification Isolation Tests (§8(6))
# -----------------------------------------------------------------------------
def test_dpdp_8_6_does_not_use_gdpr_high_risk_threshold(tmp_path):
    """Verify DPDP §8(6) requires notification without GDPR high-risk threshold."""
    code = "const phone = user.phone;"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    breach_findings = [f for f in report.findings if f.rule_id == "dpdp-8-6-breach-notification"]
    assert len(breach_findings) == 1
    f = breach_findings[0]
    assert f.framework == "DPDP"
    assert f.section == "8(6)"
    assert f.evidence_status in ["INDETERMINATE", "DETECTED", "NOT_DETECTED"]
    assert "GDPR-style high-risk severity gate" in f.description or "Board" in f.description

def test_dpdp_8_6_detected_logging_evidence(tmp_path):
    """Verify DPDP §8(6) sets evidence_status='DETECTED' when logging tools are present."""
    code = "const phone = user.phone;"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    # Create mock adapter or finding to simulate logging detection
    from src.adapters.base import BaseAdapter
    from src.core.models import ToolResult, ToolStatus
    class MockLoggingAdapter(BaseAdapter):
        tool_name = "mock-logger"
        categories = [Category.ARCHITECTURE.value]
        def run(self, path):
            return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=[
                Finding(category=Category.ARCHITECTURE.value, severity="info", file="App.js", line=1, message="Logging detected", rule_id="winston-logging-detected")
            ])

    orc.adapters.append(MockLoggingAdapter())
    report = orc.analyze("local", str(tmp_path))

    breach_findings = [f for f in report.findings if f.rule_id == "dpdp-8-6-breach-notification"]
    assert len(breach_findings) == 1
    f = breach_findings[0]
    assert f.evidence_status == "DETECTED"

# -----------------------------------------------------------------------------
# D. Cross-Border Transfer Isolation Tests (§16)
# -----------------------------------------------------------------------------
def test_dpdp_16_does_not_use_gdpr_adequacy_list(tmp_path, monkeypatch):
    """Verify DPDP §16 blacklist model is independent of GDPR adequacy list."""
    monkeypatch.delenv("DPDP_RESTRICTED_COUNTRIES", raising=False)
    
    code = "const twilio = require('twilio'); client.messages.create({ to: phone });"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    # With default empty DPDP restricted list, must emit informational config state
    dpdp_16_info = [f for f in report.findings if f.rule_id == "dpdp-16-restricted-countries-config"]
    assert len(dpdp_16_info) == 1
    assert "No countries are currently configured as restricted" in dpdp_16_info[0].description
    assert dpdp_16_info[0].effective_status == "FUTURE_STATE"
    assert dpdp_16_info[0].effective_from == "2027-05-13"

def test_dpdp_16_configured_restricted_country(tmp_path, monkeypatch):
    """Verify configured DPDP restricted country produces a Section 16 finding."""
    monkeypatch.setenv("DPDP_RESTRICTED_COUNTRIES", "twilio")

    code = """
    const twilio = require('twilio');
    const client = twilio('ACC', 'TOKEN');
    client.messages.create({ to: phone });
    """
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    dpdp_16_findings = [f for f in report.findings if f.rule_id == "dpdp-16-restricted-country-transfer"]
    assert len(dpdp_16_findings) == 1
    f = dpdp_16_findings[0]
    assert f.framework == "DPDP"
    assert f.section == "16"
    assert f.effective_status == "FUTURE_STATE"
    assert f.evidence_status == "DETECTED"

# -----------------------------------------------------------------------------
# E. Significant Data Fiduciary Non-Computable Threshold (§10)
# -----------------------------------------------------------------------------
def test_dpdp_10_sdf_never_auto_labels(tmp_path):
    """Verify SDF status is never auto-labelled as true/false/NOT_SDF."""
    code = "const user = { phone: '123' };"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    sdf_findings = [f for f in report.findings if f.rule_id == "dpdp-10-significant-data-fiduciary"]
    assert len(sdf_findings) == 1
    f = sdf_findings[0]
    assert f.evidence_status == "INDETERMINATE"
    assert "NOT_SDF" not in f.description
    assert "SDF = true" not in f.description

# -----------------------------------------------------------------------------
# F. Serialization & Round-Trip Tests
# -----------------------------------------------------------------------------
def test_dpdp_finding_serialization_roundtrip():
    finding = Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file="App.js",
        line=10,
        message="DPDP Test Finding",
        rule_id="dpdp-test-rule",
        framework="DPDP",
        section="8(5)",
        processing_basis={"type": "consent", "status": "DETECTED"},
        effective_status="FUTURE_STATE",
        effective_from="2027-05-13",
        evidence_status="DETECTED"
    )

    report = Report(repo="test-repo", timestamp="2026-09-10T00:00:00Z", findings=[finding])
    data_dict = report.to_dict()

    reconstituted = Report.from_dict(data_dict)
    assert len(reconstituted.findings) == 1
    rf = reconstituted.findings[0]
    assert rf.framework == "DPDP"
    assert rf.section == "8(5)"
    assert rf.processing_basis == {"type": "consent", "status": "DETECTED"}
    assert rf.effective_status == "FUTURE_STATE"
    assert rf.effective_from == "2027-05-13"
    assert rf.evidence_status == "DETECTED"
