import pytest
import os
from unittest.mock import patch
from src.core.models import Finding, Category, Severity, ComplianceFindingType, ToolStatus
from src.compliance.communication_models import CommunicationFlowEvidence, CommunicationChannel, CommunicationPurpose
from src.compliance.eprivacy_engine import (
    evaluate_eprivacy_applicability,
    check_eprivacy_art5_3_terminal_equipment,
    check_eprivacy_art6_traffic_data,
    check_eprivacy_art13_direct_marketing,
    check_eprivacy_art9_location_data,
    run_eprivacy_checks
)
from src.compliance.eprivacy_constants import EPRIVACY_BASELINE_EFFECTIVE_FROM, EPRIVACY_AMENDMENT_EFFECTIVE_FROM

def test_applicability_overrides():
    with patch.dict(os.environ, {"EPRIVACY_APPLICABILITY": "APPLICABLE"}):
        state, reasons, src = evaluate_eprivacy_applicability("/dummy")
        assert state == "APPLICABLE"
        assert src == "ENVIRONMENT_OVERRIDE"

    with patch.dict(os.environ, {"EPRIVACY_APPLICABILITY": "NOT_APPLICABLE"}):
        state, reasons, src = evaluate_eprivacy_applicability("/dummy")
        assert state == "NOT_APPLICABLE"

    with patch.dict(os.environ, {"EPRIVACY_APPLICABILITY": "INDETERMINATE"}):
        state, reasons, src = evaluate_eprivacy_applicability("/dummy")
        assert state == "INDETERMINATE"

    with patch.dict(os.environ, {"EPRIVACY_APPLICABILITY": "INVALID"}):
        with pytest.raises(ValueError):
            evaluate_eprivacy_applicability("/dummy")

    with patch.dict(os.environ, clear=True):
        state, reasons, src = evaluate_eprivacy_applicability("/dummy")
        assert state == "INDETERMINATE"
        assert src == "HUMAN_REVIEW"

def test_effective_dates():
    # E-privacy specific test for baseline and amendment dates
    assert EPRIVACY_BASELINE_EFFECTIVE_FROM == "2003-10-31"
    assert EPRIVACY_AMENDMENT_EFFECTIVE_FROM == "2011-05-25"

def test_art13_direct_marketing():
    ev_transactional = CommunicationFlowEvidence(
        flow_id="f1",
        channel=CommunicationChannel.SMS.value,
        purpose=CommunicationPurpose.TRANSACTIONAL.value,
        provider="twilio"
    )
    
    ev_marketing_consent = CommunicationFlowEvidence(
        flow_id="f2",
        channel=CommunicationChannel.EMAIL.value,
        purpose=CommunicationPurpose.MARKETING.value,
        consent_evidence=["some evidence"],
        provider="sendgrid"
    )

    ev_marketing_no_consent = CommunicationFlowEvidence(
        flow_id="f3",
        channel=CommunicationChannel.VOICE_CALL.value,
        purpose=CommunicationPurpose.MARKETING.value,
        consent_evidence=[],
        provider="plivo"
    )
    
    findings = check_eprivacy_art13_direct_marketing("/dummy", None, [ev_transactional, ev_marketing_consent, ev_marketing_no_consent])
    assert len(findings) == 3
    
    assert findings[0].rule_id == "EPRIVACY-ART13-TRANSACTIONAL"
    assert findings[0].severity == Severity.INFO
    assert findings[0].effective_from == "2003-10-31"
    
    assert findings[1].rule_id == "EPRIVACY-ART13-MARKETING-CONSENT"
    assert findings[1].severity == Severity.INFO
    
    assert findings[2].rule_id == "EPRIVACY-ART13-MARKETING-NOCONSENT"
    assert findings[2].severity == Severity.MEDIUM
    assert findings[2].compliance_finding_type == ComplianceFindingType.HUMAN_REVIEW

def test_art6_traffic_data():
    flow_data = {
        "pii_fields": [
            {"field": "ip_address", "file": "src/app.js", "line": 10},
            {"field": "timestamp", "file": "src/app.js", "line": 11}
        ]
    }
    findings = check_eprivacy_art6_traffic_data("/dummy", flow_data)
    assert len(findings) == 2
    assert findings[0].rule_id == "EPRIVACY-ART6-TRAFFIC-DATA"
    assert findings[0].severity == Severity.INFO
    assert "ip_address" in findings[0].detected_evidence
    
    assert findings[1].rule_id == "EPRIVACY-ART6-TRAFFIC-RETENTION"
    assert findings[1].compliance_finding_type == ComplianceFindingType.HUMAN_REVIEW

def test_art9_location_data():
    flow_data = {
        "pii_fields": [
            {"field": "gps_coordinates", "file": "src/app.js", "line": 10}
        ]
    }
    findings = check_eprivacy_art9_location_data("/dummy", flow_data)
    assert len(findings) == 1
    assert findings[0].rule_id == "EPRIVACY-ART9-LOCATION-DATA"
    assert "gps_coordinates" in findings[0].detected_evidence

def test_art5_3_terminal_equipment():
    findings = check_eprivacy_art5_3_terminal_equipment("/dummy", None)
    assert len(findings) == 0
    
    # We test file behavior directly in a real run, but we can verify the effective_from date
    # if we mock the findings output, which we know from the constants.
