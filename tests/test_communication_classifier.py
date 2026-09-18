"""
Unit tests for framework-neutral Communication Channel Classifier.
"""

import pytest
from src.compliance.communication_models import (
    CommunicationFlowEvidence,
    CommunicationChannel,
    CommunicationPurpose,
    PurposeConfidence,
    EvidenceStatus
)
from src.compliance.communication_classifier import (
    classify_communications,
    classify_communication_purpose_and_confidence
)

def test_classifier_returns_list_of_evidence(tmp_path):
    f_file = tmp_path / "app.py"
    f_file.write_text("import twilio", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    assert isinstance(results, list)
    assert all(isinstance(ev, CommunicationFlowEvidence) for ev in results)

def test_twilio_sms_detection(tmp_path):
    f_file = tmp_path / "sms.py"
    f_file.write_text("from twilio.rest import Client\nclient.messages.create(body='OTP 1234', to='+1234')", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    sms_flows = [ev for ev in results if ev.channel == CommunicationChannel.SMS.value]
    assert len(sms_flows) >= 1
    assert sms_flows[0].provider == "twilio"

def test_generic_sms_provider(tmp_path):
    f_file = tmp_path / "sms.py"
    f_file.write_text("import plivo\nplivo.send_sms()", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    sms_flows = [ev for ev in results if ev.channel == CommunicationChannel.SMS.value]
    assert len(sms_flows) >= 1
    assert sms_flows[0].provider == "plivo"

def test_voice_call_api(tmp_path):
    f_file = tmp_path / "voice.py"
    f_file.write_text("<Response><Say>Welcome to IVR</Say></Response>", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    voice_flows = [ev for ev in results if ev.channel == CommunicationChannel.VOICE_CALL.value]
    assert len(voice_flows) >= 1

def test_email_only_path(tmp_path):
    f_file = tmp_path / "mailer.py"
    f_file.write_text("import sendgrid\nsendgrid.send_mail(to='user@example.com')", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    channels = {ev.channel for ev in results}
    assert CommunicationChannel.EMAIL.value in channels
    assert CommunicationChannel.SMS.value not in channels

def test_phone_number_without_communication(tmp_path):
    flow_data = {
        "personal_data_inventory": [{"field_name": "phone_number", "location": {"file": "user.py", "line": 1}}]
    }
    results = classify_communications(str(tmp_path), flow_data)
    assert len(results) >= 1
    assert results[0].recipient_field == "phone_number"

def test_transactional_message(tmp_path):
    p, c = classify_communication_purpose_and_confidence("Your verification otp security code is 1234")
    assert p == CommunicationPurpose.TRANSACTIONAL.value
    assert c in (PurposeConfidence.MEDIUM.value, PurposeConfidence.HIGH.value)

def test_marketing_message(tmp_path):
    p, c = classify_communication_purpose_and_confidence("Special promo deal discount 50% off sales campaign")
    assert p == CommunicationPurpose.MARKETING.value
    assert c == PurposeConfidence.HIGH.value

def test_ambiguous_message(tmp_path):
    p, c = classify_communication_purpose_and_confidence("User profile update handler")
    assert p == CommunicationPurpose.UNKNOWN.value
    assert c == PurposeConfidence.LOW.value

def test_automated_bulk_communication(tmp_path):
    f_file = tmp_path / "cron.py"
    f_file.write_text("from celery import task\nimport twilio\n# batch_sms dispatch queue", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    assert any(ev.automated for ev in results)
    assert any(ev.bulk for ev in results)

def test_consent_checkbox(tmp_path):
    f_file = tmp_path / "form.jsx"
    f_file.write_text("<input type='checkbox' name='agree_sms' />", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    assert any(len(ev.consent_evidence) > 0 for ev in results)

def test_opt_out_stop_handling(tmp_path):
    f_file = tmp_path / "webhook.py"
    f_file.write_text("if body.lower() == 'stop': unsubscribe_sms()", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    assert any(len(ev.opt_out_evidence) > 0 for ev in results)

def test_suppression_list(tmp_path):
    f_file = tmp_path / "models.py"
    f_file.write_text("class DoNotCallList(db.Model): pass", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    assert any(len(ev.suppression_evidence) > 0 for ev in results)

def test_multiple_twilio_functions(tmp_path):
    f1 = tmp_path / "sms.py"
    f1.write_text("import twilio\nclient.messages.create()", encoding="utf-8")
    f2 = tmp_path / "voice.py"
    f2.write_text("import twilio\nclient.calls.create()", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    assert len(results) >= 2

def test_third_party_communication_flow(tmp_path):
    flow_data = {
        "third_party_transfers": [{"service": "Twilio SMS API", "field": "phone", "file": "api.py", "line": 10}]
    }
    results = classify_communications(str(tmp_path), flow_data)
    assert len(results) >= 1
    assert results[0].provider == "twilio"

def test_no_communication_functionality(tmp_path):
    results = classify_communications(str(tmp_path), {})
    assert results == []

def test_multiple_distinct_flows_separate_objects(tmp_path):
    f_file = tmp_path / "multi.py"
    f_file.write_text("import twilio\nimport sendgrid\nvoice_call_ivr()", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    channels = {ev.channel for ev in results}
    assert len(channels) >= 2

def test_sms_and_voice_not_merged_into_mixed_channel(tmp_path):
    f_file = tmp_path / "multi.py"
    f_file.write_text("import twilio\nsms_text_otp()\nvoice_call_ivr()", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    channels = [ev.channel for ev in results]
    assert "MIXED" not in channels
    assert CommunicationChannel.SMS.value in channels
    assert CommunicationChannel.VOICE_CALL.value in channels

def test_purpose_confidence_restricted_values(tmp_path):
    p, c = classify_communication_purpose_and_confidence("promo sales otp")
    assert c in (PurposeConfidence.LOW.value, PurposeConfidence.MEDIUM.value, PurposeConfidence.HIGH.value)

def test_shared_classifier_framework_neutral(tmp_path):
    f_file = tmp_path / "app.py"
    f_file.write_text("import twilio", encoding="utf-8")
    results = classify_communications(str(tmp_path))
    for ev in results:
        assert not hasattr(ev, "tcpa_references")
        assert not hasattr(ev, "trai_references")
        assert not hasattr(ev, "eprivacy_references")
