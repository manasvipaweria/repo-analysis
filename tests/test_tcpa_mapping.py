"""
Unit tests for TCPA requirement mapping, communication channels, and purpose classification.
"""

import pytest
from src.compliance.tcpa_constants import TCPA_CHANNELS, TCPA_PURPOSES, TCPA_REQUIREMENTS
from src.compliance.tcpa_mapping import (
    classify_communication_channel,
    classify_communication_purpose,
    get_tcpa_references_for_rule
)

def test_tcpa_requirements_metadata():
    assert "TCPA-227-B-1-A-CALLS-CONSENT" in TCPA_REQUIREMENTS
    assert "TCPA-64-1200-SMS-OPT-OUT" in TCPA_REQUIREMENTS
    assert "TCPA-227-C-DO-NOT-CALL" in TCPA_REQUIREMENTS

def test_classify_communication_channel():
    assert classify_communication_channel("twilio sms notification", {"provider": "twilio"}) == TCPA_CHANNELS["SMS"]
    assert classify_communication_channel("incoming voice call ivr", {"provider": "twilio"}) == TCPA_CHANNELS["VOICE_CALL"]
    assert classify_communication_channel("sendgrid email receipt") == TCPA_CHANNELS["EMAIL"]
    assert classify_communication_channel("") == TCPA_CHANNELS["UNKNOWN"]

def test_classify_communication_purpose():
    assert classify_communication_purpose("send promo campaign discount code") == TCPA_PURPOSES["MARKETING"]
    assert classify_communication_purpose("send otp authentication code") == TCPA_PURPOSES["TRANSACTIONAL"]
    assert classify_communication_purpose("send promo discount and otp security code") == TCPA_PURPOSES["MIXED"]
    assert classify_communication_purpose("user sign up endpoint") == TCPA_PURPOSES["UNKNOWN"]

def test_get_tcpa_references_for_rule():
    refs = get_tcpa_references_for_rule("twilio-sms-unprotected-endpoint", ["semgrep"])
    assert "TCPA-227-B-1-A-CALLS-CONSENT" in refs
    assert "TCPA-64-1200-IDENTIFICATION" in refs

    assert get_tcpa_references_for_rule("sql-injection", ["bandit"]) == []
