"""
Unit tests for India TRAI / TCCCPR / DLT mapping and classification helpers.
"""

import pytest
from src.compliance.trai_dlt_constants import TRAI_COMMUNICATION_TYPES
from src.compliance.trai_dlt_mapping import (
    classify_trai_communication_type,
    detect_dlt_parameters_in_text,
    get_trai_dlt_references_for_rule
)

def test_classify_trai_communication_type():
    assert classify_trai_communication_type("TRANSACTIONAL") == TRAI_COMMUNICATION_TYPES["SERVICE_TRANSACTIONAL"]
    assert classify_trai_communication_type("MARKETING") == TRAI_COMMUNICATION_TYPES["PROMOTIONAL_COMMERCIAL"]
    assert classify_trai_communication_type("MIXED") == TRAI_COMMUNICATION_TYPES["PROMOTIONAL_COMMERCIAL"]
    assert classify_trai_communication_type("UNKNOWN", "Your OTP verification code is 123456") == TRAI_COMMUNICATION_TYPES["SERVICE_TRANSACTIONAL"]
    assert classify_trai_communication_type("UNKNOWN", "Special promo offer! Get 50% discount today") == TRAI_COMMUNICATION_TYPES["PROMOTIONAL_COMMERCIAL"]
    assert classify_trai_communication_type("UNKNOWN", "Hello world") == TRAI_COMMUNICATION_TYPES["UNKNOWN"]

def test_detect_dlt_parameters_in_text():
    # PE ID
    res = detect_dlt_parameters_in_text("send_sms(to, msg, pe_id='1401234567890123456')")
    assert res["has_pe_id"] is True

    # 19 digit value pattern
    res_val = detect_dlt_parameters_in_text("entity_code = '1401122334455667788'")
    assert res_val["has_pe_id"] is True

    # Header / Sender ID
    res_hdr = detect_dlt_parameters_in_text("payload = {'sender_id': 'APNMND'}")
    assert res_hdr["has_header"] is True

    # Template ID
    res_tpl = detect_dlt_parameters_in_text("payload = {'template_id': '1007123456789'}")
    assert res_tpl["has_template_id"] is True

    # Empty / none found
    res_none = detect_dlt_parameters_in_text("console.log('Sending message')")
    assert res_none["has_pe_id"] is False
    assert res_none["has_header"] is False
    assert res_none["has_template_id"] is False

def test_get_trai_dlt_references_for_rule():
    refs = get_trai_dlt_references_for_rule("twilio-sms-dispatch")
    assert "TRAI-TCCCPR-REG-PE-ID" in refs
    assert "TRAI-TCCCPR-REG-HEADER-ID" in refs

    empty_refs = get_trai_dlt_references_for_rule("unrelated-security-rule")
    assert empty_refs == []
