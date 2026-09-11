"""
Shared Framework-Neutral Communication Channel Classifier.
Extracts communication flow evidence from repository AST, Data Flow Graph, and PII inventory.
Consumed by compliance engines (TCPA, TRAI/DLT, ePrivacy).
"""

import os
import uuid
from typing import List, Dict, Any, Optional, Tuple

from src.compliance.communication_models import (
    CommunicationFlowEvidence,
    CommunicationChannel,
    CommunicationPurpose,
    PurposeConfidence,
    EvidenceStatus
)

TELEPHONY_PROVIDERS = ["twilio", "plivo", "bandwidth", "vonage", "nexmo", "sinch", "telnyx", "messagebird"]
EMAIL_PROVIDERS = ["sendgrid", "ses", "mailgun", "postmark", "mailchimp", "sparkpost"]
VOICE_KEYWORDS = ["voice", "call", "ivr", "asterisk", "freeswitch", "telephony", "audio", "speech", "<say>", "<play>"]
SMS_KEYWORDS = ["sms", "text", "message", "otp", "2fa", "mms"]

MARKETING_KEYWORDS = [
    "marketing", "promo", "promotional", "campaign", "offer", "discount",
    "advertisement", "ad", "deal", "lead", "newsletter", "telemarketing", "sales"
]

TRANSACTIONAL_KEYWORDS = [
    "otp", "2fa", "verification", "auth", "login", "password_reset", "security_code",
    "receipt", "invoice", "order_status", "order_update", "shipping", "delivery",
    "appointment", "alert", "notification"
]

AUTOMATION_KEYWORDS = ["celery", "bull", "sidekiq", "cron", "batch_sms", "bulk_sms", "broadcast", "queue", "autodial"]
CONSENT_KEYWORDS = ["sms_consent", "phone_consent", "consent_to_text", "tcpa_consent", "agree_sms", "opt_in_sms"]
OPT_OUT_KEYWORDS = ["stop", "unsubscribe", "cancel", "quit", "optout", "opt_out"]
SUPPRESSION_KEYWORDS = ["suppression", "blacklist", "do_not_call", "donotcall", "dnc_list", "opt_out_list", "blocked_numbers", "dnc"]

EXCLUDE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".pytest_cache", "dist", "build"}

def classify_communication_purpose_and_confidence(text_evidence: str) -> Tuple[str, str]:
    """
    Classifies communication purpose into TRANSACTIONAL, MARKETING, MIXED, or UNKNOWN
    and assesses confidence as LOW, MEDIUM, or HIGH.
    """
    if not text_evidence:
        return CommunicationPurpose.UNKNOWN.value, PurposeConfidence.LOW.value

    txt = text_evidence.lower()
    mkt_count = sum(1 for kw in MARKETING_KEYWORDS if kw in txt)
    txn_count = sum(1 for kw in TRANSACTIONAL_KEYWORDS if kw in txt)

    if mkt_count > 0 and txn_count > 0:
        purpose = CommunicationPurpose.MIXED.value
        confidence = PurposeConfidence.HIGH.value if (mkt_count + txn_count >= 3) else PurposeConfidence.MEDIUM.value
    elif mkt_count > 0:
        purpose = CommunicationPurpose.MARKETING.value
        confidence = PurposeConfidence.HIGH.value if mkt_count >= 2 else PurposeConfidence.MEDIUM.value
    elif txn_count > 0:
        purpose = CommunicationPurpose.TRANSACTIONAL.value
        confidence = PurposeConfidence.HIGH.value if txn_count >= 2 else PurposeConfidence.MEDIUM.value
    else:
        purpose = CommunicationPurpose.UNKNOWN.value
        confidence = PurposeConfidence.LOW.value

    return purpose, confidence

def classify_communications(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None
) -> List[CommunicationFlowEvidence]:
    """
    Scans repository and shared data-flow evidence graph to produce a list of
    distinct framework-neutral CommunicationFlowEvidence objects.
    """
    flow_map: Dict[Tuple[str, Optional[str]], CommunicationFlowEvidence] = {}

    def get_or_create_flow(channel: str, provider: Optional[str]) -> CommunicationFlowEvidence:
        key = (channel, provider)
        if key not in flow_map:
            flow_map[key] = CommunicationFlowEvidence(
                flow_id=f"flow-{channel.lower()}-{(provider or 'generic').lower()}-{str(uuid.uuid4())[:8]}",
                channel=channel,
                provider=provider,
                evidence_status=EvidenceStatus.DETECTED.value
            )
        return flow_map[key]

    # 1. Inspect shared Data Flow Graph
    if flow_data:
        transfers = flow_data.get("third_party_transfers", [])
        for tr in transfers:
            svc = str(tr.get("service", "")).lower()
            field_name = str(tr.get("field", ""))
            loc = {"file": tr.get("file"), "line": tr.get("line")}

            # Identify provider
            matched_prov = None
            for p in TELEPHONY_PROVIDERS + EMAIL_PROVIDERS:
                if p in svc:
                    matched_prov = p
                    break

            if any(p in svc for p in TELEPHONY_PROVIDERS) or "phone" in field_name.lower():
                channel = CommunicationChannel.VOICE_CALL.value if ("voice" in svc or "call" in svc) else CommunicationChannel.SMS.value
                flow = get_or_create_flow(channel, matched_prov or "telephony")
                flow.recipient_field = field_name
                flow.source_locations.append(loc)
            elif any(p in svc for p in EMAIL_PROVIDERS) or "email" in field_name.lower():
                flow = get_or_create_flow(CommunicationChannel.EMAIL.value, matched_prov or "email")
                flow.recipient_field = field_name
                flow.source_locations.append(loc)

        inventory = flow_data.get("personal_data_inventory", [])
        for item in inventory:
            fname = str(item.get("field_name", "")).lower()
            if any(k in fname for k in ["phone", "mobile", "telephone", "cell"]):
                flow = get_or_create_flow(CommunicationChannel.SMS.value, None)
                if not flow.recipient_field:
                    flow.recipient_field = item.get("field_name")
                if item.get("location"):
                    flow.source_locations.append(item["location"])

    # 2. Source Code Walk Inspection
    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".html", ".vue", ".xml", ".twiml", ".yml", ".yaml")):
                    filepath = os.path.join(root, file)
                    rel_p = os.path.relpath(filepath, repo_path)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            content_lower = content.lower()

                            # Provider checks
                            detected_telephony = [p for p in TELEPHONY_PROVIDERS if p in content_lower]
                            detected_email = [p for p in EMAIL_PROVIDERS if p in content_lower]

                            has_voice = any(k in content_lower for k in VOICE_KEYWORDS)
                            has_sms = any(k in content_lower for k in SMS_KEYWORDS) or "phone" in content_lower
                            has_email = any(k in content_lower for k in EMAIL_PROVIDERS) or "email" in content_lower

                            has_auto = any(k in content_lower for k in AUTOMATION_KEYWORDS)
                            has_consent = any(k in content_lower for k in CONSENT_KEYWORDS)
                            has_opt_out = any(k in content_lower for k in OPT_OUT_KEYWORDS) and any(kw in content_lower for kw in ["sms", "twilio", "webhook", "message", "incoming"])
                            has_suppression = any(k in content_lower for k in SUPPRESSION_KEYWORDS)

                            # Telephony flows (SMS or Voice)
                            if detected_telephony or has_voice or has_sms or (has_consent or has_opt_out or has_suppression):
                                prov = detected_telephony[0] if detected_telephony else None
                                if has_voice:
                                    v_flow = get_or_create_flow(CommunicationChannel.VOICE_CALL.value, prov)
                                    v_flow.source_locations.append({"file": rel_p, "line": None})
                                if has_sms or not has_voice:
                                    s_flow = get_or_create_flow(CommunicationChannel.SMS.value, prov)
                                    s_flow.source_locations.append({"file": rel_p, "line": None})

                            # Email flows
                            if detected_email or (has_email and not has_sms and not has_voice and not detected_telephony):
                                e_prov = detected_email[0] if detected_email else "email"
                                e_flow = get_or_create_flow(CommunicationChannel.EMAIL.value, e_prov)
                                e_flow.source_locations.append({"file": rel_p, "line": None})

                            # Signals collection across all flows
                            has_auto = any(k in content_lower for k in AUTOMATION_KEYWORDS)
                            has_consent = any(k in content_lower for k in CONSENT_KEYWORDS)
                            has_opt_out = any(k in content_lower for k in OPT_OUT_KEYWORDS) and any(kw in content_lower for kw in ["sms", "twilio", "webhook", "message", "incoming"])
                            has_suppression = any(k in content_lower for k in SUPPRESSION_KEYWORDS)

                            purpose, conf = classify_communication_purpose_and_confidence(content_lower)

                            for flow in flow_map.values():
                                if has_auto:
                                    flow.automated = True
                                if any(b_kw in content_lower for b_kw in ["batch", "bulk", "broadcast"]):
                                    flow.bulk = True
                                if has_consent:
                                    ref = f"Consent reference in {rel_p}"
                                    if ref not in flow.consent_evidence:
                                        flow.consent_evidence.append(ref)
                                if has_opt_out:
                                    ref = f"Opt-out handler in {rel_p}"
                                    if ref not in flow.opt_out_evidence:
                                        flow.opt_out_evidence.append(ref)
                                if has_suppression:
                                    ref = f"Suppression list reference in {rel_p}"
                                    if ref not in flow.suppression_evidence:
                                        flow.suppression_evidence.append(ref)

                                if purpose != CommunicationPurpose.UNKNOWN.value:
                                    if flow.purpose == CommunicationPurpose.UNKNOWN.value:
                                        flow.purpose = purpose
                                        flow.purpose_confidence = conf
                                    elif flow.purpose != purpose:
                                        flow.purpose = CommunicationPurpose.MIXED.value
                                        flow.purpose_confidence = PurposeConfidence.HIGH.value
                    except Exception:
                        pass

    return list(flow_map.values())
