"""
EU ePrivacy Directive (2002/58/EC) Constants.
"""

FRAMEWORK_EPRIVACY = "EPRIVACY"
EPRIVACY_EFFECTIVE_STATUS = "IN_FORCE"

# Baseline transposition dates
EPRIVACY_BASELINE_EFFECTIVE_FROM = "2003-10-31"  # Original Directive 2002/58/EC
EPRIVACY_AMENDMENT_EFFECTIVE_FROM = "2011-05-25" # Directive 2009/136/EC (Cookie Law)

EPRIVACY_REQUIREMENTS = {
    "EPRIVACY-ART5-CONFIDENTIALITY": {
        "title": "ePrivacy Art. 5: Confidentiality of Communications",
        "requirement": "Member States shall ensure the confidentiality of communications and the related traffic data by means of a public communications network and publicly available electronic communications services. In particular, they shall prohibit listening, tapping, storage or other kinds of interception or surveillance.",
        "recommended_action": "Ensure all electronic communications and traffic data are protected from unauthorized access or interception.",
        "baseline_date": EPRIVACY_BASELINE_EFFECTIVE_FROM
    },
    "EPRIVACY-ART5-3-TERMINAL-EQUIPMENT": {
        "title": "ePrivacy Art. 5(3): Terminal Equipment Storage (Cookie Law)",
        "requirement": "Storing information, or gaining access to information already stored, in the terminal equipment of a subscriber or user is only allowed on condition that the subscriber or user concerned has given his or her consent, having been provided with clear and comprehensive information.",
        "recommended_action": "Implement a consent mechanism for all non-essential cookies, local storage, and tracking technologies.",
        "baseline_date": EPRIVACY_AMENDMENT_EFFECTIVE_FROM
    },
    "EPRIVACY-ART6-TRAFFIC-DATA": {
        "title": "ePrivacy Art. 6: Traffic Data Processing",
        "requirement": "Traffic data relating to subscribers and users processed and stored by the provider of a public communications network or publicly available electronic communications service must be erased or made anonymous when it is no longer needed for the purpose of the transmission of a communication.",
        "recommended_action": "Verify retention policies and legal basis (e.g., billing, consent) for processing traffic metadata.",
        "baseline_date": EPRIVACY_BASELINE_EFFECTIVE_FROM
    },
    "EPRIVACY-ART9-LOCATION-DATA": {
        "title": "ePrivacy Art. 9: Location Data Processing",
        "requirement": "Location data other than traffic data relating to users or subscribers of public communications networks or publicly available electronic communications services may only be processed when they are made anonymous, or with the consent of the users or subscribers.",
        "recommended_action": "Ensure precise location data is collected only with consent and used solely for the authorized value-added service.",
        "baseline_date": EPRIVACY_BASELINE_EFFECTIVE_FROM
    },
    "EPRIVACY-ART12-PUBLIC-DIRECTORIES": {
        "title": "ePrivacy Art. 12: Directories of Subscribers",
        "requirement": "Subscribers must be informed, free of charge and before they are included in the directory, about the purpose(s) of a printed or electronic directory of subscribers available to the public. Consent is required for personal data inclusion.",
        "recommended_action": "Implement opt-in consent for inclusion in publicly accessible user directories.",
        "baseline_date": EPRIVACY_BASELINE_EFFECTIVE_FROM
    },
    "EPRIVACY-ART13-DIRECT-MARKETING": {
        "title": "ePrivacy Art. 13: Unsolicited Communications (Direct Marketing)",
        "requirement": "The use of automated calling systems without human intervention, facsimile machines (fax) or electronic mail for the purposes of direct marketing may only be allowed in respect of subscribers who have given their prior consent.",
        "recommended_action": "Ensure prior opt-in consent is obtained for direct marketing communications, unless the soft opt-in exception applies.",
        "baseline_date": EPRIVACY_BASELINE_EFFECTIVE_FROM
    },
    "EPRIVACY-ART4-SECURITY": {
        "title": "ePrivacy Art. 4: Security of Processing",
        "requirement": "The provider of a publicly available electronic communications service must take appropriate technical and organisational measures to safeguard security of its services.",
        "recommended_action": "Remediate identified security vulnerabilities that impact the confidentiality and integrity of communications.",
        "baseline_date": EPRIVACY_BASELINE_EFFECTIVE_FROM
    }
}
