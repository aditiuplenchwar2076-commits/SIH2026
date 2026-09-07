"""
CIS Compliance Mapping Layer for SIH2026

Maps internal security rule IDs to Center for Internet Security (CIS)
Benchmark references and security control categories in a vendor-neutral structure.
"""

from typing import Dict, Any, Optional

CIS_RULE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "NET-001": {
        "reference": "CIS Network Devices Benchmark - Remote Access",
        "title": "Disable Insecure Remote Access Protocols (Telnet)",
        "rationale": "Telnet transmits plaintext credentials and session data across the network, enabling eavesdropping and credential theft."
    },
    "LOG-001": {
        "reference": "CIS Network Devices Benchmark - Logging & Auditing",
        "title": "Ensure Centralized System Logging is Configured",
        "rationale": "Centralized logging preserves audit trails on external log hosts, preventing local tampering and enabling security monitoring."
    },
    "SNMP-001": {
        "reference": "CIS Network Devices Benchmark - Management Protocols",
        "title": "Disable Default SNMP Community Strings",
        "rationale": "Default community strings like 'public' allow unauthorized device information disclosure and network mapping."
    },
    "NET-002": {
        "reference": "CIS Network Devices Benchmark - Remote Access",
        "title": "Enable Secure Encrypted Administrative Access (SSH)",
        "rationale": "Administrative sessions must be protected with cryptographically strong protocols to secure management traffic."
    },
    "WEB-001": {
        "reference": "CIS Network Devices Benchmark - Web Management",
        "title": "Disable Insecure HTTP Web Management Server",
        "rationale": "Unencrypted HTTP management allows attackers to intercept cookies, session tokens, and administrative credentials."
    },
    "TIME-001": {
        "reference": "CIS Network Devices Benchmark - Time Synchronization",
        "title": "Ensure Accurate Network Time Protocol (NTP) Synchronization",
        "rationale": "Synchronized time across network infrastructure is critical for forensic correlation and audit log validity."
    },
    "AUTH-001": {
        "reference": "CIS Network Devices Benchmark - Authentication & Authorization",
        "title": "Configure Centralized AAA Authentication (RADIUS/TACACS+)",
        "rationale": "Centralized AAA provides consistent credential enforcement, accountability, and role-based access control."
    },
    "AUTH-002": {
        "reference": "CIS Network Devices Benchmark - Password Security",
        "title": "Enforce Strong Password and Secret Protection Policies",
        "rationale": "Weak passwords and reversible password encryptions increase exposure to dictionary and offline cracking attacks."
    },
    "SVC-001": {
        "reference": "CIS Network Devices Benchmark - Device Hardening",
        "title": "Disable Unused and Insecure Network Services",
        "rationale": "Auxiliary network services (such as FTP, finger, small-servers) broaden the attack surface and should be disabled."
    },
    "AUTH-003": {
        "reference": "CIS Network Devices Benchmark - Login & Access Controls",
        "title": "Configure Login Rate Limiting and Lockout Controls",
        "rationale": "Rate-limiting login attempts and enforcing backoff delays mitigate automated brute-force attacks on management lines."
    },
    "NET-003": {
        "reference": "CIS Network Devices Benchmark - SSH Protocol Hardening",
        "title": "Enforce SSH Protocol Version 2 Only",
        "rationale": "SSHv1 contains fundamental cryptographic flaws and must be disabled in favor of SSHv2."
    },
    "AUTH-004": {
        "reference": "CIS Network Devices Benchmark - Privileged Access Management",
        "title": "Disable Direct Root Login Over SSH",
        "rationale": "Direct remote login as root should be prohibited to require named administrative accountability before privilege escalation."
    }
}


def get_cis_mapping(rule_id: str) -> Optional[Dict[str, str]]:
    """
    Retrieve CIS compliance mapping for a specific rule ID.
    Returns None if no confident mapping exists.
    """
    return CIS_RULE_MAPPINGS.get(rule_id)


def attach_cis_mappings(findings: list) -> list:
    """
    Attaches CIS compliance information to each finding in the findings list.
    Preserves all existing finding fields without modification.
    """
    for finding in findings:
        rule_id = finding.get("rule_id")
        if rule_id:
            mapping = get_cis_mapping(rule_id)
            if mapping:
                finding["compliance"] = {
                    "CIS": {
                        "reference": mapping["reference"],
                        "title": mapping["title"],
                        "rationale": mapping["rationale"]
                    }
                }
    return findings
