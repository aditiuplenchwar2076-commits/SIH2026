def run_security_rules(parsed_data):
    """
    Runs security checks on the parsed configuration
    and returns all detected security findings.
    """

    findings = []

    # Rule 1: Telnet
    if parsed_data.get("telnet_enabled"):
        findings.append({
            "rule_id": "NET-001",
            "issue": "Telnet is enabled",
            "severity": "High",
            "description": "Telnet is an insecure remote management protocol.",
            "remediation": "Disable Telnet and use SSH for secure remote access."
        })

    # Rule 2: Logging
    if not parsed_data.get("logging_configured"):
        findings.append({
            "rule_id": "LOG-001",
            "issue": "Logging may not be configured",
            "severity": "Medium",
            "description": "Without proper logging, security events may be difficult to monitor and investigate.",
            "remediation": "Configure centralized system logging and monitor security events."
        })

    # Rule 3: SNMP public community
    if parsed_data.get("snmp_public"):
        findings.append({
            "rule_id": "SNMP-001",
            "issue": "SNMP is using the public community string",
            "severity": "High",
            "description": "The default public SNMP community string can allow unauthorized information access.",
            "remediation": "Replace the public community string with a strong, unique value or use SNMPv3."
        })

    # Rule 4: SSH
    if parsed_data.get("ssh_enabled") is False:
        findings.append({
            "rule_id": "NET-002",
            "issue": "SSH is not configured",
            "severity": "High",
            "description": "Secure remote administration should use an encrypted management protocol.",
            "remediation": "Enable SSH and disable insecure remote management protocols."
        })

    # Rule 5: HTTP management
    if parsed_data.get("http_enabled"):
        findings.append({
            "rule_id": "WEB-001",
            "issue": "HTTP management is enabled",
            "severity": "High",
            "description": "HTTP does not provide encrypted communication for management traffic.",
            "remediation": "Disable HTTP management and use HTTPS instead."
        })

    # Rule 6: NTP
    if parsed_data.get("ntp_configured") is False:
        findings.append({
            "rule_id": "TIME-001",
            "issue": "NTP may not be configured",
            "severity": "Medium",
            "description": "Accurate time synchronization is important for reliable security logs and incident investigation.",
            "remediation": "Configure a trusted NTP server."
        })

    # Rule 7: AAA
    if parsed_data.get("aaa_configured") is False:
        findings.append({
            "rule_id": "AUTH-001",
            "issue": "AAA authentication may not be configured",
            "severity": "High",
            "description": "AAA provides centralized authentication, authorization and accounting for network access.",
            "remediation": "Configure AAA using an appropriate authentication service."
        })

    # Rule 8: Password policy
    if parsed_data.get("weak_password_policy"):
        findings.append({
            "rule_id": "AUTH-002",
            "issue": "Weak password policy detected",
            "severity": "High",
            "description": "Weak password policies can increase the risk of unauthorized access.",
            "remediation": "Enforce strong passwords and appropriate password security policies."
        })

    # Rule 9: Unnecessary service
    if parsed_data.get("unnecessary_services"):
        findings.append({
            "rule_id": "SVC-001",
            "issue": "Potentially unnecessary network services are enabled",
            "severity": "Medium",
            "description": "Unused services increase the device attack surface.",
            "remediation": "Disable services that are not required for device operation."
        })

    # Rule 10: Login protection
    if parsed_data.get("login_protection") is False:
        findings.append({
            "rule_id": "AUTH-003",
            "issue": "Login protection may not be configured",
            "severity": "Medium",
            "description": "Login protection can help reduce automated password-guessing attacks.",
            "remediation": "Configure login attempt limits, lockout or equivalent protection."
        })

    return findings