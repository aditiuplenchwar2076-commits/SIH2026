def parse_configuration(configuration, vendor):
    """
    Converts raw network configuration into
    standardized security-related information.
    """

    data = {
        "vendor": vendor,
        "hostname": None,

        # Remote access
        "telnet_enabled": False,
        "ssh_enabled": False,
        "http_enabled": False,

        # Logging and time
        "logging_configured": False,
        "ntp_configured": False,

        # Security protocols
        "snmp_public": False,

        # Authentication
        "aaa_configured": False,
        "weak_password_policy": False,
        "login_protection": False,

        # Services
        "unnecessary_services": False
    }

    # Remove comments before analysing the configuration.
    # Cisco uses "!" for comments.
    configuration_lines = []

    for line in configuration.splitlines():
        line = line.strip()

        if line.startswith("!"):
            continue

        if line:
            configuration_lines.append(line)

    # Rebuild configuration using only actual configuration lines
    clean_configuration = "\n".join(configuration_lines)
    configuration_lower = clean_configuration.lower()

    # =========================================================
    # CISCO
    # =========================================================
    if vendor == "Cisco":

        for line in configuration_lines:
            if line.lower().startswith("hostname "):
                parts = line.split()
                if len(parts) > 1:
                    data["hostname"] = parts[1]

        # Telnet
        if "transport input telnet" in configuration_lower:
            data["telnet_enabled"] = True

        # SSH
        if "transport input ssh" in configuration_lower:
            data["ssh_enabled"] = True

        # HTTP
        if "ip http server" in configuration_lower:
            data["http_enabled"] = True

        # Logging
        if "logging " in configuration_lower:
            data["logging_configured"] = True

        # NTP
        if "ntp server" in configuration_lower:
            data["ntp_configured"] = True

        # SNMP public
        if "snmp-server community public" in configuration_lower:
            data["snmp_public"] = True

        # AAA
        if "aaa new-model" in configuration_lower:
            data["aaa_configured"] = True

        # Weak password
        if "enable password" in configuration_lower:
            data["weak_password_policy"] = True

        # Login protection
        if "login block-for" in configuration_lower:
            data["login_protection"] = True

        # Potentially unnecessary service
        if "ip http server" in configuration_lower:
            data["unnecessary_services"] = True

    # =========================================================
    # JUNIPER
    # =========================================================
    elif vendor == "Juniper":

        for line in configuration_lines:
            if line.lower().startswith("set system host-name"):
                parts = line.split()
                if len(parts) > 3:
                    data["hostname"] = parts[3]

        if "set system services telnet" in configuration_lower:
            data["telnet_enabled"] = True

        if "set system services ssh" in configuration_lower:
            data["ssh_enabled"] = True

        if "http" in configuration_lower:
            data["http_enabled"] = True

        if "set system syslog" in configuration_lower:
            data["logging_configured"] = True

        if "set system ntp" in configuration_lower:
            data["ntp_configured"] = True

        if "community public" in configuration_lower:
            data["snmp_public"] = True

        if "authentication-order" in configuration_lower:
            data["aaa_configured"] = True

        if "login retry-options" in configuration_lower:
            data["login_protection"] = True

    # =========================================================
    # FORTINET
    # =========================================================
    elif vendor == "Fortinet":

        for line in configuration_lines:
            if line.lower().startswith("set hostname"):
                parts = line.split()
                if len(parts) > 2:
                    data["hostname"] = parts[2]

        if "telnet" in configuration_lower:
            data["telnet_enabled"] = True

        if "ssh" in configuration_lower:
            data["ssh_enabled"] = True

        if "http" in configuration_lower:
            data["http_enabled"] = True

        if "config log" in configuration_lower:
            data["logging_configured"] = True

        if "config system ntp" in configuration_lower:
            data["ntp_configured"] = True

        if "community public" in configuration_lower:
            data["snmp_public"] = True

    # =========================================================
    # PALO ALTO
    # =========================================================
    elif vendor == "Palo Alto":

        for line in configuration_lines:
            if "hostname" in line.lower():
                parts = line.split()
                if len(parts) > 1:
                    data["hostname"] = parts[-1]

        if "telnet" in configuration_lower:
            data["telnet_enabled"] = True

        if "ssh" in configuration_lower:
            data["ssh_enabled"] = True

        if "http" in configuration_lower:
            data["http_enabled"] = True

        if "syslog" in configuration_lower:
            data["logging_configured"] = True

        if "ntp" in configuration_lower:
            data["ntp_configured"] = True

        if "snmp" in configuration_lower and "public" in configuration_lower:
            data["snmp_public"] = True

    # =========================================================
    # HUAWEI
    # =========================================================
    elif vendor == "Huawei":

        for line in configuration_lines:
            if line.lower().startswith("sysname "):
                parts = line.split()
                if len(parts) > 1:
                    data["hostname"] = parts[1]

        if "telnet server enable" in configuration_lower:
            data["telnet_enabled"] = True

        if "stelnet server enable" in configuration_lower:
            data["ssh_enabled"] = True

        if "http" in configuration_lower:
            data["http_enabled"] = True

        if "info-center enable" in configuration_lower:
            data["logging_configured"] = True

        if "ntp-service" in configuration_lower:
            data["ntp_configured"] = True

        if "community public" in configuration_lower:
            data["snmp_public"] = True

    return data