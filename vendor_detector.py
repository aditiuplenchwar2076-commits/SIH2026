def detect_vendor(configuration):
    configuration = configuration.lower()

    # Cisco
    if (
        "transport input" in configuration
        or "snmp-server" in configuration
        or "line vty" in configuration
        or "enable secret" in configuration
        or "enable password" in configuration
    ):
        return "Cisco"

    # Juniper
    elif any(
        marker in configuration
        for marker in [
            "set system",
            "set interfaces",
            "set security",
            "set protocols",
            "set snmp",
            "set routing-options",
            "set firewall",
            "set vlans",
            "system {",
            "interfaces {",
            "protocols {",
            "## last commit",
            "## last changed",
            "junos",
            "juniper"
        ]
    ):
        return "Juniper"

    # Fortinet
    elif any(
        marker in configuration
        for marker in [
            "config system",
            "config router",
            "config firewall",
            "config log",
            "config user",
            "set allowaccess",
            "fortigate",
            "fortios",
            "#config-version="
        ]
    ):
        return "Fortinet"

    # Palo Alto
    elif "set deviceconfig" in configuration or "pan-os" in configuration:
        return "Palo Alto"

    # Huawei
    elif "sysname" in configuration or "huawei" in configuration:
        return "Huawei"

    return "Unknown"