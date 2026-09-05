def detect_vendor(configuration):
    configuration = configuration.lower()

    # Cisco
    if "transport input" in configuration or "snmp-server" in configuration:
        return "Cisco"

    # Juniper
    elif "set system" in configuration or "juniper" in configuration:
        return "Juniper"

    # Fortinet
    elif "config system" in configuration or "fortigate" in configuration:
        return "Fortinet"

    # Palo Alto
    elif "set deviceconfig" in configuration or "pan-os" in configuration:
        return "Palo Alto"

    # Huawei
    elif "sysname" in configuration or "huawei" in configuration:
        return "Huawei"

    return "Unknown"