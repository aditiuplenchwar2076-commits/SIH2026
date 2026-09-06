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
        "unnecessary_services": False,

        # Junos / SSH management checks
        "ssh_v1_enabled": False,
        "ssh_root_login_allowed": False
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
        weak_passwords = {
            "12345", "123456", "1234", "cisco", "admin", "password",
            "test", "cisco123", "admin123", "pass"
        }
        other_unnecessary = False

        for line in configuration_lines:
            line_l = line.lower()
            tokens = line_l.split()
            if not tokens:
                continue

            # Hostname
            if tokens[0] == "hostname" and len(tokens) > 1:
                data["hostname"] = line.split()[1]

            # AAA
            if tokens[:2] == ["aaa", "new-model"]:
                data["aaa_configured"] = True
            elif tokens[:3] == ["no", "aaa", "new-model"]:
                data["aaa_configured"] = False

            # HTTP Management
            if tokens[:3] == ["ip", "http", "server"]:
                data["http_enabled"] = True
            elif tokens[:4] == ["no", "ip", "http", "server"]:
                data["http_enabled"] = False

            # Transport input (Telnet / SSH)
            if tokens[:2] == ["transport", "input"]:
                opts = tokens[2:]
                if "none" in opts:
                    data["telnet_enabled"] = False
                    data["ssh_enabled"] = False
                elif "all" in opts:
                    data["telnet_enabled"] = True
                    data["ssh_enabled"] = True
                else:
                    if "telnet" in opts:
                        data["telnet_enabled"] = True
                    if "ssh" in opts:
                        data["ssh_enabled"] = True
            elif tokens[:3] == ["no", "transport", "input"]:
                opts = tokens[3:]
                if not opts or "all" in opts:
                    data["telnet_enabled"] = False
                    data["ssh_enabled"] = False
                else:
                    if "telnet" in opts:
                        data["telnet_enabled"] = False
                    if "ssh" in opts:
                        data["ssh_enabled"] = False

            # SNMP Public Community
            if tokens[:3] == ["snmp-server", "community", "public"]:
                data["snmp_public"] = True
            elif tokens[:4] == ["no", "snmp-server", "community", "public"]:
                data["snmp_public"] = False
            elif tokens[:2] == ["no", "snmp-server"]:
                data["snmp_public"] = False

            # Logging
            if tokens[0] == "logging":
                if len(tokens) > 1:
                    sub = tokens[1]
                    if sub in ["host", "server", "buffered", "on", "trap"]:
                        data["logging_configured"] = True
                    elif sub not in ["synchronous", "console", "monitor", "rate-limit", "userinfo"]:
                        # e.g., logging 192.168.1.10
                        data["logging_configured"] = True
            elif tokens[:2] == ["no", "logging"]:
                if len(tokens) == 2 or (len(tokens) > 2 and tokens[2] in ["on", "host", "server", "buffered"]):
                    data["logging_configured"] = False

            # NTP
            if tokens[:2] in [["ntp", "server"], ["ntp", "peer"]]:
                data["ntp_configured"] = True
            elif tokens[:2] == ["no", "ntp"]:
                data["ntp_configured"] = False

            # Login Protection
            if tokens[:2] in [["login", "block-for"], ["login", "delay"], ["login", "quiet-mode"]]:
                data["login_protection"] = True
            elif tokens[:2] == ["no", "login"]:
                data["login_protection"] = False

            # Unnecessary Services
            if tokens[0] != "no":
                if (
                    tokens[:2] == ["service", "tcp-small-servers"]
                    or tokens[:2] == ["service", "udp-small-servers"]
                    or tokens[:3] == ["ip", "bootp", "server"]
                    or tokens[:1] == ["bootp-server"]
                    or tokens[:2] == ["ip", "finger"]
                    or tokens[:2] == ["service", "finger"]
                    or tokens[:3] == ["ip", "dns", "server"]
                    or tokens[:2] == ["ip", "source-route"]
                ):
                    other_unnecessary = True

            # Weak Password Policy
            if tokens[0] != "no":
                # enable password (plaintext or type 7)
                if tokens[:2] == ["enable", "password"]:
                    data["weak_password_policy"] = True

                # enable secret <val>
                elif tokens[:2] == ["enable", "secret"]:
                    secret_args = tokens[2:]
                    if secret_args:
                        val = secret_args[1] if secret_args[0] in ["0", "5", "8", "9"] and len(secret_args) > 1 else secret_args[0]
                        if val in weak_passwords:
                            data["weak_password_policy"] = True

                # username <name> password <val> or username <name> secret <val>
                elif tokens[0] == "username" and len(tokens) > 2:
                    rest = tokens[2:]
                    if "password" in rest:
                        data["weak_password_policy"] = True
                    elif "secret" in rest:
                        s_idx = rest.index("secret")
                        secret_args = rest[s_idx + 1:]
                        if secret_args:
                            val = secret_args[1] if secret_args[0] in ["0", "5", "8", "9"] and len(secret_args) > 1 else secret_args[0]
                            if val in weak_passwords:
                                data["weak_password_policy"] = True

                # password under line configuration or password 7
                elif tokens[0] == "password":
                    data["weak_password_policy"] = True

                # explicit password 7 command anywhere
                elif "password 7" in line_l:
                    data["weak_password_policy"] = True

        data["unnecessary_services"] = other_unnecessary or data["http_enabled"]

    # =========================================================
    # JUNIPER
    # =========================================================
    elif vendor == "Juniper":
        weak_passwords = {
            "12345", "123456", "1234", "juniper", "admin", "password",
            "root", "test", "juniper123", "admin123", "pass", "cisco"
        }
        other_unnecessary = False

        for raw_line in configuration.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Ignore Junos comments
            if (
                line.startswith("#")
                or line.startswith("##")
                or line.startswith("/*")
                or line.startswith("*")
                or line.startswith("//")
                or line.startswith("!")
            ):
                continue

            line_clean = line.rstrip(";").strip()
            line_l = line_clean.lower()
            tokens = line_l.split()
            if not tokens:
                continue

            # -----------------------------------------------------
            # Hostname
            # -----------------------------------------------------
            if tokens[:3] == ["set", "system", "host-name"] and len(tokens) > 3:
                data["hostname"] = raw_line.split()[3].strip(';"')
            elif tokens[0] == "host-name" and len(tokens) > 1:
                data["hostname"] = raw_line.split()[1].strip(';"')

            # -----------------------------------------------------
            # Telnet
            # -----------------------------------------------------
            if tokens[:4] == ["set", "system", "services", "telnet"]:
                if "disable" in tokens[4:]:
                    data["telnet_enabled"] = False
                else:
                    data["telnet_enabled"] = True
            elif tokens[:4] in [
                ["delete", "system", "services", "telnet"],
                ["deactivate", "system", "services", "telnet"]
            ]:
                data["telnet_enabled"] = False
            elif tokens == ["telnet"]:
                data["telnet_enabled"] = True
            elif tokens == ["telnet", "disable"]:
                data["telnet_enabled"] = False

            # -----------------------------------------------------
            # SSH
            # -----------------------------------------------------
            if tokens[:4] == ["set", "system", "services", "ssh"]:
                if "disable" in tokens[4:]:
                    data["ssh_enabled"] = False
                else:
                    data["ssh_enabled"] = True

                # SSH protocol version check
                if "protocol-version" in tokens:
                    pv_idx = tokens.index("protocol-version")
                    if pv_idx + 1 < len(tokens):
                        pv_val = tokens[pv_idx + 1].strip(';"')
                        if pv_val in ["v1", "1"]:
                            data["ssh_v1_enabled"] = True
                        elif pv_val in ["v2", "2"]:
                            data["ssh_v1_enabled"] = False

                # Root login check
                if "root-login" in tokens:
                    rl_idx = tokens.index("root-login")
                    if rl_idx + 1 < len(tokens):
                        rl_val = tokens[rl_idx + 1].strip(';"')
                        if rl_val == "allow":
                            data["ssh_root_login_allowed"] = True
                        elif rl_val in ["deny", "unauthorized"]:
                            data["ssh_root_login_allowed"] = False

            elif tokens[:4] in [
                ["delete", "system", "services", "ssh"],
                ["deactivate", "system", "services", "ssh"]
            ]:
                data["ssh_enabled"] = False
            elif tokens == ["ssh"]:
                data["ssh_enabled"] = True
            elif tokens == ["ssh", "disable"]:
                data["ssh_enabled"] = False
            elif "protocol-version" in tokens:
                pv_idx = tokens.index("protocol-version")
                if pv_idx + 1 < len(tokens):
                    pv_val = tokens[pv_idx + 1].strip(';"')
                    if pv_val in ["v1", "1"]:
                        data["ssh_v1_enabled"] = True
                    elif pv_val in ["v2", "2"]:
                        data["ssh_v1_enabled"] = False
            elif "root-login" in tokens:
                rl_idx = tokens.index("root-login")
                if rl_idx + 1 < len(tokens):
                    rl_val = tokens[rl_idx + 1].strip(';"')
                    if rl_val == "allow":
                        data["ssh_root_login_allowed"] = True
                    elif rl_val in ["deny", "unauthorized"]:
                        data["ssh_root_login_allowed"] = False

            # -----------------------------------------------------
            # HTTP Management (Plain unencrypted HTTP)
            # -----------------------------------------------------
            if tokens[:5] == ["set", "system", "services", "web-management", "http"]:
                if "disable" in tokens[5:]:
                    data["http_enabled"] = False
                else:
                    data["http_enabled"] = True
            elif tokens[:5] in [
                ["delete", "system", "services", "web-management", "http"],
                ["deactivate", "system", "services", "web-management", "http"]
            ]:
                data["http_enabled"] = False
            elif tokens == ["http"] and "web-management" in line_l:
                data["http_enabled"] = True
            elif tokens == ["http", "disable"] and "web-management" in line_l:
                data["http_enabled"] = False

            # -----------------------------------------------------
            # Centralized Syslog / Logging
            # -----------------------------------------------------
            if tokens[:3] == ["set", "system", "syslog"]:
                if len(tokens) > 3 and tokens[3] in ["host", "server", "file", "console", "user"]:
                    data["logging_configured"] = True
            elif tokens[:3] in [
                ["delete", "system", "syslog"],
                ["deactivate", "system", "syslog"]
            ]:
                data["logging_configured"] = False
            elif tokens[0] in ["host", "file"] and len(tokens) > 1:
                data["logging_configured"] = True

            # -----------------------------------------------------
            # NTP
            # -----------------------------------------------------
            if tokens[:3] == ["set", "system", "ntp"]:
                if len(tokens) > 3 and tokens[3] in ["server", "peer", "boot-server"]:
                    data["ntp_configured"] = True
            elif tokens[:3] in [
                ["delete", "system", "ntp"],
                ["deactivate", "system", "ntp"]
            ]:
                data["ntp_configured"] = False
            elif tokens[0] in ["server", "peer"] and len(tokens) > 1:
                data["ntp_configured"] = True

            # -----------------------------------------------------
            # SNMP Public Community
            # -----------------------------------------------------
            if tokens[:4] == ["set", "snmp", "community", "public"]:
                if "authorization" in tokens:
                    auth_idx = tokens.index("authorization")
                    if auth_idx + 1 < len(tokens) and tokens[auth_idx + 1] == "none":
                        data["snmp_public"] = False
                    else:
                        data["snmp_public"] = True
                elif "disable" in tokens:
                    data["snmp_public"] = False
                else:
                    data["snmp_public"] = True
            elif tokens[:4] in [
                ["delete", "snmp", "community", "public"],
                ["deactivate", "snmp", "community", "public"]
            ]:
                data["snmp_public"] = False
            elif tokens[:2] == ["community", "public"]:
                data["snmp_public"] = True

            # -----------------------------------------------------
            # Centralized AAA (RADIUS / TACACS+)
            # -----------------------------------------------------
            if tokens[:3] == ["set", "system", "authentication-order"]:
                order_args = [t.strip(';[]",') for t in tokens[3:]]
                if any(proto in order_args for proto in ["radius", "tacplus"]):
                    data["aaa_configured"] = True
            elif tokens[:3] in [
                ["set", "system", "radius-server"],
                ["set", "system", "tacplus-server"]
            ]:
                data["aaa_configured"] = True
            elif tokens[:3] in [
                ["delete", "system", "authentication-order"],
                ["deactivate", "system", "authentication-order"]
            ]:
                data["aaa_configured"] = False
            elif tokens[0] == "authentication-order":
                if any(proto in tokens[1:] for proto in ["radius", "tacplus"]):
                    data["aaa_configured"] = True

            # -----------------------------------------------------
            # Login Protection (Retry Options / Lockout)
            # -----------------------------------------------------
            if tokens[:4] == ["set", "system", "login", "retry-options"]:
                if len(tokens) > 4 and tokens[4] in [
                    "tries-before-disconnect",
                    "backoff-threshold",
                    "lockout-period",
                    "backoff-factor"
                ]:
                    data["login_protection"] = True
            elif tokens[:4] in [
                ["delete", "system", "login", "retry-options"],
                ["deactivate", "system", "login", "retry-options"]
            ]:
                data["login_protection"] = False
            elif tokens[0] == "retry-options" or (
                tokens[0] in ["tries-before-disconnect", "backoff-threshold", "lockout-period"]
            ):
                data["login_protection"] = True

            # -----------------------------------------------------
            # Weak Password Policy & Plaintext Credentials
            # -----------------------------------------------------
            if "plain-text-password-value" in tokens:
                pt_idx = tokens.index("plain-text-password-value")
                if pt_idx + 1 < len(tokens):
                    pw = tokens[pt_idx + 1].strip(';"')
                    if pw in weak_passwords or len(pw) < 8:
                        data["weak_password_policy"] = True
                else:
                    data["weak_password_policy"] = True
            elif "plain-text-password" in tokens:
                data["weak_password_policy"] = True

            if "minimum-length" in tokens:
                ml_idx = tokens.index("minimum-length")
                if ml_idx + 1 < len(tokens):
                    try:
                        val = int(tokens[ml_idx + 1].strip(';"'))
                        if val < 8:
                            data["weak_password_policy"] = True
                    except ValueError:
                        pass

            # -----------------------------------------------------
            # Potentially Unnecessary / Insecure Services
            # -----------------------------------------------------
            if tokens[:3] == ["set", "system", "services"] and len(tokens) > 3:
                svc = tokens[3]
                if svc in ["finger", "ftp", "rlogin", "rsh", "xnm-clear-text"]:
                    if "disable" not in tokens:
                        other_unnecessary = True
            elif tokens[:4] in [
                ["delete", "system", "services", "finger"],
                ["delete", "system", "services", "ftp"],
                ["delete", "system", "services", "rlogin"],
                ["delete", "system", "services", "rsh"]
            ]:
                pass

        data["unnecessary_services"] = other_unnecessary or data["http_enabled"]

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