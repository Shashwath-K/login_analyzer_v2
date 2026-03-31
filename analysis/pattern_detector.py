"""
analysis/pattern_detector.py
=============================
Detects suspicious login/network patterns using a rule-based engine.

Responsibilities:
    - Define the rule set (regex pattern → category, severity, recommendation)
    - Classify individual log events by matching against rules
    - Apply port-based fallback classification for unknown protocols
    - Run the full analysis pipeline over a list of log tuples
    - Produce per-event results and an aggregate summary

This module preserves the complete rule engine from the original monolith
(python_project.py, lines 172–286) with clean refactoring and full docstrings.
"""

import re
from collections import Counter
from utils.helpers import order_val, max_severity, build_summary


# ── Rule definitions ───────────────────────────────────────────────────────────
# Each rule is a 4-tuple:
#   (regex_pattern, min_severity, category_label, recommendation_text)
#
# Events are matched top-to-bottom; the first matching rule wins.
# Severity is taken as the max of the rule's floor and the event's hint severity.

RULES: list[tuple] = [
    # ── Critical attack patterns ─────────────────────────────────────────────
    (r"brute.force|login.fail|ssh.login.fail",
     "CRITICAL", "Brute Force Attack",
     "Block source IP. Enable account lockout. Deploy fail2ban."),

    (r"cobalt.strike|beacon|c2.pattern|reverse.shell",
     "CRITICAL", "C2 Beaconing",
     "Isolate host immediately. Capture memory. Investigate persistence."),

    (r"ransomware|encrypt|ransom|locky|decrypt",
     "CRITICAL", "Ransomware Activity",
     "Isolate network segment. Restore from backup. Engage IR team."),

    (r"sql.inject|union.select|drop.table",
     "CRITICAL", "SQL Injection",
     "Enable WAF. Sanitize inputs. Review DB query logs."),

    (r"lateral.movement|smb.scan|eternal.blue",
     "CRITICAL", "Lateral Movement",
     "Segment network. Patch SMB. Audit service accounts."),

    (r"kerberoast|pass.the.hash|ntlm.relay",
     "CRITICAL", "Privilege Escalation",
     "Reset service account passwords. Enable Kerberos AES. Monitor LSASS."),

    (r"db.export|dump.all|bulk.select",
     "CRITICAL", "Data Theft",
     "Revoke DB permissions. Alert DLP. Investigate user activity."),

    (r"shadow.copy|vssadmin",
     "CRITICAL", "Ransomware Prep",
     "Block vssadmin. Enable VSS monitoring. Alert SOC immediately."),

    (r"port.3389|rdp.login",
     "CRITICAL", "Unauthorized RDP",
     "Disable RDP externally. Enforce NLA. Use VPN for remote access."),

    (r"malware|evil\.com|\.onion|ransom.pay",
     "CRITICAL", "Malicious Domain",
     "Block domain at DNS. Scan host for malware. Check persistence."),

    (r"path.traversal|etc.passwd|etc.shadow",
     "CRITICAL", "Path Traversal",
     "Sanitize file paths. Restrict web root. Update WAF rules."),

    (r"command.inject|cat /etc|/bin/sh",
     "CRITICAL", "Command Injection",
     "Sanitize all inputs. Disable shell execution from web app."),

    (r"lfi:|local.file.inclus",
     "CRITICAL", "LFI Attack",
     "Disable PHP include with user input. Use whitelist file paths."),

    (r"arp.poison|arp.flood|cache.poison",
     "CRITICAL", "ARP Poisoning",
     "Enable Dynamic ARP Inspection. Port security on switches."),

    (r"port.4444|port.9001|port.31337|port.6667",
     "CRITICAL", "Known Malware Port",
     "Block port at firewall. Investigate process binding to port."),

    # ── High severity patterns ────────────────────────────────────────────────
    (r"exfil|sensitive_data|upload.personal",
     "HIGH", "Data Exfiltration",
     "Review DLP policy. Block unauthorized cloud storage."),

    (r"dns.tunnel|txt.record.data|long.subdomain",
     "HIGH", "DNS Tunnelling",
     "Block anomalous DNS TXT queries. Monitor DNS payload sizes."),

    (r"xss:|<script>|alert\(1\)",
     "HIGH", "XSS Attack",
     "Implement CSP headers. Encode HTML output. Use HTTPOnly cookies."),

    (r"ssrf|metadata.request",
     "HIGH", "SSRF Attack",
     "Block internal IP ranges in outbound requests. Use allowlists."),

    (r"xxe|xml.external",
     "HIGH", "XXE Attack",
     "Disable XML external entity processing. Update XML parsers."),

    (r"directory.traversal|/var",
     "HIGH", "Directory Traversal",
     "Restrict web directory access. Normalize all URL paths."),

    (r"icmp.tunnel|covert.channel",
     "HIGH", "Covert Channel",
     "Block ICMP payloads > 64 bytes. Monitor ICMP frequency."),

    (r"smb.eternalblue|smb.exploit",
     "CRITICAL", "EternalBlue Exploit",
     "Patch MS17-010 immediately. Disable SMBv1. Block port 445 externally."),

    (r"crypto.?min|xmr|monero|mining.stratum",
     "HIGH", "Cryptomining",
     "Block mining pool IPs. Scan for unauthorized processes."),

    (r"tor.browser|\.onion|tor.usage",
     "HIGH", "Tor Usage",
     "Block Tor exit nodes. Enforce proxy policy. Alert HR/Legal."),

    (r"telnet|port.23",
     "HIGH", "Insecure Protocol",
     "Disable Telnet. Migrate to SSH. Block port 23 at firewall."),

    (r"ftp.plain|ftp.upload|ftp.cred",
     "HIGH", "Insecure FTP",
     "Replace FTP with SFTP/FTPS. Encrypt all file transfers."),

    (r"vnc.unencrypt|port.5900",
     "HIGH", "Unencrypted VNC",
     "Encrypt VNC with TLS. Restrict VNC to VPN only."),

    (r"ldap.enum|ldap.dump|domain.user",
     "HIGH", "AD Enumeration",
     "Monitor LDAP queries. Enable AD audit logging. Block anonymous LDAP."),

    (r"port.scan|tcp.syn.*port|scan.*port",
     "HIGH", "Port Scan",
     "Rate-limit TCP SYN. Implement port scan detection. Alert on threshold."),

    # ── Medium severity patterns ──────────────────────────────────────────────
    (r"snmp.public|snmp.community",
     "MEDIUM", "Weak SNMP",
     "Change SNMP community strings. Migrate to SNMPv3 with auth."),

    (r"icmp.ping.sweep|ping.sweep",
     "MEDIUM", "Reconnaissance",
     "Block external ICMP. Monitor for sweep patterns. Log source IPs."),

    (r"vpn.violation|proxy.bypass|openVPN",
     "MEDIUM", "Policy Violation",
     "Enforce proxy policy. Block unauthorized VPN clients."),

    (r"csrf.token|csrf",
     "MEDIUM", "CSRF Risk",
     "Implement CSRF tokens. Use SameSite cookie attribute."),

    (r"http.get|http.post.*normal|http.80.*normal",
     "MEDIUM", "Cleartext HTTP",
     "Enforce HTTPS. Redirect all HTTP to HTTPS. Use HSTS."),

    # ── Login-specific patterns (for login_logs.csv data) ────────────────────
    (r"login failed|login fail",
     "CRITICAL", "Brute Force Attack",
     "Enable account lockout after 5 failed attempts. Block IP. Use MFA."),

    (r"credential.stuff|multiple.user",
     "HIGH", "Credential Stuffing",
     "Enforce MFA. Use CAPTCHA. Monitor for distributed login failures."),

    (r"dictionary.attack|word.?list",
     "HIGH", "Dictionary Attack",
     "Enforce strong password policy. Add CAPTCHA. Rate-limit login endpoint."),

    (r"password.spray|spray",
     "HIGH", "Password Spray",
     "Enable smart lockout. Monitor for low-rate multi-account failures."),

    # ── Informational / normal traffic ────────────────────────────────────────
    (r"normal|info|ntp|dhcp|arp.who.has|dns.response|dns.query.*normal|"
     r"https.*normal|teams|azure|zoom|slack|login success",
     "INFO", "Normal Traffic",
     "No action required. Continue monitoring."),
]


# ── Known suspicious ports ─────────────────────────────────────────────────────

SUSPICIOUS_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
    88: "Kerberos", 135: "DCOM", 137: "NetBIOS", 139: "NetBIOS",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS",
    1433: "MSSQL", 1337: "Suspicious", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5900: "VNC",
    6667: "IRC", 8080: "HTTP-Alt", 9001: "Tor",
    31337: "Back Orifice", 45700: "Miner",
}

_HIGH_RISK_PORT_SERVICES = {"FTP", "Telnet", "SMB", "RDP", "Metasploit"}


# ── Event classifier ───────────────────────────────────────────────────────────

def classify_event(
    ts: str,
    src: str,
    dst: str,
    proto: str,
    port: str | int,
    desc: str,
    hint_sev: str,
) -> dict:
    """Classify a single log event using the RULES engine.

    Matches the event description + protocol against each rule's regex in order.
    Falls back to port-based classification if no text rule matches.

    Args:
        ts:       Timestamp string.
        src:      Source IP address.
        dst:      Destination IP address.
        proto:    Network protocol (e.g., 'TCP', 'HTTP').
        port:     Destination port number.
        desc:     Human-readable description of the event.
        hint_sev: Severity hint from the raw log (used as a floor).

    Returns:
        Dict with keys: ts, src, dst, proto, port, desc, severity, category, recommendation.
    """
    text = (str(desc) + " " + str(proto)).lower()

    for pattern, rule_sev, category, recommendation in RULES:
        if re.search(pattern, text, re.IGNORECASE):
            final_sev = max_severity(rule_sev, hint_sev)
            return {
                "ts": ts, "src": src, "dst": dst, "proto": proto, "port": port,
                "desc": desc, "severity": final_sev,
                "category": category, "recommendation": recommendation,
            }

    # ── Port-based fallback ──────────────────────────────────────────────────
    try:
        port_int = int(port) if str(port).isdigit() else 0
    except (ValueError, TypeError):
        port_int = 0

    port_name = SUSPICIOUS_PORTS.get(port_int, "")
    if port_name and port_name not in ("HTTPS", "DNS", "HTTP"):
        category = f"Suspicious Port ({port_name})"
        recommendation = f"Review traffic on port {port}. Verify service is authorized."
        port_sev = "HIGH" if port_name in _HIGH_RISK_PORT_SERVICES else "MEDIUM"
        final_sev = max_severity(port_sev, hint_sev)
        return {
            "ts": ts, "src": src, "dst": dst, "proto": proto, "port": port,
            "desc": desc, "severity": final_sev,
            "category": category, "recommendation": recommendation,
        }

    # ── Default: unrecognised / benign ───────────────────────────────────────
    return {
        "ts": ts, "src": src, "dst": dst, "proto": proto, "port": port,
        "desc": desc, "severity": hint_sev,
        "category": "Normal Traffic",
        "recommendation": "Continue monitoring.",
    }


# ── Full analysis pipeline ─────────────────────────────────────────────────────

def detect_patterns(log_rows: list[tuple | list]) -> tuple[list[dict], dict]:
    """Run the rule-based pattern detector over a list of log tuples.

    Classifies every row and produces per-event results plus an aggregate
    summary dictionary.

    Args:
        log_rows: List of tuples in the format:
                  (timestamp, src, dst, proto, port, description[, severity])

    Returns:
        Tuple of:
            results  — list of classified event dicts (one per row)
            summary  — aggregated statistics dict from utils.helpers.build_summary
    """
    results = []
    for i, row in enumerate(log_rows):
        if len(row) == 7:
            ts, src, dst, proto, port, desc, sev = row
        elif len(row) >= 6:
            ts, src, dst, proto, port, desc = row[:6]
            sev = "INFO"
        else:
            continue  # skip malformed rows

        event = classify_event(
            str(ts), str(src), str(dst), str(proto),
            str(port), str(desc), str(sev),
        )
        event["id"] = i + 1
        results.append(event)

    summary = build_summary(results)
    return results, summary
