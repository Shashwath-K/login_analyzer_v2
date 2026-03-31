"""
insights/recommendation_engine.py
===================================
Generates actionable security mitigation recommendations for detected attacks.

Responsibilities:
    - Map attack types to specific, prioritised mitigation steps
    - Generate a full SOC-style incident report (extracted from monolith's
      generate_soc_report and generate_alert_emails, adapted for ML output)
    - Produce firewall rule snippets for blocking attacking IPs
    - Provide per-attack-type risk levels and compliance notes

This module extracts and adapts the recommendation logic from:
    python_project.py — generate_soc_report() (lines 379–453)
    python_project.py — generate_firewall_rules() (lines 337–377)
    python_project.py — generate_alert_emails() (lines 455–516)
"""

import datetime
from collections import Counter


# ── Per-attack-type recommendation database ────────────────────────────────────

RECOMMENDATIONS: dict[str, dict] = {
    "Brute Force": {
        "severity": "CRITICAL",
        "steps": [
            "Block the source IP immediately at the firewall level.",
            "Enable account lockout after 5 consecutive failed attempts.",
            "Deploy fail2ban or equivalent intrusion prevention on the login endpoint.",
            "Enforce Multi-Factor Authentication (MFA) for all accounts.",
            "Reset credentials for any account that received the attack.",
            "Review authentication logs for any successful logins from this IP.",
            "Enable CAPTCHA challenges after 3 failed attempts.",
        ],
        "compliance_note": (
            "A successful brute-force breach may constitute a data breach under GDPR "
            "and PCI-DSS. Preserve all authentication logs as evidence."
        ),
    },
    "Credential Stuffing": {
        "severity": "CRITICAL",
        "steps": [
            "Block the attacking IP address; consider blocking the /24 subnet.",
            "Force password resets for all accounts targeted in the attack.",
            "Enable MFA immediately — credential stuffing only works against password-only auth.",
            "Subscribe to Have I Been Pwned (HIBP) breach notifications.",
            "Implement login velocity throttling by IP and by username.",
            "Deploy device fingerprinting to detect unusual login contexts.",
            "Alert affected users about a potential credential leak.",
        ],
        "compliance_note": (
            "Credential stuffing indicates user credentials may have been exposed in a "
            "third-party breach. GDPR Article 33 notification obligations may apply."
        ),
    },
    "Dictionary Attack": {
        "severity": "HIGH",
        "steps": [
            "Block the attacking IP at the firewall.",
            "Add CAPTCHA to the login form to prevent automated submissions.",
            "Enforce a strong password policy (minimum 12 characters, complexity requirements).",
            "Enable progressive delays after repeated login failures.",
            "Review and rotate credentials for the targeted accounts.",
            "Implement a password breach check (HIBP API) at password creation.",
        ],
        "compliance_note": (
            "Dictionary attacks indicate weak passwords are in use. "
            "Review compliance with password policies under ISO 27001 / NIST SP 800-63."
        ),
    },
    "Password Spray": {
        "severity": "HIGH",
        "steps": [
            "Enable Smart Lockout to detect spray patterns (lock per IP, not per account).",
            "Block or rate-limit the attacking IP address.",
            "Audit all accounts for the sprayed password — reset any that match.",
            "Enforce MFA, particularly for accounts with common usernames (admin, support).",
            "Monitor for low-frequency, multi-account failure patterns.",
            "Review Azure AD / Active Directory Conditional Access policies.",
        ],
        "compliance_note": (
            "Password spray attacks are designed to evade standard lockout policies. "
            "Ensure your lockout configuration accounts for distributed patterns."
        ),
    },
    "Normal": {
        "severity": "INFO",
        "steps": [
            "No immediate action required.",
            "Continue monitoring authentication logs for anomalies.",
            "Review login success rates periodically.",
        ],
        "compliance_note": "Normal login activity — no compliance concerns at this time.",
    },
}

# Fallback for unrecognised attack types
_DEFAULT_RECOMMENDATION = {
    "severity": "MEDIUM",
    "steps": [
        "Investigate the source IP for malicious intent.",
        "Review authentication logs for unusual patterns.",
        "Consider rate-limiting the login endpoint.",
        "Enable MFA for all user accounts.",
    ],
    "compliance_note": "Unknown attack pattern — manual security review recommended.",
}


# ── Per-IP recommendation generator ───────────────────────────────────────────

def get_recommendation(attack_type: str) -> dict:
    """Retrieve the recommendation dict for a given attack type.

    Args:
        attack_type: Predicted attack type label (e.g. 'Brute Force').

    Returns:
        Dict with keys: severity, steps (list), compliance_note.
    """
    return RECOMMENDATIONS.get(attack_type, _DEFAULT_RECOMMENDATION)


def format_recommendation(attack_type: str) -> str:
    """Format the recommendation for a given attack type as a readable string.

    Args:
        attack_type: Predicted attack type label.

    Returns:
        Formatted multi-line recommendation string.
    """
    rec = get_recommendation(attack_type)
    lines = [
        f"\n  Recommended Actions for: {attack_type}",
        f"  Severity Level: {rec['severity']}",
        f"  ─────────────────────────────────────",
    ]
    for i, step in enumerate(rec["steps"], 1):
        lines.append(f"  {i}. {step}")
    lines.append(f"\n  Compliance Note: {rec['compliance_note']}")
    return "\n".join(lines)


# ── Full SOC incident report ───────────────────────────────────────────────────

def generate_full_report(
    explanations: list[dict],
    summary: dict,
) -> str:
    """Generate a comprehensive SOC-style incident report from ML analysis results.

    Adapted from generate_soc_report() in the original monolith (lines 379–453).

    Args:
        explanations: List of explanation dicts from explain_attack().
        summary:      Aggregate summary dict from utils.helpers.build_summary().

    Returns:
        Full incident report as a formatted multi-line string.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attack_counts = Counter(e["attack_type"] for e in explanations)
    severity_counts = Counter(e["severity"] for e in explanations)
    critical_count = severity_counts.get("CRITICAL", 0)
    high_count = severity_counts.get("HIGH", 0)
    non_normal = [e for e in explanations if e["attack_type"] != "Normal"]
    overall_class = (
        "CRITICAL" if critical_count >= 3
        else "HIGH" if critical_count >= 1 or high_count >= 3
        else "MEDIUM" if high_count >= 1
        else "LOW"
    )

    lines = [
        "═" * 65,
        "  LOGIN ATTACK PATTERN ANALYZER — INCIDENT REPORT",
        f"  Generated     : {now}",
        f"  Classification: {overall_class}",
        f"  Analyzer      : ML-based (RandomForestClassifier)",
        "═" * 65,
        "",
        "## 1. EXECUTIVE SUMMARY",
        "─" * 40,
        f"A total of {summary.get('total', 0)} login events were analysed.",
        f"{critical_count} CRITICAL and {high_count} HIGH severity attack sources were found.",
        f"The overall threat ratio is {summary.get('threat_pct', 0)}% of all login events.",
        f"{len(non_normal)} source IP(s) were classified as active attackers.",
        "",
        "## 2. ATTACK TYPE ANALYSIS",
        "─" * 40,
    ]

    for attack_type, count in attack_counts.most_common():
        if attack_type != "Normal":
            rec = get_recommendation(attack_type)
            lines.append(f"  [{count:3d} IP(s)]  {attack_type}  [{rec['severity']}]")

    lines.extend([
        "",
        "## 3. TOP ATTACKING IPs",
        "─" * 40,
    ])

    for e in sorted(non_normal, key=lambda x: x["confidence"], reverse=True)[:10]:
        lines.append(
            f"  {e['ip']:<22} {e['attack_type']:<25} "
            f"[{e['severity']}]  Confidence: {e['confidence'] * 100:.0f}%"
        )

    lines.extend([
        "",
        "## 4. RISK ASSESSMENT",
        "─" * 40,
        f"  Overall Risk Level  : {overall_class}",
        f"  Active Attackers    : {len(non_normal)} source IP(s)",
        f"  Dominant Attack     : {attack_counts.most_common(1)[0][0] if attack_counts else 'None'}",
    ])

    if critical_count >= 1:
        lines.append("  Business Impact     : SEVERE — immediate response required")
    elif high_count >= 1:
        lines.append("  Business Impact     : HIGH — escalate to security team")
    else:
        lines.append("  Business Impact     : LOW — standard monitoring sufficient")

    lines.extend([
        "",
        "## 5. RECOMMENDATIONS",
        "─" * 40,
    ])

    seen_types = set()
    for e in sorted(non_normal, key=lambda x: x["confidence"], reverse=True):
        if e["attack_type"] not in seen_types:
            seen_types.add(e["attack_type"])
            rec = get_recommendation(e["attack_type"])
            lines.append(f"\n  [{e['attack_type']}]")
            for i, step in enumerate(rec["steps"][:4], 1):
                lines.append(f"    {i}. {step}")

    lines.extend([
        "",
        "## 6. NEXT STEPS",
        "─" * 40,
        "  □ Block all CRITICAL severity source IPs at the firewall",
        "  □ Force password resets for all targeted accounts",
        "  □ Enable MFA for the login endpoint immediately",
        "  □ Apply auto-generated firewall rules (see below)",
        "  □ Notify CISO if credential stuffing or brute force succeeded",
        "  □ Schedule post-incident review within 72 hours",
        "",
        "─" * 65,
        "  END OF REPORT — Login Attack Pattern Analyzer",
        "─" * 65,
    ])

    return "\n".join(lines)


# ── Firewall rule generator ────────────────────────────────────────────────────

def generate_firewall_rules(explanations: list[dict]) -> str:
    """Generate iptables and Windows firewall rules for blocking attacking IPs.

    Extracted and adapted from generate_firewall_rules() in the original monolith
    (lines 337–377), focused on login attacker IPs identified by the ML model.

    Args:
        explanations: List of explanation dicts from explain_attack().

    Returns:
        Firewall rule script as a formatted string.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attacking_ips = [
        e["ip"] for e in explanations
        if e["attack_type"] != "Normal" and e["severity"] in ("CRITICAL", "HIGH")
    ]
    attacking_ips = list(dict.fromkeys(attacking_ips))[:20]  # deduplicate, limit to 20

    lines = [
        "# ═══════════════════════════════════════════════════════",
        "# Login Attack Analyzer — Auto-Generated Firewall Rules",
        f"# Generated : {now}",
        f"# Sources   : {len(attacking_ips)} attacking IP(s) blocked",
        "# ═══════════════════════════════════════════════════════",
        "",
        "# ── iptables (Linux) ─────────────────────────────────────",
        "#!/bin/bash",
        "",
        "# Block attacking IPs identified by ML classifier:",
    ]

    for ip in attacking_ips:
        lines.append(f"iptables -I INPUT  -s {ip} -j DROP    # Block inbound from attacker")
        lines.append(f"iptables -I OUTPUT -d {ip} -j DROP    # Block outbound to attacker")

    lines.extend([
        "",
        "# Rate-limit login endpoint (port 80/443) to 10 requests per minute:",
        "iptables -A INPUT -p tcp --dport 80  -m limit --limit 10/min --limit-burst 20 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 443 -m limit --limit 10/min --limit-burst 20 -j ACCEPT",
        "",
        "# Save rules:",
        "iptables-save > /etc/iptables/rules.v4",
        "",
        "# ── Windows Firewall (PowerShell) ────────────────────────",
        "",
    ])

    for ip in attacking_ips:
        lines.append(
            f'New-NetFirewallRule -DisplayName "Block attacker {ip}" '
            f'-Direction Inbound -RemoteAddress {ip} -Action Block'
        )

    return "\n".join(lines)


# ── Alert email drafter ────────────────────────────────────────────────────────

def generate_alert_emails(explanations: list[dict], summary: dict) -> str:
    """Draft security alert emails for technical and management audiences.

    Adapted from generate_alert_emails() in the original monolith (lines 455–516).

    Args:
        explanations: List of explanation dicts from explain_attack().
        summary:      Aggregate summary dict.

    Returns:
        Two drafted email templates as a formatted string.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    non_normal = [e for e in explanations if e["attack_type"] != "Normal"]
    critical = [e for e in non_normal if e["severity"] == "CRITICAL"]
    total = summary.get("total", 0)
    threat_pct = summary.get("threat_pct", 0)
    attack_types = list({e["attack_type"] for e in non_normal})
    top_ips = [e["ip"] for e in sorted(non_normal, key=lambda x: x["confidence"], reverse=True)[:5]]

    return f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EMAIL 1: SECURITY TEAM (Technical)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TO: soc-team@company.com
CC: incident-response@company.com
SUBJECT: [{'CRITICAL' if critical else 'HIGH'}] Login Attack Detected — {now}

Team,

The Login Attack Pattern Analyzer has detected {len(non_normal)} attacking IP(s)
across {total} login events ({threat_pct}% threat ratio).

ATTACK SUMMARY:
• Attack types detected : {', '.join(attack_types) if attack_types else 'None'}
• Critical sources      : {len(critical)} IP(s)
• Top attacking IPs     : {', '.join(top_ips) if top_ips else 'None identified'}

IMMEDIATE ACTIONS:
1. Block attacking IPs at firewall (rules generated in report)
2. Enable MFA for all user accounts immediately
3. Reset passwords for all targeted accounts
4. Review authentication logs for successful logins from flagged IPs
5. Apply account lockout policy (max 5 failed attempts)

Full ML analysis report is attached.

— Login Attack Pattern Analyzer (ML Engine)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EMAIL 2: MANAGEMENT (Non-Technical)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TO: ciso@company.com; cto@company.com
SUBJECT: [ACTION REQUIRED] Login Attack Incident — {now}

Leadership,

Our automated security monitoring has detected active login attacks
against our systems.

RISK LEVEL: {'🔴 CRITICAL' if critical else '🟠 HIGH' if non_normal else '🟢 LOW'}

BUSINESS IMPACT:
• {len(non_normal)} external IP(s) identified as active attackers
• {threat_pct}% of login traffic is malicious
• {'Potential account compromise risk — MFA enforcement recommended immediately' if critical else 'No confirmed account breaches at this time'}

Our security team has been notified and is responding.
Password resets and IP blocks will be applied within 1 hour.

Full incident report available from the SOC team.

— Automated Security Operations Center
"""
