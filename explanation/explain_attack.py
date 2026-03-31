"""
explanation/explain_attack.py
==============================
Generates human-readable explanations for ML attack classifications.

Responsibilities:
    - Explain WHY a particular attack type was classified based on feature values
    - Map ML feature values to natural-language reasoning sentences
    - Produce a structured explanation dict for each classified IP
    - Provide an overall threat narrative (extracted from the monolith's
      generate_ai_summary NLG logic, adapted for login-specific ML output)

This module bridges the ML model's numeric predictions with plain-English
security analysis, completing the chain:
    Feature Extraction → Classification → Explanation → Recommendation
"""

from collections import Counter


# ── Feature-based explanation templates ───────────────────────────────────────

# Thresholds used for contextual reasoning
_BRUTE_FORCE_THRESHOLD = 10      # failed attempts to flag as brute force
_SPRAY_USERNAME_RATIO = 0.5      # unique_usernames / failed_attempts
_DICT_SAME_PWD_THRESHOLD = 5     # same_password_count for dictionary attack
_HIGH_RATE_THRESHOLD = 0.2       # requests/second considered fast


def explain_attack(
    ip: str,
    features: dict,
    classification: dict,
) -> dict:
    """Produce a feature-driven explanation for a single IP's attack classification.

    Analyses the numeric feature values and maps them to meaningful security
    observations that directly support (or contradict) the ML classification.

    Args:
        ip:             Source IP address string.
        features:       Feature dict with keys: failed_attempts, unique_usernames,
                        time_window, same_password_count, request_rate.
        classification: Dict from attack_classifier.classify_features(), containing
                        attack_type, confidence, all_probs.

    Returns:
        Dict with keys:
            ip              — source IP
            attack_type     — ML-predicted attack label
            confidence      — model confidence (0–1)
            reasons         — list of plain-English explanation strings
            severity        — inferred severity label
            summary         — single-sentence summary of the attack
    """
    attack_type = classification.get("attack_type", "Unknown")
    confidence = classification.get("confidence", 0.0)

    # Extract features with safe defaults
    failed = int(features.get("failed_attempts", 0))
    unique_users = int(features.get("unique_usernames", 0))
    time_win = float(features.get("time_window", 1.0))
    same_pwd = int(features.get("same_password_count", 0))
    rate = float(features.get("request_rate", 0.0))

    reasons = []

    # ── Feature-based reasoning ────────────────────────────────────────────────

    if failed == 0:
        reasons.append("No failed login attempts detected — activity appears normal.")
    else:
        reasons.append(f"{failed} failed login attempt(s) detected from this IP address.")

    if unique_users == 1 and failed > _BRUTE_FORCE_THRESHOLD:
        reasons.append(
            f"All {failed} attempts targeted a single username, "
            "which is characteristic of a brute-force password guessing attack."
        )
    elif unique_users > 1 and (unique_users / max(failed, 1)) >= _SPRAY_USERNAME_RATIO:
        reasons.append(
            f"{unique_users} different usernames were attempted across {failed} failures, "
            "which is consistent with credential stuffing or password spraying."
        )
    elif unique_users > 1:
        reasons.append(
            f"{unique_users} distinct usernames were tried across {failed} attempts."
        )

    if same_pwd > _DICT_SAME_PWD_THRESHOLD and unique_users == 1:
        reasons.append(
            f"The same password was reused {same_pwd} times, "
            "suggesting a dictionary or wordlist attack against a single account."
        )
    elif same_pwd > 0 and unique_users > 1:
        reasons.append(
            f"A single password was tried against {same_pwd} different accounts, "
            "which is a password spray pattern."
        )

    if rate >= _HIGH_RATE_THRESHOLD:
        reasons.append(
            f"The request rate was {rate:.3f} attempts/second over a "
            f"{time_win:.0f}-second window — this is an automated attack speed."
        )
    elif failed > 0:
        reasons.append(
            f"Attempts were distributed over {time_win:.0f} seconds "
            f"({rate:.4f} req/s) — slow enough to evade simple rate-limiters."
        )

    # ── Attack-type-specific reasoning ─────────────────────────────────────────

    specific_reasons = _get_attack_specific_reasons(attack_type, features)
    reasons.extend(specific_reasons)

    # ── Infer severity from confidence and attack type ─────────────────────────
    severity = _infer_severity(attack_type, failed, confidence)

    # ── One-line summary ───────────────────────────────────────────────────────
    summary = _build_summary_sentence(ip, attack_type, failed, confidence)

    return {
        "ip": ip,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "reasons": reasons,
        "severity": severity,
        "summary": summary,
    }


def _get_attack_specific_reasons(attack_type: str, features: dict) -> list[str]:
    """Return additional reasons specific to the predicted attack type.

    Args:
        attack_type: Predicted attack label.
        features:    Feature dict.

    Returns:
        List of additional reasoning strings.
    """
    reasons = []
    failed = int(features.get("failed_attempts", 0))
    same_pwd = int(features.get("same_password_count", 0))
    unique_users = int(features.get("unique_usernames", 0))

    if attack_type == "Brute Force":
        reasons.append(
            "Brute Force classification: single-target, high attempt count with varied passwords "
            "is the defining signature of automated password cracking."
        )
    elif attack_type == "Credential Stuffing":
        reasons.append(
            "Credential Stuffing classification: each username is tried with matching "
            "credentials from leaked password databases — each (user, password) pair is unique."
        )
    elif attack_type == "Dictionary Attack":
        reasons.append(
            "Dictionary Attack classification: a pre-built wordlist is being exhausted "
            "against the target account — same-password repetition with high attempt count is key."
        )
    elif attack_type == "Password Spray":
        reasons.append(
            "Password Spray classification: one or few common passwords tried across "
            "many accounts — avoids per-account lockout while covering a wide attack surface."
        )
    elif attack_type == "Normal":
        reasons.append(
            "Normal classification: the low attempt count and time distribution "
            "matches legitimate user login behaviour."
        )

    return reasons


def _infer_severity(attack_type: str, failed_attempts: int, confidence: float) -> str:
    """Infer a severity level from attack type and model confidence.

    Args:
        attack_type:    Predicted attack label.
        failed_attempts: Number of failed login attempts.
        confidence:     Model prediction confidence (0–1).

    Returns:
        Severity string: 'CRITICAL', 'HIGH', 'MEDIUM', or 'INFO'.
    """
    if attack_type in ("Brute Force", "Credential Stuffing") and failed_attempts >= 10:
        return "CRITICAL"
    elif attack_type in ("Brute Force", "Credential Stuffing"):
        return "HIGH"
    elif attack_type in ("Dictionary Attack", "Password Spray") and failed_attempts >= 10:
        return "HIGH"
    elif attack_type in ("Dictionary Attack", "Password Spray"):
        return "MEDIUM"
    elif attack_type == "Normal":
        return "INFO"
    else:
        return "MEDIUM"


def _build_summary_sentence(
    ip: str,
    attack_type: str,
    failed_attempts: int,
    confidence: float,
) -> str:
    """Build a one-sentence summary of the classification result.

    Args:
        ip:              Source IP address.
        attack_type:     Predicted attack label.
        failed_attempts: Number of failed login attempts.
        confidence:      Model confidence.

    Returns:
        Single summary sentence.
    """
    if attack_type == "Normal":
        return f"IP {ip} shows normal login behaviour ({failed_attempts} failed attempts)."

    return (
        f"IP {ip} is conducting a {attack_type} with {failed_attempts} failed login "
        f"attempt(s) — model confidence {confidence * 100:.0f}%."
    )


# ── Multi-IP threat narrative ──────────────────────────────────────────────────

def generate_threat_narrative(explanations: list[dict], summary: dict) -> str:
    """Generate an overall human-readable threat assessment from all IP explanations.

    Adapted from the monolith's generate_ai_summary() NLG engine, now focused
    on login-specific ML classifications.

    Args:
        explanations: List of explanation dicts from explain_attack().
        summary:      Aggregate summary dict from utils.helpers.build_summary().

    Returns:
        Multi-line plain-English threat narrative string.
    """
    if not explanations:
        return "No attack patterns detected. Login activity appears normal."

    critical = [e for e in explanations if e["severity"] == "CRITICAL"]
    high = [e for e in explanations if e["severity"] == "HIGH"]
    attack_counts = Counter(e["attack_type"] for e in explanations if e["attack_type"] != "Normal")
    total = summary.get("total", 0)
    threat_pct = summary.get("threat_pct", 0)

    lines = []

    # ── Overall threat level ───────────────────────────────────────────────────
    if len(critical) >= 3:
        lines.append(f"🔴 CRITICAL THREAT LEVEL: {len(critical)} source IPs mounting critical-severity attacks.")
    elif len(critical) >= 1:
        lines.append(f"🟠 HIGH THREAT LEVEL: {len(critical)} critical and {len(high)} high-severity source IPs detected.")
    elif len(high) >= 1:
        lines.append(f"🟡 ELEVATED THREAT LEVEL: {len(high)} high-severity IPs — investigation recommended.")
    else:
        lines.append("🟢 LOW THREAT LEVEL: No critical or high-severity attack sources detected.")

    # ── Attack breakdown ───────────────────────────────────────────────────────
    if attack_counts:
        lines.append(f"\n📊 ATTACK TYPE BREAKDOWN:")
        for attack_type, count in attack_counts.most_common():
            lines.append(f"  • {attack_type}: {count} source IP(s)")

    # ── Individual summaries ───────────────────────────────────────────────────
    non_normal = [e for e in explanations if e["attack_type"] != "Normal"]
    if non_normal:
        lines.append(f"\n🎯 TOP ATTACKING IPs:")
        for e in sorted(non_normal, key=lambda x: x["confidence"], reverse=True)[:5]:
            lines.append(f"  • {e['summary']}")

    # ── Statistics ─────────────────────────────────────────────────────────────
    lines.append(f"\n📈 STATISTICS: {total} total events | {threat_pct}% threat ratio")

    # ── Immediate actions ──────────────────────────────────────────────────────
    lines.append(f"\n⚡ IMMEDIATE ACTIONS REQUIRED:")
    if critical:
        ips = ", ".join(e["ip"] for e in critical[:4])
        lines.append(f"  1. Block or rate-limit attacking IPs: {ips}")
    lines.append("  2. Enable MFA for all administrative and user accounts.")
    lines.append("  3. Enforce account lockout after 5 consecutive failures.")
    lines.append("  4. Review authentication logs for successful logins from flagged IPs.")

    return "\n".join(lines)


# ── Formatting helpers ─────────────────────────────────────────────────────────

def format_explanation(explanation: dict) -> str:
    """Format a single IP explanation dict as a pretty-printed string.

    Args:
        explanation: Dict returned by explain_attack().

    Returns:
        Formatted multi-line string.
    """
    lines = [
        f"\n{'─' * 55}",
        f"  IP Address   : {explanation['ip']}",
        f"  Attack Type  : {explanation['attack_type']}",
        f"  Severity     : {explanation['severity']}",
        f"  Confidence   : {explanation['confidence'] * 100:.1f}%",
        f"  Summary      : {explanation['summary']}",
        f"\n  Reasoning:",
    ]
    for i, reason in enumerate(explanation["reasons"], 1):
        lines.append(f"    {i}. {reason}")
    return "\n".join(lines)
