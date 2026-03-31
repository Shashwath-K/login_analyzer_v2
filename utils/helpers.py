"""
utils/helpers.py
================
Shared utility functions used across all modules in the Login Attack Pattern Analyzer.

Responsibilities:
    - Severity ordering and comparison
    - Timestamp formatting and parsing
    - IP address classification (private vs public)
    - Logging helpers
    - CSV/JSON export utilities
    - Risk score computation weights
"""

import csv
import json
import datetime
import io
from collections import Counter


# ── Severity ordering ──────────────────────────────────────────────────────────

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHTS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 5, "CRITICAL": 10}


def order_val(severity: str) -> int:
    """Return an integer rank for a severity string (higher = more severe).

    Args:
        severity: Severity label, e.g. 'CRITICAL', 'HIGH', 'INFO'.

    Returns:
        Integer rank from 0 (INFO) to 4 (CRITICAL). Returns 0 for unknown values.
    """
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def max_severity(sev_a: str, sev_b: str) -> str:
    """Return the more severe of two severity strings.

    Args:
        sev_a: First severity label.
        sev_b: Second severity label.

    Returns:
        Whichever severity label has the higher rank.
    """
    return sev_a if order_val(sev_a) >= order_val(sev_b) else sev_b


# ── Timestamp helpers ──────────────────────────────────────────────────────────

def now_str() -> str:
    """Return the current datetime as a formatted string (YYYY-MM-DD HH:MM:SS)."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_timestamp(ts_str: str) -> datetime.datetime | None:
    """Parse a timestamp string into a datetime object.

    Supports the format: 'YYYY-MM-DD HH:MM:SS'.

    Args:
        ts_str: Timestamp string to parse.

    Returns:
        datetime object, or None if parsing fails.
    """
    try:
        return datetime.datetime.strptime(str(ts_str).strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


# ── IP classification ──────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Determine whether an IP address is in a private (RFC 1918) range.

    Args:
        ip: IPv4 address string.

    Returns:
        True if the IP is private/internal, False if public/external.
    """
    private_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.", "127.", "0.0.0.0")
    return ip.startswith(private_prefixes)


# ── Risk scoring ───────────────────────────────────────────────────────────────

def compute_risk_scores(results: list[dict]) -> dict[str, dict]:
    """Compute a per-source-IP risk score from a list of classified events.

    Score is based on the sum of SEVERITY_WEIGHTS for each event from that IP.

    Args:
        results: List of event dicts, each containing 'src' and 'severity' keys.

    Returns:
        Dict mapping IP address → {'score': int, 'events': int}.
    """
    scores: dict[str, dict] = {}
    for r in results:
        ip = r.get("src", "0.0.0.0")
        if ip not in scores:
            scores[ip] = {"score": 0, "events": 0}
        scores[ip]["events"] += 1
        scores[ip]["score"] += SEVERITY_WEIGHTS.get(r.get("severity", "INFO"), 0)
    return scores


def top_risk_hosts(results: list[dict], top_n: int = 8) -> list[tuple]:
    """Return the top-N highest-risk source IPs from a list of events.

    Args:
        results: List of classified event dicts.
        top_n:   Number of top hosts to return.

    Returns:
        Sorted list of (ip, {'score': int, 'events': int}) tuples.
    """
    scores = compute_risk_scores(results)
    return sorted(scores.items(), key=lambda x: x[1]["score"], reverse=True)[:top_n]


# ── Summary builder ────────────────────────────────────────────────────────────

def build_summary(results: list[dict]) -> dict:
    """Aggregate a list of classified events into a summary statistics dict.

    Args:
        results: List of event dicts produced by the analysis pipeline.

    Returns:
        Dict containing:
            total, sev (severity counts), protos (protocol counts),
            categories (category counts), top_talkers, unique_ips,
            threats (count of CRITICAL+HIGH), threat_pct, top_risks.
    """
    total = len(results)
    sev_c = Counter(r["severity"] for r in results)
    proto_c = Counter(r.get("proto", "UNKNOWN") for r in results)
    cat_c = Counter(r["category"] for r in results)
    src_c = Counter(r["src"] for r in results)
    top_talkers = src_c.most_common(5)
    unique_ips = len(set(r["src"] for r in results) | set(r["dst"] for r in results))
    threats = sev_c.get("CRITICAL", 0) + sev_c.get("HIGH", 0)
    threat_pct = round(threats / total * 100, 1) if total else 0

    return {
        "total": total,
        "sev": dict(sev_c),
        "protos": dict(proto_c),
        "categories": dict(cat_c),
        "top_talkers": top_talkers,
        "unique_ips": unique_ips,
        "threats": threats,
        "threat_pct": threat_pct,
        "top_risks": top_risk_hosts(results),
    }


# ── Export helpers ─────────────────────────────────────────────────────────────

def results_to_csv_string(results: list[dict]) -> str:
    """Serialize a list of event dicts to a CSV-formatted string.

    Args:
        results: List of event dicts.

    Returns:
        CSV string with headers.
    """
    if not results:
        return ""
    fields = ["id", "ts", "src", "dst", "proto", "port",
              "severity", "category", "desc", "recommendation"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(results)
    return buf.getvalue()


def results_to_json_string(results: list[dict]) -> str:
    """Serialize a list of event dicts to a JSON-formatted string.

    Args:
        results: List of event dicts.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps(
        {"exported": now_str(), "count": len(results), "data": results},
        indent=2,
        default=str,
    )


# ── Console formatting ─────────────────────────────────────────────────────────

def print_banner(title: str, width: int = 65) -> None:
    """Print a formatted banner to stdout.

    Args:
        title: Text to display in the banner.
        width: Banner width in characters.
    """
    border = "═" * width
    print(f"\n{border}")
    print(f"  {title}")
    print(f"{border}\n")


def print_section(heading: str) -> None:
    """Print a section heading separator.

    Args:
        heading: Section heading text.
    """
    print(f"\n── {heading} " + "─" * (50 - len(heading)))
