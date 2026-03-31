"""
analysis/feature_extractor.py
==============================
Converts raw login log data into numerical feature vectors for ML classification.

Responsibilities:
    - Group login log rows by source IP and time window
    - Compute features: failed_attempts, unique_usernames, time_window,
      same_password_count, request_rate
    - Return a pandas DataFrame ready for scikit-learn input
    - Also handle single-IP feature extraction for on-demand classification

Feature Definitions:
    failed_attempts     — total number of failed login attempts from this IP
    unique_usernames    — number of distinct usernames tried
    time_window         — span in seconds between first and last attempt
    same_password_count — number of attempts using the same password repeatedly
    request_rate        — attempts per second (failed_attempts / time_window)
"""

import datetime
from collections import Counter

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False

from utils.helpers import parse_timestamp


# ── Minimum window to avoid division-by-zero ──────────────────────────────────
_MIN_WINDOW_SECONDS = 1.0


def extract_features_from_logs(log_rows: list[dict]) -> "pd.DataFrame":
    """Group login log rows by source IP and extract ML features per group.

    Each IP address gets one feature row representing all of its activity
    in the log. This is the primary entry point for batch analysis.

    Args:
        log_rows: List of login log dicts from log_reader.read_login_logs_csv().
                  Expected keys: timestamp, ip_address, username,
                                 status, password_used.

    Returns:
        pandas DataFrame with columns:
            ip_address, failed_attempts, unique_usernames,
            time_window, same_password_count, request_rate.

    Raises:
        ImportError: If pandas is not installed.
    """
    if not _PANDAS_AVAILABLE:
        raise ImportError(
            "pandas is required for feature extraction. "
            "Install it with: pip install pandas"
        )

    # Group rows by IP address
    ip_groups: dict[str, list[dict]] = {}
    for row in log_rows:
        ip = row.get("ip_address", "0.0.0.0")
        ip_groups.setdefault(ip, []).append(row)

    feature_rows = []
    for ip, rows in ip_groups.items():
        features = _compute_features_for_group(ip, rows)
        feature_rows.append(features)

    if not feature_rows:
        return pd.DataFrame(columns=[
            "ip_address", "failed_attempts", "unique_usernames",
            "time_window", "same_password_count", "request_rate",
        ])

    return pd.DataFrame(feature_rows)


def extract_features_for_ip(ip: str, rows: list[dict]) -> dict:
    """Extract ML features for a single IP address's login activity.

    Useful for on-demand classification of a specific IP without processing
    the entire log file.

    Args:
        ip:   The IP address string.
        rows: All login log rows associated with this IP.

    Returns:
        Feature dict with keys matching the DataFrame columns above.
    """
    return _compute_features_for_group(ip, rows)


def _compute_features_for_group(ip: str, rows: list[dict]) -> dict:
    """Compute the 5 ML features for a group of rows from one source IP.

    Args:
        ip:   Source IP address.
        rows: All log rows from this IP.

    Returns:
        Dict containing ip_address + 5 numeric features.
    """
    # Only count failed attempts for attack-pattern features
    failures = [r for r in rows if r.get("status", "").lower() == "failure"]

    failed_attempts = len(failures)

    # Count distinct usernames tried across all failures
    usernames = [r.get("username", "") for r in failures]
    unique_usernames = len(set(u for u in usernames if u))

    # Time window: span from first to last event (including successes)
    timestamps = []
    for r in rows:
        ts = parse_timestamp(r.get("timestamp", ""))
        if ts:
            timestamps.append(ts)

    if len(timestamps) >= 2:
        time_window = max(
            (max(timestamps) - min(timestamps)).total_seconds(),
            _MIN_WINDOW_SECONDS,
        )
    else:
        time_window = _MIN_WINDOW_SECONDS

    # Most repeated password count (same password = likely brute force or spray)
    passwords = [r.get("password_used", "") for r in failures if r.get("password_used")]
    if passwords:
        password_counts = Counter(passwords)
        same_password_count = password_counts.most_common(1)[0][1]
    else:
        same_password_count = 0

    # Request rate: failed attempts per second
    request_rate = round(failed_attempts / time_window, 4)

    return {
        "ip_address": ip,
        "failed_attempts": failed_attempts,
        "unique_usernames": unique_usernames,
        "time_window": round(time_window, 2),
        "same_password_count": same_password_count,
        "request_rate": request_rate,
    }


def get_feature_columns() -> list[str]:
    """Return the ordered list of feature column names used by the ML model.

    These must match the columns used during model training in train_model.py.

    Returns:
        List of feature column name strings.
    """
    return [
        "failed_attempts",
        "unique_usernames",
        "time_window",
        "same_password_count",
        "request_rate",
    ]


def features_to_dict_list(df: "pd.DataFrame") -> list[dict]:
    """Convert a feature DataFrame to a list of plain dicts.

    Useful for passing features to the classifier without pandas dependency.

    Args:
        df: Feature DataFrame from extract_features_from_logs().

    Returns:
        List of feature dicts (one per IP).
    """
    if not _PANDAS_AVAILABLE:
        return []
    return df.to_dict(orient="records")
