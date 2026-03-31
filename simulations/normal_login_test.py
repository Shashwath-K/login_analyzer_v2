"""
simulations/normal_login_test.py
==================================
Generates synthetic normal (legitimate) login log entries as a baseline.

Normal login behaviour is characterised by:
    - Known users from corporate IP ranges
    - Low failure counts (typos / forgotten passwords)
    - Spread across business hours — not bursty
    - Realistic success rate (~85–95%)
    - Consistent device and location per user

Usage:
    python simulations/normal_login_test.py
    python simulations/normal_login_test.py --events 50 --users alice bob carol
"""

import os
import sys
import csv
import argparse
import datetime
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "login_logs.csv",
)

# Realistic corporate user profiles
USER_PROFILES = [
    {"username": "alice",   "ip": "192.168.1.10", "device": "Windows", "location": "New York",  "password": "P@ssw0rd1"},
    {"username": "bob",     "ip": "192.168.1.11", "device": "macOS",   "location": "London",    "password": "Secur3#2024"},
    {"username": "carol",   "ip": "10.0.0.5",     "device": "Linux",   "location": "Paris",     "password": "C@r0lPass!"},
    {"username": "dave",    "ip": "192.168.1.20", "device": "Windows", "location": "Tokyo",     "password": "D@ve2024!"},
    {"username": "eve",     "ip": "172.16.0.10",  "device": "macOS",   "location": "Sydney",    "password": "Ev3ning#9"},
    {"username": "frank",   "ip": "192.168.1.30", "device": "Linux",   "location": "Berlin",    "password": "Fr@nk!789"},
    {"username": "george",  "ip": "10.0.0.12",    "device": "Windows", "location": "Toronto",   "password": "G30rge#1"},
    {"username": "henry",   "ip": "192.168.1.40", "device": "macOS",   "location": "Singapore", "password": "H3nry@99"},
    {"username": "irene",   "ip": "10.0.0.20",    "device": "Windows", "location": "Dubai",     "password": "Ir3n3!2024"},
    {"username": "john",    "ip": "192.168.1.50", "device": "Linux",   "location": "Mumbai",    "password": "J0hn$2024"},
]

# Business hours range (hours in 24h format)
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 19


def generate_normal_login_logs(
    user_profiles: list[dict],
    num_events: int,
    start_date: datetime.date,
    success_rate: float = 0.92,
) -> list[dict]:
    """Generate normal legitimate login event logs.

    Args:
        user_profiles: List of user profile dicts with username, ip, device, location, password.
        num_events:    Total number of login events to generate.
        start_date:    Date to start generating events from.
        success_rate:  Fraction of logins that succeed (default: 0.92 = 92%).

    Returns:
        List of login log dicts representing normal user activity.
    """
    rows = []

    # Distribute events across the day during business hours
    base_dt = datetime.datetime.combine(start_date, datetime.time(BUSINESS_HOURS_START, 0, 0))
    total_seconds = (BUSINESS_HOURS_END - BUSINESS_HOURS_START) * 3600

    event_times = sorted(
        base_dt + datetime.timedelta(seconds=random.randint(0, total_seconds))
        for _ in range(num_events)
    )

    for ts in event_times:
        user = random.choice(user_profiles)
        is_success = random.random() < success_rate
        status = "success" if is_success else "failure"

        # On failure, user types a wrong password (realistic typo or forgotten)
        if is_success:
            password = user["password"]
        else:
            password = _simulate_typo(user["password"])

        row = {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": user["username"],
            "ip_address": user["ip"],
            "status": status,
            "password_used": password,
            "device": user["device"],
            "location": user["location"],
        }
        rows.append(row)

    return rows


def _simulate_typo(password: str) -> str:
    """Simulate a realistic password typo.

    Args:
        password: The correct password string.

    Returns:
        A slightly modified version of the password (common typo patterns).
    """
    if not password:
        return "wrongpassword"
    typo_kind = random.choice(["suffix", "prefix", "truncate", "caps"])
    if typo_kind == "suffix":
        return password + random.choice(["1", "!", ".", "_", "2"])
    elif typo_kind == "prefix":
        return random.choice(["x", "1", "_"]) + password
    elif typo_kind == "truncate":
        return password[:-1] if len(password) > 4 else password + "x"
    else:
        return password.swapcase()


def append_to_csv(rows: list[dict], filepath: str) -> None:
    """Append generated log rows to the login_logs.csv file."""
    file_exists = os.path.exists(filepath)
    with open(filepath, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "username", "ip_address", "status",
            "password_used", "device", "location",
        ])
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic normal (legitimate) login entries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--events", type=int, default=40,
                        help="Number of login events to generate")
    parser.add_argument("--date", default=None,
                        help="Date to generate events for (YYYY-MM-DD), default: today")
    parser.add_argument("--success-rate", type=float, default=0.92,
                        help="Fraction of logins that succeed [0.0–1.0]")
    parser.add_argument("--output", default=DATA_PATH,
                        help="Output CSV filepath")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.date:
        try:
            start_date = datetime.date.fromisoformat(args.date)
        except ValueError:
            print(f"[ERROR] Invalid date format: {args.date}. Use YYYY-MM-DD.")
            sys.exit(1)
    else:
        start_date = datetime.date.today()

    print(f"[INFO] Generating {args.events} normal login events for {start_date}")
    rows = generate_normal_login_logs(
        USER_PROFILES, args.events, start_date, args.success_rate
    )
    append_to_csv(rows, args.output)

    successes = sum(1 for r in rows if r["status"] == "success")
    failures = sum(1 for r in rows if r["status"] == "failure")
    print(f"[OK]   {len(rows)} rows appended to: {args.output}")
    print(f"       Successes: {successes}  |  Failures: {failures}")
    print(f"       Success rate: {successes / len(rows) * 100:.1f}%")
