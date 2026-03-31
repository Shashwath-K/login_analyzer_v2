"""
simulations/brute_force_test.py
================================
Generates synthetic brute-force login attack log entries and appends them
to data/login_logs.csv for testing the analysis pipeline.

A brute-force attack is characterised by:
    - Single target username
    - Many password attempts in quick succession
    - High request rate (automated tool)
    - All attempts from one IP address

Usage:
    python simulations/brute_force_test.py
    python simulations/brute_force_test.py --attempts 25 --ip 10.0.0.99 --user admin
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

# Common brute-force password list (realistic wordlist fragment)
BRUTE_PASSWORDS = [
    "password", "123456", "qwerty", "admin", "letmein", "monkey", "dragon",
    "master", "111111", "sunshine", "password1", "iloveyou", "princess",
    "welcome", "shadow", "superman", "michael", "football", "batman",
    "trustno1", "baseball", "abc123", "thomas", "charlie", "robert",
    "daniel", "andrew", "hunter", "joshua", "george", "hockey", "pepper",
    "buster", "cheese", "tigger", "ranger", "access", "thunder", "dallas",
    "mustang", "testing", "123qwe", "pass1234", "admin123", "root123",
]


def generate_brute_force_logs(
    ip: str,
    username: str,
    num_attempts: int,
    start_time: datetime.datetime,
    interval_seconds: float = 1.0,
) -> list[dict]:
    """Generate brute-force attack log rows targeting a single account.

    Args:
        ip:               Source IP address of the attacker.
        username:         Target username being attacked.
        num_attempts:     Total number of password attempts to generate.
        start_time:       Datetime of the first attempt.
        interval_seconds: Seconds between each attempt (default 1.0).

    Returns:
        List of login log dicts (all failures, representing automated password guessing).
    """
    rows = []
    current_time = start_time

    # Use a shuffled slice of the password list
    passwords = random.sample(BRUTE_PASSWORDS * 3, min(num_attempts, len(BRUTE_PASSWORDS) * 3))

    for i in range(num_attempts):
        password = passwords[i] if i < len(passwords) else f"password{i}"
        row = {
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "ip_address": ip,
            "status": "failure",
            "password_used": password,
            "device": "Unknown",
            "location": "Unknown",
        }
        rows.append(row)
        current_time += datetime.timedelta(seconds=interval_seconds)

    return rows


def append_to_csv(rows: list[dict], filepath: str) -> None:
    """Append generated log rows to the login_logs.csv file.

    Args:
        rows:     List of log row dicts to append.
        filepath: Path to the CSV file.
    """
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
        description="Generate synthetic brute-force login attack entries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--attempts", type=int, default=20,
                        help="Number of password attempts to generate")
    parser.add_argument("--ip", default="192.168.99.1",
                        help="Attacker IP address")
    parser.add_argument("--user", default="admin",
                        help="Target username")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds between each attempt")
    parser.add_argument("--output", default=DATA_PATH,
                        help="Output CSV filepath")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    start = datetime.datetime.now()

    print(f"[INFO] Generating {args.attempts} brute-force entries from {args.ip} → '{args.user}'")
    rows = generate_brute_force_logs(args.ip, args.user, args.attempts, start, args.interval)
    append_to_csv(rows, args.output)
    print(f"[OK]   {len(rows)} rows appended to: {args.output}")
    print(f"       Attack window: {args.attempts * args.interval:.0f} seconds")
    print(f"       Rate: {1 / args.interval:.2f} attempts/second")
