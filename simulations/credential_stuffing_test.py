"""
simulations/credential_stuffing_test.py
=========================================
Generates synthetic credential stuffing attack log entries.

A credential stuffing attack is characterised by:
    - Many different usernames, each paired with a unique password
    - Credentials sourced from real leaked (username, password) pairs
    - Each pair tried only once or a few times
    - High username diversity — one credential pair per unique account

Usage:
    python simulations/credential_stuffing_test.py
    python simulations/credential_stuffing_test.py --pairs 30 --ip 45.33.32.200
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

# Simulated leaked credential pairs (username, password)
LEAKED_CREDENTIALS = [
    ("alice", "P@ssw0rd1"), ("bob", "Secur3#2024"), ("carol", "C@r0lPass!"),
    ("dave", "D@ve2024!"), ("eve", "Ev3ning#9"), ("frank", "Fr@nk!789"),
    ("george", "G30rge#1"), ("henry", "H3nry@99"), ("irene", "Ir3n3!2024"),
    ("john", "J0hn$2024"), ("karen", "K@r3n!99"), ("leo", "L30#2024"),
    ("mary", "M@ry2024!"), ("nick", "N!ck@2024"), ("olivia", "0livia#99"),
    ("peter", "P3t3r!789"), ("quinn", "Qu!nn@99"), ("rachel", "R@ch3l!24"),
    ("sam", "S@m2024!"), ("tony", "T0ny#2024"), ("uma", "Um@#2024"),
    ("victor", "V!ct0r99"), ("wendy", "W3ndy@24"), ("xavier", "X@v13r!"),
    ("yvonne", "Yv0nn3#9"), ("zara", "Z@ra2024!"), ("alex", "Al3x!pass"),
    ("blake", "Bl@k3#99"), ("casey", "C@s3y2024"), ("drew", "Dr3w!2024"),
    ("elliot", "El!i0t#24"), ("finley", "F!nl3y99"), ("grace", "Gr@c3!24"),
    ("hayden", "H@yd3n99"), ("indigo", "Ind!g0#24"), ("jordan", "J0rd@n!"),
    ("kendall", "K3nd@ll24"), ("liam", "L!@m2024"), ("morgan", "M0rg@n!"),
    ("noah", "N0@h2024!"),
]


def generate_credential_stuffing_logs(
    ip: str,
    credentials: list[tuple],
    start_time: datetime.datetime,
    interval_seconds: float = 3.0,
) -> list[dict]:
    """Generate credential stuffing log rows — one unique (user, password) pair per attempt.

    Args:
        ip:               Attacker IP address.
        credentials:      List of (username, password) tuples from a leaked database.
        start_time:       Start datetime of the attack.
        interval_seconds: Seconds between each credential attempt.

    Returns:
        List of login log dicts representing credential stuffing attempts.
    """
    rows = []
    current_time = start_time

    for username, password in credentials:
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
        description="Generate synthetic credential stuffing attack entries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--pairs", type=int, default=20,
                        help="Number of credential pairs to attempt")
    parser.add_argument("--ip", default="91.108.4.100",
                        help="Attacker IP address")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="Seconds between each credential attempt")
    parser.add_argument("--output", default=DATA_PATH,
                        help="Output CSV filepath")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    start = datetime.datetime.now()

    creds = random.sample(LEAKED_CREDENTIALS, min(args.pairs, len(LEAKED_CREDENTIALS)))
    print(f"[INFO] Generating {len(creds)} credential stuffing entries from {args.ip}")
    rows = generate_credential_stuffing_logs(args.ip, creds, start, args.interval)
    append_to_csv(rows, args.output)
    print(f"[OK]   {len(rows)} rows appended to: {args.output}")
    print(f"       Unique usernames: {len(set(r['username'] for r in rows))}")
    print(f"       Unique passwords: {len(set(r['password_used'] for r in rows))}")
