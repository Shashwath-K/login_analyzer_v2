"""
simulations/dictionary_attack_test.py
=======================================
Generates synthetic dictionary attack login log entries.

A dictionary attack is characterised by:
    - Single target username
    - Passwords from a curated dictionary / wordlist (common phrases, variations)
    - Slower pace than brute force (to evade lockout)
    - Each password tried at most once or twice

Usage:
    python simulations/dictionary_attack_test.py
    python simulations/dictionary_attack_test.py --words 40 --ip 178.128.99.1 --user root
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

# Simulated dictionary wordlist (common passwords and variations)
DICTIONARY_WORDS = [
    "password", "password1", "Password1", "P@ssword", "p@$$word",
    "welcome", "Welcome1", "W3lcome!", "welcome123",
    "summer2024", "winter2024", "spring2024", "fall2024", "autumn2024",
    "monkey", "monkey1", "m0nkey", "Monkey!", "monkey123",
    "baseball", "Basketball", "football", "Football1", "soccer",
    "starwars", "StarWars1", "star.wars", "Starwars!",
    "batman", "Batman1", "Batman!", "b@tman",
    "superman", "Superman1", "sup3rman", "S@perman",
    "qwerty123", "Qwerty123", "qwerty!", "QWERTY1",
    "abc123", "Abc123!", "abc@123", "ABC123",
    "iloveyou", "iloveyou1", "ILoveYou!", "il0veyou",
    "sunshine", "Sunshine1", "sunsh!ne", "SunShine",
    "chocolate", "Chocolate1", "ch0c0late",
    "princess", "Princess1", "pr!ncess",
    "dragon", "Dragon1", "dr@gon", "Dragon!",
    "master", "Master1", "m@ster", "Master!",
    "shadow", "Shadow1", "sh@dow", "Shadow!",
    "access", "Access1", "acc3ss", "Access!",
    "pepper", "Pepper1", "p3pper", "Pepper!",
    "tigger", "Tigger1", "t!gger", "Tigger!",
    "google", "Google1", "g00gle", "Google!",
    "cheese", "Cheese1", "ch33se", "Cheese!",
]


def generate_dictionary_attack_logs(
    ip: str,
    username: str,
    wordlist: list[str],
    start_time: datetime.datetime,
    interval_seconds: float = 6.0,
) -> list[dict]:
    """Generate dictionary attack log rows using a password wordlist.

    Args:
        ip:               Attacker IP address.
        username:         Single target username.
        wordlist:         List of passwords from the dictionary.
        start_time:       Datetime of the first attempt.
        interval_seconds: Seconds between attempts (slower = evades lockout).

    Returns:
        List of login log dicts (all failures from wordlist exhaustion).
    """
    rows = []
    current_time = start_time

    for password in wordlist:
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
        description="Generate synthetic dictionary attack login entries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--words", type=int, default=30,
                        help="Number of dictionary words to attempt")
    parser.add_argument("--ip", default="178.128.99.10",
                        help="Attacker IP address")
    parser.add_argument("--user", default="root",
                        help="Target username")
    parser.add_argument("--interval", type=float, default=6.0,
                        help="Seconds between each attempt (slower = stealth)")
    parser.add_argument("--output", default=DATA_PATH,
                        help="Output CSV filepath")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    start = datetime.datetime.now()

    wordlist = random.sample(DICTIONARY_WORDS, min(args.words, len(DICTIONARY_WORDS)))
    print(f"[INFO] Generating {len(wordlist)} dictionary attack entries from {args.ip} → '{args.user}'")
    rows = generate_dictionary_attack_logs(args.ip, args.user, wordlist, start, args.interval)
    append_to_csv(rows, args.output)
    print(f"[OK]   {len(rows)} rows appended to: {args.output}")
    print(f"       Attack window: {len(wordlist) * args.interval:.0f} seconds")
    print(f"       Rate: {1 / args.interval:.4f} attempts/second (slow / stealthy)")
