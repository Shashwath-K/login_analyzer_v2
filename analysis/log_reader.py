"""
analysis/log_reader.py
======================
Reads and validates login log data from various sources.

Responsibilities:
    - Read login logs from CSV files (login_logs.csv) using pandas
    - Parse raw text-based log files (tab/comma-delimited)
    - Parse binary PCAP files without external dependencies (pure struct)
    - Validate and normalise log entries before analysis
    - Return a consistent list-of-tuples format used throughout the pipeline
"""

import re
import struct
import socket
import datetime
import os
import sys

# pandas is used only for CSV reading; gracefully degrade if unavailable
try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False

# ── Expected CSV columns ───────────────────────────────────────────────────────

LOGIN_LOG_COLUMNS = [
    "timestamp", "username", "ip_address", "status",
    "password_used", "device", "location",
]

# Tuple field order used throughout the analysis pipeline:
# (timestamp, src_ip, dst_ip, proto, port, description, severity)
_DEFAULT_SEVERITY = "INFO"


# ── CSV log reader (login_logs.csv) ───────────────────────────────────────────

def read_login_logs_csv(filepath: str) -> list[dict]:
    """Read and validate a login log CSV file into a list of row dicts.

    Each row must contain at minimum: timestamp, username, ip_address, status.
    Optional columns (password_used, device, location) are filled with defaults
    when missing.

    Args:
        filepath: Path to the CSV file (e.g., 'data/login_logs.csv').

    Returns:
        List of dicts, one per valid log row.

    Raises:
        FileNotFoundError: If the CSV file does not exist.
        ValueError: If required columns are missing.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Login log file not found: {filepath}")

    if not _PANDAS_AVAILABLE:
        return _read_login_logs_csv_stdlib(filepath)

    df = pd.read_csv(filepath, dtype=str).fillna("")

    # Validate required columns
    required = {"timestamp", "username", "ip_address", "status"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Login log CSV is missing required columns: {missing}")

    # Fill optional columns with defaults
    for col, default in [("password_used", ""), ("device", "Unknown"), ("location", "Unknown")]:
        if col not in df.columns:
            df[col] = default

    # Strip whitespace from all string columns
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)

    return df.to_dict(orient="records")


def _read_login_logs_csv_stdlib(filepath: str) -> list[dict]:
    """Fallback CSV reader using the standard library (no pandas).

    Args:
        filepath: Path to the CSV file.

    Returns:
        List of row dicts.
    """
    import csv
    rows = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k: (v.strip() if v else "") for k, v in row.items()})
    return rows


# ── Convert login log rows to analysis pipeline tuple format ──────────────────

def login_logs_to_tuples(log_rows: list[dict]) -> list[tuple]:
    """Convert login log dicts (from CSV) to the 7-field tuple format used by
    the analysis pipeline and pattern detector.

    Output tuple fields: (timestamp, src_ip, dst_ip, proto, port, description, severity)

    - src_ip   → ip_address from log
    - dst_ip   → '0.0.0.0' (login logs don't record destination)
    - proto    → 'HTTP' for failed attempts, 'HTTPS' for successful
    - port     → 80 for failure, 443 for success
    - desc     → 'Login {status}: {username} (pwd: {password_used})'
    - severity → 'CRITICAL' for failure, 'INFO' for success

    Args:
        log_rows: List of login log dicts.

    Returns:
        List of 7-element tuples.
    """
    tuples = []
    for row in log_rows:
        ts = row.get("timestamp", now_str())
        src = row.get("ip_address", "0.0.0.0")
        dst = "0.0.0.0"
        status = row.get("status", "").lower()
        username = row.get("username", "unknown")
        password = row.get("password_used", "")
        device = row.get("device", "Unknown")

        if status == "failure":
            proto = "HTTP"
            port = 80
            desc = f"Login Failed: {username} | pwd: {password} | device: {device}"
            severity = "CRITICAL"
        else:
            proto = "HTTPS"
            port = 443
            desc = f"Login Success: {username} | device: {device}"
            severity = "INFO"

        tuples.append((ts, src, dst, proto, port, desc, severity))

    return tuples


# ── Text / syslog parser ──────────────────────────────────────────────────────

def parse_text_log(text: str) -> list[tuple]:
    """Parse a raw text-based log file into analysis pipeline tuples.

    Supports both tab-delimited and comma-delimited formats with at least
    6 columns (timestamp, src, dst, proto, port, description[, severity]).
    Lines that do not match are parsed loosely by extracting the first IP found.

    Args:
        text: Raw string content of the log file.

    Returns:
        List of 7-element tuples: (timestamp, src, dst, proto, port, desc, severity).
    """
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = re.split(r"\t|,", line)
        if len(parts) >= 6:
            try:
                row = (
                    parts[0].strip(),
                    parts[1].strip(),
                    parts[2].strip(),
                    parts[3].strip(),
                    parts[4].strip(),
                    parts[5].strip(),
                    parts[6].strip() if len(parts) > 6 else _DEFAULT_SEVERITY,
                )
                rows.append(row)
                continue
            except IndexError:
                pass

        # Loose fallback: grab first IP from line as src
        ip_match = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line)
        rows.append((
            now_str(),
            ip_match.group(0) if ip_match else "0.0.0.0",
            "0.0.0.0",
            "UNKNOWN",
            0,
            line[:120],
            _DEFAULT_SEVERITY,
        ))

    return rows


# ── PCAP parser (pure Python, no scapy required) ──────────────────────────────

def parse_pcap(data: bytes) -> list[tuple]:
    """Parse a PCAP binary file into analysis pipeline tuples.

    Supports both little-endian and big-endian PCAP global headers.
    Decodes Ethernet → IPv4 → TCP/UDP/ICMP packets.
    Does NOT require scapy or any external library.

    Args:
        data: Raw bytes content of the .pcap file.

    Returns:
        List of 7-element tuples, or an empty list on parse failure.
    """
    rows = []
    if len(data) < 24:
        return rows

    # Detect endianness from magic number
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
        return rows  # not a valid PCAP file

    endian = "<" if magic == 0xA1B2C3D4 else ">"
    link_type = struct.unpack_from(f"{endian}I", data, 20)[0]
    offset = 24

    while offset + 16 <= len(data):
        ts_sec, _, inc_len, _ = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16

        if offset + inc_len > len(data):
            break

        packet = data[offset : offset + inc_len]
        offset += inc_len

        ts = datetime.datetime.fromtimestamp(ts_sec).strftime("%Y-%m-%d %H:%M:%S")
        src = dst = proto = "N/A"
        port = 0
        desc = "Raw packet"

        try:
            if link_type == 1 and len(packet) >= 14:
                ether_type = struct.unpack_from(">H", packet, 12)[0]

                if ether_type == 0x0800 and len(packet) >= 34:
                    ip_header_len = (packet[14] & 0x0F) * 4
                    proto_num = packet[23]
                    src = socket.inet_ntoa(packet[26:30])
                    dst = socket.inet_ntoa(packet[30:34])
                    proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, str(proto_num))

                    transport_offset = 14 + ip_header_len
                    if proto_num in (6, 17) and len(packet) >= transport_offset + 4:
                        src_port, dst_port = struct.unpack_from(">HH", packet, transport_offset)
                        port = dst_port
                        desc = f"Port {src_port}→{dst_port}"
                    elif proto_num == 1:
                        desc = "ICMP packet"

                elif ether_type == 0x0806:
                    proto = "ARP"
                    desc = "ARP packet"
        except Exception:
            pass

        rows.append((ts, src, dst, proto, port, desc, _DEFAULT_SEVERITY))

    return rows


# ── Validation helpers ─────────────────────────────────────────────────────────

def validate_tuple_row(row: tuple | list) -> tuple | None:
    """Validate and normalise a single log tuple.

    Ensures all 7 fields are present and have correct types.

    Args:
        row: A tuple or list with up to 7 fields.

    Returns:
        Normalised 7-element tuple, or None if the row is irrecoverably invalid.
    """
    if len(row) == 7:
        ts, src, dst, proto, port, desc, sev = row
    elif len(row) == 6:
        ts, src, dst, proto, port, desc = row
        sev = _DEFAULT_SEVERITY
    else:
        return None

    return (
        str(ts),
        str(src),
        str(dst),
        str(proto),
        str(port),
        str(desc),
        str(sev) if sev in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") else _DEFAULT_SEVERITY,
    )


# ── Timestamp helper (avoids circular import with utils.helpers) ───────────────

def now_str() -> str:
    """Return the current datetime as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
