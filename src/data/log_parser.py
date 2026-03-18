"""
Log Parser Module
Supports CSV, JSON, and basic syslog formats.
Normalises to a standard schema for ML/agent consumption.
"""

import json
import csv
import re
import io
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional
from loguru import logger


STANDARD_FIELDS = [
    "timestamp", "user", "ip_address", "action",
    "status", "location", "device",
    "failed_attempts", "session_duration_min", "bytes_transferred"
]


def _parse_syslog_line(line: str) -> Optional[Dict]:
    """Parse a basic syslog-format line."""
    pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+): (.*)"
    match = re.match(pattern, line.strip())
    if not match:
        return None
    timestamp_str, host, process, message = match.groups()
    current_year = datetime.now().year
    try:
        ts = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = datetime.now()

    # Extract IP from message
    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", message)
    ip = ip_match.group(1) if ip_match else "0.0.0.0"

    failed = 1 if "failed" in message.lower() or "invalid" in message.lower() else 0
    status = "FAILURE" if failed else "SUCCESS"

    return {
        "timestamp": ts.isoformat(),
        "user": host,
        "ip_address": ip,
        "action": process.upper(),
        "status": status,
        "location": "Unknown",
        "device": "Unknown",
        "failed_attempts": failed,
        "session_duration_min": 0,
        "bytes_transferred": 0,
    }


def parse_csv(content: str) -> List[Dict]:
    """Parse CSV log content."""
    df = pd.read_csv(io.StringIO(content))
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    records = []
    for _, row in df.iterrows():
        record = {}
        for field in STANDARD_FIELDS:
            record[field] = row.get(field, None)
        records.append(record)
    return records


def parse_json(content: str) -> List[Dict]:
    """Parse JSON log content (array or newline-delimited)."""
    try:
        data = json.loads(content)
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = [data]
        else:
            return []
    except json.JSONDecodeError:
        # Try newline-delimited JSON
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    records = []
    for entry in entries:
        record = {field: entry.get(field) for field in STANDARD_FIELDS}
        records.append(record)
    return records


def parse_syslog(content: str) -> List[Dict]:
    """Parse syslog-format content."""
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = _parse_syslog_line(line)
        if parsed:
            records.append(parsed)
        else:
            logger.warning(f"Could not parse syslog line: {line[:80]}")
    return records


def normalise_record(record: Dict) -> Dict:
    """Ensure all standard fields are present with sensible defaults."""
    normalised = {}
    for field in STANDARD_FIELDS:
        val = record.get(field)
        if field == "failed_attempts":
            normalised[field] = int(val) if val is not None else 0
        elif field in ("session_duration_min", "bytes_transferred"):
            normalised[field] = float(val) if val is not None else 0.0
        elif field == "status":
            normalised[field] = str(val).upper() if val else "UNKNOWN"
        else:
            normalised[field] = str(val).strip() if val else "Unknown"
    return normalised


def parse_logs(content: str, fmt: str = "csv") -> List[Dict]:
    """
    Main entry-point.
    fmt: 'csv' | 'json' | 'syslog'
    Returns list of normalised log record dicts.
    """
    fmt = fmt.lower()
    raw_records: List[Dict] = []

    if fmt == "csv":
        raw_records = parse_csv(content)
    elif fmt == "json":
        raw_records = parse_json(content)
    elif fmt == "syslog":
        raw_records = parse_syslog(content)
    else:
        raise ValueError(f"Unsupported log format: {fmt}")

    normalised = []
    for i, rec in enumerate(raw_records):
        try:
            normalised.append(normalise_record(rec))
        except Exception as e:
            logger.warning(f"Skipping malformed record {i}: {e}")

    logger.info(f"Parsed {len(normalised)} records from {fmt} format")
    return normalised


def parse_file(filepath: str) -> List[Dict]:
    """Auto-detect format from file extension and parse."""
    ext = filepath.rsplit(".", 1)[-1].lower()
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    fmt = {"csv": "csv", "json": "json", "log": "syslog", "txt": "syslog"}.get(ext, "csv")
    return parse_logs(content, fmt)
