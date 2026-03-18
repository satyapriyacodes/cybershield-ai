"""
Synthetic Security Log Generator
Produces 1000+ realistic log entries with controlled anomaly injection.
Run: python src/data/log_generator.py
"""

import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from faker import Faker
import os

fake = Faker()
random.seed(42)
np.random.seed(42)

# --- Config ---
TOTAL_LOGS = 1200
ANOMALY_RATIO = 0.10

NORMAL_IPS = [fake.ipv4_private() for _ in range(50)]
SUSPICIOUS_IPS = [
    "185.220.101.47",  # Tor exit node
    "91.92.248.11",    # Romania
    "194.165.16.100",  # Russia
    "103.76.228.50",   # China
    "45.142.212.100",  # Netherlands (VPN)
    "95.214.55.0",     # Eastern Europe
    "2.58.56.201",     # Romania 2
    "185.234.218.21",  # Russia 2
]

USERS = [f"user_{i:03d}" for i in range(1, 51)]
DEVICES = ["Windows 10", "MacOS Ventura", "Ubuntu 22.04", "iOS 17", "Android 14"]
LOCATIONS_NORMAL = ["New York, US", "Los Angeles, US", "Chicago, US", "Austin, US", "Seattle, US"]
LOCATIONS_SUSPICIOUS = ["Bucharest, Romania", "Moscow, Russia", "Shanghai, China", "Amsterdam, Netherlands"]
ACTIONS = ["LOGIN", "LOGOUT", "FILE_ACCESS", "ADMIN_PANEL", "PASSWORD_CHANGE", "DATA_EXPORT", "SSH_LOGIN"]


def random_business_timestamp(base_date):
    """Business hours: Mon-Fri, 8AM-7PM."""
    hour = random.randint(8, 19)
    minute = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute, second=random.randint(0, 59))


def random_night_timestamp(base_date):
    """Unusual hours: 2AM-5AM."""
    hour = random.randint(2, 5)
    minute = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute, second=random.randint(0, 59))


def generate_normal_log(base_date):
    user = random.choice(USERS)
    ts = random_business_timestamp(base_date)
    return {
        "timestamp": ts.isoformat(),
        "user": user,
        "ip_address": random.choice(NORMAL_IPS),
        "action": random.choice(ACTIONS),
        "status": "SUCCESS" if random.random() < 0.95 else "FAILURE",
        "location": random.choice(LOCATIONS_NORMAL),
        "device": random.choice(DEVICES),
        "failed_attempts": random.randint(0, 1),
        "session_duration_min": random.randint(5, 480),
        "bytes_transferred": random.randint(100, 50000),
        "anomaly_label": "normal",
    }


def generate_brute_force_logs(base_date, user=None, ip=None):
    """Generate multiple failed login attempts."""
    if user is None:
        user = random.choice(USERS)
    if ip is None:
        ip = random.choice(SUSPICIOUS_IPS)
    ts = random_business_timestamp(base_date)
    logs = []
    attempt_count = random.randint(6, 20)
    for i in range(attempt_count):
        attempt_ts = ts + timedelta(seconds=i * 30)
        logs.append({
            "timestamp": attempt_ts.isoformat(),
            "user": user,
            "ip_address": ip,
            "action": "LOGIN",
            "status": "FAILURE" if i < attempt_count - 1 else random.choice(["FAILURE", "SUCCESS"]),
            "location": random.choice(LOCATIONS_SUSPICIOUS),
            "device": random.choice(DEVICES),
            "failed_attempts": i + 1,
            "session_duration_min": 0,
            "bytes_transferred": 0,
            "anomaly_label": "brute_force",
        })
    return logs


def generate_unusual_time_log(base_date):
    user = random.choice(USERS)
    ts = random_night_timestamp(base_date)
    return {
        "timestamp": ts.isoformat(),
        "user": user,
        "ip_address": random.choice(SUSPICIOUS_IPS),
        "action": random.choice(["FILE_ACCESS", "DATA_EXPORT", "ADMIN_PANEL"]),
        "status": "SUCCESS",
        "location": random.choice(LOCATIONS_SUSPICIOUS),
        "device": random.choice(DEVICES),
        "failed_attempts": 0,
        "session_duration_min": random.randint(30, 240),
        "bytes_transferred": random.randint(100000, 1000000),
        "anomaly_label": "unusual_time",
    }


def generate_geo_anomaly_log(base_date):
    user = random.choice(USERS)
    ts = random_business_timestamp(base_date)
    return {
        "timestamp": ts.isoformat(),
        "user": user,
        "ip_address": random.choice(SUSPICIOUS_IPS),
        "action": "LOGIN",
        "status": "SUCCESS",
        "location": random.choice(LOCATIONS_SUSPICIOUS),
        "device": random.choice(DEVICES),
        "failed_attempts": 0,
        "session_duration_min": random.randint(5, 60),
        "bytes_transferred": random.randint(1000, 100000),
        "anomaly_label": "geo_anomaly",
    }


def generate_impossible_travel_log(base_date):
    user = random.choice(USERS)
    ts = random_business_timestamp(base_date)
    log1 = {
        "timestamp": ts.isoformat(),
        "user": user,
        "ip_address": random.choice(NORMAL_IPS),
        "action": "LOGIN",
        "status": "SUCCESS",
        "location": "New York, US",
        "device": "Windows 10",
        "failed_attempts": 0,
        "session_duration_min": 10,
        "bytes_transferred": 5000,
        "anomaly_label": "impossible_travel",
    }
    # 15 minutes later from another continent
    ts2 = ts + timedelta(minutes=15)
    log2 = {
        "timestamp": ts2.isoformat(),
        "user": user,
        "ip_address": random.choice(SUSPICIOUS_IPS),
        "action": "LOGIN",
        "status": "SUCCESS",
        "location": "Moscow, Russia",
        "device": "Ubuntu 22.04",
        "failed_attempts": 0,
        "session_duration_min": 30,
        "bytes_transferred": 50000,
        "anomaly_label": "impossible_travel",
    }
    return [log1, log2]


def generate_privilege_escalation_log(base_date):
    user = random.choice(USERS)
    ts = random_business_timestamp(base_date)
    return {
        "timestamp": ts.isoformat(),
        "user": user,
        "ip_address": random.choice(NORMAL_IPS),
        "action": "ADMIN_PANEL",
        "status": "SUCCESS",
        "location": random.choice(LOCATIONS_NORMAL),
        "device": random.choice(DEVICES),
        "failed_attempts": 0,
        "session_duration_min": random.randint(60, 300),
        "bytes_transferred": random.randint(500000, 5000000),
        "anomaly_label": "privilege_escalation",
    }


def generate_logs():
    logs = []
    base_date = datetime(2024, 1, 1)
    target_anomaly = int(TOTAL_LOGS * ANOMALY_RATIO)
    target_normal = TOTAL_LOGS - target_anomaly

    # Normal logs
    for i in range(target_normal):
        day_offset = random.randint(0, 89)
        date = base_date + timedelta(days=day_offset)
        logs.append(generate_normal_log(date))

    # Anomalous logs (various types)
    anomaly_types = [
        "brute_force", "unusual_time", "geo_anomaly", "impossible_travel", "privilege_escalation"
    ]
    per_type = target_anomaly // len(anomaly_types)

    for _ in range(per_type):
        day_offset = random.randint(0, 89)
        date = base_date + timedelta(days=day_offset)
        logs.extend(generate_brute_force_logs(date))

    for _ in range(per_type):
        day_offset = random.randint(0, 89)
        date = base_date + timedelta(days=day_offset)
        logs.append(generate_unusual_time_log(date))

    for _ in range(per_type):
        day_offset = random.randint(0, 89)
        date = base_date + timedelta(days=day_offset)
        logs.append(generate_geo_anomaly_log(date))

    for _ in range(per_type):
        day_offset = random.randint(0, 89)
        date = base_date + timedelta(days=day_offset)
        logs.extend(generate_impossible_travel_log(date))

    for _ in range(per_type):
        day_offset = random.randint(0, 89)
        date = base_date + timedelta(days=day_offset)
        logs.append(generate_privilege_escalation_log(date))

    # Shuffle and create DataFrame
    random.shuffle(logs)
    df = pd.DataFrame(logs)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.index.name = "id"

    os.makedirs("data", exist_ok=True)
    df.to_csv("data/security_logs.csv", index=True)
    print(f"✅ Generated {len(df)} log entries → data/security_logs.csv")
    print(f"   Normal: {len(df[df['anomaly_label'] == 'normal'])}")
    print(f"   Anomalous: {len(df[df['anomaly_label'] != 'normal'])}")
    return df


if __name__ == "__main__":
    df = generate_logs()
    print(df["anomaly_label"].value_counts())
