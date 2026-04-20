#!/usr/bin/env python3
"""Traffic simulator — generates normal + attack traffic against the payment API.

Produces real logs in logs/access.jsonl that Sigma rules can detect.
Usage: python scripts/simulate-traffic.py [--base-url http://localhost:8080]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
LOG_PATH = "logs/access.jsonl"


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}")


def simulate_normal_traffic(base_url: str) -> None:
    """Normal API usage."""
    log("--- Normal traffic ---")

    # Health check
    r = requests.get(f"{base_url}/health", timeout=5)
    log(f"GET /health → {r.status_code}")

    # Successful login
    r = requests.post(
        f"{base_url}/api/login",
        json={"username": "admin", "password": "admin"},
        timeout=5,
    )
    log(f"POST /api/login → {r.status_code}")
    token = r.json().get("token", "") if r.status_code == 200 else ""

    # Create payment
    r = requests.post(
        f"{base_url}/api/payment/create",
        json={"card_number": "4111111111111111", "amount": 5000, "currency": "JPY"},
        timeout=5,
    )
    log(f"POST /api/payment/create → {r.status_code}")
    payment_id = r.json().get("payment_id", "") if r.status_code == 200 else ""

    # Confirm payment
    if payment_id:
        r = requests.post(
            f"{base_url}/api/payment/confirm",
            json={"payment_id": payment_id, "otp": "123456"},
            timeout=5,
        )
        log(f"POST /api/payment/confirm → {r.status_code}")

    # Normal export
    r = requests.get(f"{base_url}/api/export?query=confirmed", timeout=5)
    log(f"GET /api/export?query=confirmed → {r.status_code}")


def simulate_brute_force(base_url: str, attempts: int = 10) -> None:
    """Brute force login attempts (triggers Sigma: bf-001, ATT&CK T1110)."""
    log(f"--- Brute force attack ({attempts} attempts) ---")

    for i in range(attempts):
        r = requests.post(
            f"{base_url}/api/login",
            json={"username": "admin", "password": f"wrong-password-{i}"},
            timeout=5,
        )
        log(f"  Attempt {i + 1}/{attempts} → {r.status_code}")
        time.sleep(0.1)


def simulate_sql_injection(base_url: str) -> None:
    """SQL injection attempts (triggers Sigma: sqli-001, ATT&CK T1190)."""
    log("--- SQL injection attack ---")

    payloads = [
        "' OR '1'='1",
        "' UNION SELECT * FROM payments--",
        "'; DROP TABLE payments;--",
        "1 OR 1=1",
    ]

    for payload in payloads:
        r = requests.get(
            f"{base_url}/api/export",
            params={"query": payload},
            timeout=5,
        )
        log(f"  SQLi payload → {r.status_code}: {payload[:40]}")


def simulate_data_exfiltration(base_url: str) -> None:
    """Large data export (triggers Sigma: exfil-001, ATT&CK T1048)."""
    log("--- Data exfiltration ---")

    # First create many payments
    for i in range(20):
        requests.post(
            f"{base_url}/api/payment/create",
            json={"card_number": f"411111111111{i:04d}", "amount": 100 + i, "currency": "JPY"},
            timeout=5,
        )

    # Then export all
    r = requests.get(f"{base_url}/api/export?query=pending", timeout=5)
    count = r.json().get("count", 0) if r.status_code == 200 else 0
    log(f"  Exported {count} records")


def simulate_negative_payment(base_url: str) -> None:
    """Negative payment amount (business logic vulnerability)."""
    log("--- Negative payment (business logic bug) ---")

    r = requests.post(
        f"{base_url}/api/payment/create",
        json={"card_number": "4111111111111111", "amount": -5000, "currency": "JPY"},
        timeout=5,
    )
    log(f"  Negative amount (-5000 JPY) → {r.status_code} (should be 400, got {r.status_code})")


def generate_offline_logs() -> None:
    """Generate sample logs without a running server (for Sigma testing)."""
    log("--- Generating offline logs ---")

    Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)

    events = [
        # Normal traffic
        {"event_type": "api_request", "method": "GET", "path": "/health", "status": 200, "ip": "10.0.0.1"},
        {"event_type": "login_success", "username": "admin", "ip": "10.0.0.1"},
        {"event_type": "payment_created", "payment_id": "PAY-001", "amount": 5000, "currency": "JPY", "ip": "10.0.0.1"},
        {"event_type": "api_request", "method": "GET", "path": "/api/export?query=confirmed", "status": 200, "ip": "10.0.0.1"},
        # Brute force (ATT&CK T1110)
        {"event_type": "login_failed", "username": "admin", "ip": "192.168.1.100", "reason": "invalid_password"},
        {"event_type": "login_failed", "username": "admin", "ip": "192.168.1.100", "reason": "invalid_password"},
        {"event_type": "login_failed", "username": "admin", "ip": "192.168.1.100", "reason": "invalid_password"},
        {"event_type": "login_failed", "username": "admin", "ip": "192.168.1.100", "reason": "invalid_password"},
        {"event_type": "login_failed", "username": "admin", "ip": "192.168.1.100", "reason": "invalid_password"},
        # SQL injection (ATT&CK T1190)
        {"event_type": "api_request", "method": "GET", "path": "/api/export?query=' OR 1=1", "status": 400, "ip": "10.0.0.5"},
        {"event_type": "api_request", "method": "GET", "path": "/api/export?query=' UNION SELECT * FROM payments--", "status": 400, "ip": "10.0.0.5"},
        # Data exfiltration (ATT&CK T1048)
        {"event_type": "data_export", "username": "user1", "records_count": 50000, "ip": "10.0.0.2"},
        # Privilege escalation (ATT&CK T1078)
        {"event_type": "role_change", "username": "user2", "old_role": "viewer", "new_role": "admin", "ip": "10.0.0.3"},
    ]

    with open(LOG_PATH, "w") as f:
        for event in events:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
            f.write(json.dumps(event) + "\n")

    log(f"  Generated {len(events)} log entries → {LOG_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Payment API traffic simulator")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL")
    parser.add_argument("--offline", action="store_true", help="Generate logs without server")
    args = parser.parse_args()

    if args.offline:
        generate_offline_logs()
        return

    log(f"Target: {args.base_url}")
    log("=" * 50)

    try:
        simulate_normal_traffic(args.base_url)
        simulate_brute_force(args.base_url)
        simulate_sql_injection(args.base_url)
        simulate_data_exfiltration(args.base_url)
        simulate_negative_payment(args.base_url)
    except requests.ConnectionError:
        log(f"ERROR: Cannot connect to {args.base_url}")
        log("Start the server first: uvicorn src.app:app --port 8080")
        log("Or use --offline to generate logs without a server")
        sys.exit(1)

    log("=" * 50)
    log("Traffic simulation complete. Check logs/access.jsonl")


if __name__ == "__main__":
    main()
