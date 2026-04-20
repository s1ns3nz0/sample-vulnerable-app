"""Payment API — INTENTIONALLY VULNERABLE FastAPI application."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from src.config import DATABASE_URL, JWT_ALGORITHM, JWT_SECRET, LOG_PATH

app = FastAPI(title="Payment API", version="1.0.0")
logger = logging.getLogger("payment-api")

# Ensure log directory exists
Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)


# --- Models ---


class LoginRequest(BaseModel):
    username: str
    password: str


class PaymentCreateRequest(BaseModel):
    card_number: str
    amount: float
    currency: str = "JPY"
    description: str = ""


class PaymentConfirmRequest(BaseModel):
    payment_id: str
    otp: str


# --- Logging ---


def log_event(event: dict[str, Any]) -> None:
    """Write structured JSON log entry."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


# --- Database ---


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_URL.replace("sqlite:///", ""))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            card_number TEXT,
            amount REAL,
            currency TEXT,
            status TEXT,
            created_at TEXT
        )"""
    )
    conn.commit()
    conn.close()


# --- Endpoints ---


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "payment-api"}


@app.post("/api/login")
def login(req: LoginRequest, request: Request) -> dict[str, str]:
    """Login endpoint — returns JWT token.

    VULNERABILITY 4: Uses HS256 with hardcoded secret (ASVS-V3.5.1)
    """
    # Dummy auth — accepts admin/admin
    if req.username == "admin" and req.password == "admin":
        token = jwt.encode(
            {"sub": req.username, "role": "admin"},
            JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        log_event({
            "event_type": "login_success",
            "username": req.username,
            "ip": request.client.host if request.client else "unknown",
        })
        return {"token": token}

    log_event({
        "event_type": "login_failed",
        "username": req.username,
        "ip": request.client.host if request.client else "unknown",
        "reason": "invalid_password",
    })
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/payment/create")
def create_payment(req: PaymentCreateRequest, request: Request) -> dict[str, Any]:
    """Create a new payment.

    VULNERABILITY 3: PII (card number) logged in plaintext (PCI-DSS-6.3.1)
    VULNERABILITY 5: Negative payment amount accepted (business logic bug)
    """
    payment_id = f"PAY-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    # VULNERABILITY 5: No validation on negative amounts
    # Should check: if req.amount <= 0: raise HTTPException(400)

    # VULNERABILITY 3: Card number logged in plaintext
    logger.info(
        "Payment created: id=%s card=%s amount=%s %s",
        payment_id,
        req.card_number,  # PII LEAK — should be masked: card[-4:]
        req.amount,
        req.currency,
    )

    log_event({
        "event_type": "payment_created",
        "payment_id": payment_id,
        "card_number": req.card_number,  # PII LEAK in structured log
        "amount": req.amount,
        "currency": req.currency,
        "ip": request.client.host if request.client else "unknown",
    })

    conn = get_db()
    conn.execute(
        "INSERT INTO payments VALUES (?, ?, ?, ?, ?, ?)",
        (payment_id, req.card_number, req.amount, req.currency, "pending",
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    return {"payment_id": payment_id, "status": "pending", "amount": req.amount}


@app.post("/api/payment/confirm")
def confirm_payment(req: PaymentConfirmRequest) -> dict[str, str]:
    """Confirm a payment with OTP."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM payments WHERE id = ?", (req.payment_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Payment not found")

    # Dummy OTP validation
    if req.otp != "123456":
        raise HTTPException(status_code=400, detail="Invalid OTP")

    conn = get_db()
    conn.execute(
        "UPDATE payments SET status = 'confirmed' WHERE id = ?",
        (req.payment_id,),
    )
    conn.commit()
    conn.close()

    log_event({
        "event_type": "payment_confirmed",
        "payment_id": req.payment_id,
    })

    return {"payment_id": req.payment_id, "status": "confirmed"}


@app.get("/api/export")
def export_data(request: Request, query: str = "") -> dict[str, Any]:
    """Export payment data.

    VULNERABILITY 2: SQL injection via string concatenation (PCI-DSS-6.3.1)
    """
    conn = get_db()

    # VULNERABILITY 2: Direct string concatenation in SQL query
    # Should use parameterized query: cursor.execute("SELECT * FROM payments WHERE status = ?", (query,))
    sql = f"SELECT * FROM payments WHERE status = '{query}'"  # noqa: S608
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.OperationalError as e:
        log_event({
            "event_type": "api_request",
            "method": "GET",
            "path": f"/api/export?query={query}",
            "status": 400,
            "ip": request.client.host if request.client else "unknown",
            "error": str(e),
        })
        conn.close()
        raise HTTPException(status_code=400, detail=str(e)) from e

    result = [dict(row) for row in rows]

    log_event({
        "event_type": "data_export",
        "username": "unknown",
        "records_count": len(result),
        "ip": request.client.host if request.client else "unknown",
    })

    conn.close()
    return {"count": len(result), "data": result}


@app.on_event("startup")
def startup() -> None:
    init_db()
