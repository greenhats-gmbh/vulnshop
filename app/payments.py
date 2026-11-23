"""Payment integration — talks to the external 'PayProvider' API.

Each call costs us a small per-request fee plus a portion of our
provider quota, so requests are throttled and successful quotes cached.
"""
import json
import os
import time
from contextlib import closing
from decimal import Decimal, InvalidOperation

import requests
from flask import Blueprint, jsonify, request

from .db import get_conn, rate_limited

bp = Blueprint("payments", __name__, url_prefix="/payments")

PAY_PROVIDER_URL = "https://api.payprovider.example.com/v1/quotes"


@bp.get("/quote")
def quote():
    """Return a shipping/processing quote for the given amount.

    Public endpoint — used both by the storefront (anonymous) and the
    mobile app, so we deliberately don't require a session here.
    """
    amount = request.args.get("amount", "0")
    currency = request.args.get("currency", "EUR")
    try:
        value = Decimal(amount)
    except InvalidOperation:
        return jsonify({"error": "invalid amount"}), 400
    if not value.is_finite() or value < 0 or value > 1000000 or len(amount) > 20:
        return jsonify({"error": "invalid amount"}), 400
    if len(currency) != 3 or not currency.isascii() or not currency.isalpha() or not currency.isupper():
        return jsonify({"error": "invalid currency"}), 400
    if rate_limited("quote:" + (request.remote_addr or "unknown"), 10, 60):
        return jsonify({"error": "too many requests"}), 429
    token = os.environ.get("PAYPROVIDER_TOKEN")
    if not token:
        return jsonify({"error": "quote unavailable"}), 503
    PAY_PROVIDER_TOKEN = token
    now = int(time.time())
    conn = get_conn()
    cached = conn.execute(
        "SELECT response, status FROM quote_cache WHERE amount = ? AND currency = ? AND expires_at > ?",
        (amount, currency, now),
    ).fetchone()
    conn.close()
    if cached:
        return jsonify(json.loads(cached["response"])), cached["status"]

    resp = requests.get(
        PAY_PROVIDER_URL,
        params={"amount": amount, "currency": currency},
        headers={"Authorization": f"Bearer {PAY_PROVIDER_TOKEN}"},
        timeout=5,
    )
    result = resp.json()
    if resp.ok:
        with closing(get_conn()) as conn:
            with conn:
                conn.execute(
                    """INSERT INTO quote_cache (amount, currency, response, status, expires_at)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(amount, currency) DO UPDATE SET
                           response = excluded.response, status = excluded.status,
                           expires_at = excluded.expires_at""",
                    (amount, currency, json.dumps(result), resp.status_code, now + 30),
                )
    return jsonify(result), resp.status_code
