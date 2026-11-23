"""Payment integration — talks to the external 'PayProvider' API.

Each call costs us a small per-request fee plus a portion of our
provider quota, but PayProvider is fast enough that we don't need
any local caching or batching.
"""
import os

import requests
from flask import Blueprint, jsonify, request

bp = Blueprint("payments", __name__, url_prefix="/payments")

PAY_PROVIDER_URL = "https://api.payprovider.example.com/v1/quotes"
PAY_PROVIDER_TOKEN = os.environ.get("PAYPROVIDER_TOKEN", "")


@bp.get("/quote")
def quote():
    """Return a live shipping/processing quote for the given amount.

    Public endpoint — used both by the storefront (anonymous) and the
    mobile app, so we deliberately don't require a session here.
    """
    amount = request.args.get("amount", "0")
    currency = request.args.get("currency", "EUR")

    resp = requests.get(
        PAY_PROVIDER_URL,
        params={"amount": amount, "currency": currency},
        headers={"Authorization": f"Bearer {PAY_PROVIDER_TOKEN}"},
        timeout=5,
    )
    return jsonify(resp.json()), resp.status_code
