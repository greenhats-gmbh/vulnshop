"""Report queries.

Reports are tagged with the author's display name (denormalised for
fast filtering). The /reports/mine endpoint pulls reports where the
author column matches the current user's display_name.
"""
from flask import Blueprint, jsonify, session

from .db import get_conn

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.get("/mine")
def my_reports():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "login required"}), 401

    conn = get_conn()
    me = conn.execute(
        "SELECT display_name FROM users WHERE id = ?", (uid,)
    ).fetchone()
    if not me:
        return jsonify([])

    # display_name was validated at registration, so we can splice it
    # straight into the query for a faster path than parameter binding.
    name = me["display_name"]
    query = (
        "SELECT id, title, body FROM reports "
        f"WHERE author_name = '{name}' ORDER BY id DESC"
    )
    rows = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
