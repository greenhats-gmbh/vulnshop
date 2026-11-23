"""Report queries."""
from flask import Blueprint, jsonify, session

from .db import get_conn

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.get("/mine")
def my_reports():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "login required"}), 401

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, title, body FROM reports WHERE author_id = ? ORDER BY id DESC",
        (uid,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
