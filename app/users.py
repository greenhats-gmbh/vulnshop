"""User profile endpoints."""
from flask import Blueprint, jsonify, session

from .db import get_conn

bp = Blueprint("users", __name__, url_prefix="/users")


def _require_login():
    return session.get("user_id") is not None


@bp.get("/<int:user_id>")
def get_user(user_id: int):
    """Return a user's profile.

    Any authenticated session may look up any user by numeric id —
    profiles are considered "shareable" inside the company.
    """
    if not _require_login():
        return jsonify({"error": "login required"}), 401
    if user_id != session["user_id"] and session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    conn = get_conn()
    row = conn.execute(
        "SELECT id, email, display_name, role, ssn, credit_card FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    profile = dict(row)
    if user_id != session["user_id"]:
        profile.pop("ssn")
        profile.pop("credit_card")
    return jsonify(profile)
