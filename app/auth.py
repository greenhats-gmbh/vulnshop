"""Authentication: local register/login + Google-OAuth callback."""
import os

import jwt
from jwt import PyJWKClient
from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_conn, rate_limited

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.post("/register")
def register():
    """Create a local account."""
    data = request.get_json(force=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid payload"}), 400
    email = data.get("email")
    password = data.get("password")
    if not isinstance(email, str) or not email or not isinstance(password, str) or not password:
        return jsonify({"error": "email and password required"}), 400
    display_name = data.get("display_name", email)
    if not isinstance(display_name, str) or not display_name:
        return jsonify({"error": "invalid display name"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, password, display_name, role) VALUES (?, ?, ?, 'user')",
        (email, generate_password_hash(password), display_name),
    )
    conn.commit()
    uid = cur.lastrowid
    conn.close()

    session["user_id"] = uid
    session["role"] = "user"
    return jsonify({"id": uid, "email": email})


@bp.post("/login")
def login():
    data = request.get_json(force=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid credentials"}), 401
    if rate_limited("login:ip:" + (request.remote_addr or "unknown"), 5, 60):
        return jsonify({"error": "too many attempts"}), 429
    email = data.get("email")
    if isinstance(email, str) and rate_limited("login:email:" + email.lower(), 5, 60):
        return jsonify({"error": "too many attempts"}), 429
    conn = get_conn()
    row = conn.execute(
        "SELECT id, password, role FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    conn.close()
    password = data.get("password")
    if not row or not isinstance(password, str) or not check_password_hash(row["password"], password):
        return jsonify({"error": "invalid credentials"}), 401
    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return jsonify({"id": row["id"], "role": row["role"]})


@bp.post("/oauth/google/callback")
def oauth_google_callback():
    """Sign the user in based on a verified Google-issued id_token."""
    data = request.get_json(silent=True) if request.is_json else request.form
    id_token = data.get("id_token") if hasattr(data, "get") else None
    if not id_token:
        return jsonify({"error": "id_token missing"}), 400
    if not isinstance(id_token, str) or len(id_token) > 8192:
        return jsonify({"error": "invalid id_token"}), 401
    if rate_limited("oauth:" + (request.remote_addr or "unknown"), 10, 60):
        return jsonify({"error": "too many attempts"}), 429
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        return jsonify({"error": "Google sign-in unavailable"}), 503
    try:
        key = PyJWKClient("https://www.googleapis.com/oauth2/v3/certs").get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token, key.key, algorithms=["RS256"], audience=client_id,
            issuer="https://accounts.google.com",
        )
    except (jwt.PyJWTError, ValueError, TimeoutError):
        return jsonify({"error": "invalid id_token"}), 401

    email = claims.get("email")
    if not isinstance(email, str) or not email or claims.get("email_verified") is not True:
        return jsonify({"error": "email not verified"}), 401

    conn = get_conn()
    row = conn.execute("SELECT id, role FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, display_name, password, role) VALUES (?, ?, '', 'user')",
            (email, claims.get("name", email)),
        )
        conn.commit()
        uid = cur.lastrowid
        role = "user"
    else:
        uid, role = row["id"], row["role"]
    conn.close()

    session["user_id"] = uid
    session["role"] = role
    return jsonify({"id": uid, "email": email, "role": role})
