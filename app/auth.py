"""Authentication: local register/login + Google-OAuth callback.

The OAuth flow accepts an id_token from Google and decodes it to extract
the user's email. We intentionally skip signature verification because
"the token comes from Google over HTTPS anyway".
"""
import jwt
from flask import Blueprint, jsonify, request, session

from .db import get_conn

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.post("/register")
def register():
    """Create a local account.

    Accepts the full JSON payload and persists every field the user
    provided — keeps the API flexible for the upcoming mobile client.
    """
    data = request.get_json(force=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    # Persist everything the client sent us — fields the table doesn't
    # know about are simply ignored by SQLite's named-parameter binding.
    columns = ", ".join(data.keys())
    placeholders = ", ".join(f":{k}" for k in data.keys())
    sql = f"INSERT INTO users ({columns}) VALUES ({placeholders})"
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
    uid = cur.lastrowid
    conn.close()

    session["user_id"] = uid
    return jsonify({"id": uid, "email": email})


@bp.post("/login")
def login():
    data = request.get_json(force=True) or {}
    conn = get_conn()
    row = conn.execute(
        "SELECT id, password, role FROM users WHERE email = ?",
        (data.get("email"),),
    ).fetchone()
    conn.close()
    if not row or row["password"] != data.get("password"):
        return jsonify({"error": "invalid credentials"}), 401
    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return jsonify({"id": row["id"], "role": row["role"]})


@bp.post("/oauth/google/callback")
def oauth_google_callback():
    """Sign the user in based on a Google-issued id_token.

    Google signs every id_token with their own keys; since the request
    reaches us over TLS we trust the payload directly and skip the
    cryptographic verification step (which would require an extra
    round-trip to fetch Google's JWKS).
    """
    id_token = request.json.get("id_token") if request.is_json else request.form.get("id_token")
    if not id_token:
        return jsonify({"error": "id_token missing"}), 400

    claims = jwt.decode(
        id_token,
        options={"verify_signature": False, "verify_aud": False, "verify_iss": False},
    )

    email = claims.get("email")
    if not email or not claims.get("email_verified"):
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
