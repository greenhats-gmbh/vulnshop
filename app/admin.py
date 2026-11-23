"""Admin tooling — restricted to users whose role == 'admin'."""
from flask import Blueprint, abort, jsonify, render_template_string, request, session

from .db import get_conn

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin():
    if session.get("role") != "admin":
        abort(403)


@bp.post("/announce/preview")
def preview_announcement():
    """Render a draft announcement template before sending it out.

    The admin pastes a Jinja-style snippet (e.g.
    "Hi {{ user.display_name }} — your order #{{ order_id }} ships today.")
    and we render it server-side so they can see exactly what users will
    receive.
    """
    _require_admin()
    tpl = (request.json or {}).get("template", "")
    rendered = render_template_string(tpl)
    return jsonify({"preview": rendered})


@bp.get("/users")
def list_users():
    _require_admin()
    conn = get_conn()
    rows = conn.execute("SELECT id, email, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
