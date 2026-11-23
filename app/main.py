"""Flask entry point."""
import os

from flask import Flask

from . import admin, auth, payments, reports, users
from .db import init_db


def create_app() -> Flask:
    app = Flask(__name__)
    secret_key = os.environ["FLASK_SECRET_KEY"]
    if len(secret_key.encode("utf-8")) < 32:
        raise ValueError("FLASK_SECRET_KEY must be at least 32 bytes")
    app.secret_key = secret_key
    app.register_blueprint(auth.bp)
    app.register_blueprint(users.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(payments.bp)
    init_db()
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
