import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

from app import db
from app.crypto_util import sign_token, verify_token
from app.main import create_app


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_path = db.DB_PATH
        db.DB_PATH = Path(self.tmp.name) / "test.sqlite"
        self.addCleanup(setattr, db, "DB_PATH", self.old_path)
        env = patch.dict(os.environ, {
            "FLASK_SECRET_KEY": "test-session-key" * 3,
            "TOKEN_KEY": "test-token-key" * 3,
            "GOOGLE_CLIENT_ID": "test-client",
            "PAYPROVIDER_TOKEN": "test-provider-key",
        })
        env.start()
        self.addCleanup(env.stop)
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def register(self, email, **extra):
        return self.client.post("/auth/register", json={
            "email": email, "password": "test-pass", **extra,
        })

    def test_registration_login_and_sensitive_profile(self):
        self.assertEqual(self.register("one@example.org", role="admin",
                                       display_name="O'Reilly").status_code, 200)
        conn = db.get_conn()
        one = conn.execute("SELECT id, role, password FROM users WHERE email = ?",
                           ("one@example.org",)).fetchone()
        self.assertEqual(one["role"], "user")
        self.assertNotEqual(one["password"], "test-pass")
        conn.execute("UPDATE users SET ssn = 'private' WHERE id = ?", (one["id"],))
        conn.execute(
            "INSERT INTO reports (author_id, title, body) VALUES (?, ?, ?)",
            (one["id"], "own report", "private body"),
        )
        conn.commit()
        conn.close()
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        self.assertEqual(self.client.get(f"/users/{one['id']}").json["ssn"], "private")
        self.register("two@example.org")
        self.assertEqual(self.client.get(f"/users/{one['id']}").status_code, 403)
        self.assertEqual(self.client.post("/auth/login", json={
            "email": "one@example.org", "password": "test-pass",
        }).status_code, 200)
        self.assertEqual(self.client.get("/reports/mine").json[0]["title"], "own report")
        self.assertEqual(self.client.get(f"/users/{one['id']}").status_code, 200)
        self.assertEqual(self.client.post("/auth/register", json={
            "email": "three@example.org", "password": "test-pass",
            "bad) VALUES ('x'); DROP TABLE users; --": "x",
        }).status_code, 200)

    def test_login_throttle(self):
        self.register("one@example.org")
        for _ in range(5):
            self.assertEqual(self.client.post("/auth/login", json={
                "email": "one@example.org", "password": "wrong",
            }).status_code, 401)
        self.assertEqual(self.client.post("/auth/login", json={
            "email": "one@example.org", "password": "test-pass",
        }).status_code, 429)

    def test_google_token_verification(self):
        self.assertEqual(self.client.post("/auth/oauth/google/callback",
                                          json=["not a token"]).status_code, 400)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = {"email": "verified@example.org", "email_verified": True,
                  "aud": "test-client", "iss": "https://accounts.google.com"}
        with patch("app.auth.PyJWKClient") as jwks:
            jwks.return_value.get_signing_key_from_jwt.return_value.key = key.public_key()
            for changes in ({"aud": "wrong"}, {"iss": "wrong"}):
                token = jwt.encode({**claims, **changes}, key, algorithm="RS256")
                self.assertEqual(self.client.post("/auth/oauth/google/callback",
                                                 json={"id_token": token}).status_code, 401)
            forged = jwt.encode(claims, "attacker-key" * 4, algorithm="HS256")
            self.assertEqual(self.client.post("/auth/oauth/google/callback",
                                              json={"id_token": forged}).status_code, 401)
            unsigned = jwt.encode(claims, key=None, algorithm="none")
            self.assertEqual(self.client.post("/auth/oauth/google/callback",
                                              json={"id_token": unsigned}).status_code, 401)
            signed = jwt.encode(claims, key, algorithm="RS256")
            self.assertEqual(self.client.post("/auth/oauth/google/callback",
                                              json={"id_token": signed}).status_code, 200)

    def test_preview_and_tokens(self):
        old_app = Flask(__name__)
        old_app.secret_key = "different-test-secret" * 3
        forged_cookie = SecureCookieSessionInterface().get_signing_serializer(old_app).dumps({
            "user_id": 1, "role": "admin",
        })
        self.client.set_cookie("session", forged_cookie)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        self.register("one@example.org")
        with self.client.session_transaction() as sess:
            sess["role"] = "admin"
        self.assertEqual(self.client.post("/admin/announce/preview",
                                           json={"template": "{{ 7*7 }}"}).json["preview"],
                         "{{ 7*7 }}")
        token = sign_token("hello")
        self.assertEqual(verify_token(token), "hello")
        with self.assertRaises(ValueError):
            verify_token(token[:-2] + "AA")

    def test_paid_api_cache_and_limit(self):
        with patch("app.payments.requests.get") as get:
            get.return_value.ok = True
            get.return_value.status_code = 200
            get.return_value.json.return_value = {"price": 5}
            self.assertEqual(self.client.get("/payments/quote?amount=5").json, {"price": 5})
            self.assertEqual(self.client.get("/payments/quote?amount=5").json, {"price": 5})
            self.assertEqual(get.call_count, 1)
            for _ in range(8):
                self.client.get("/payments/quote?amount=5")
            self.assertEqual(self.client.get("/payments/quote?amount=5").status_code, 429)
            self.assertEqual(get.call_count, 1)


class NativeSecurityTests(unittest.TestCase):
    def test_safe_file_and_label(self):
        binary = Path(__file__).resolve().parents[1] / "native" / "file_processor"
        if not binary.exists():
            self.skipTest("build native/file_processor with make -C native")
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "upload"
            file.write_bytes(b"\x00\xff")
            result = subprocess.run([binary, file, "x" * 100], capture_output=True,
                                    text=True, check=True)
            self.assertEqual(result.stdout, "label:" + "x" * 25 + "\n00ff\n")
            (Path(tmp) / "link").symlink_to(file)
            rejected = subprocess.run([binary, Path(tmp) / "link", "ok"],
                                      capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
