import os
import tempfile
import unittest
from io import BytesIO
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch
from pathlib import Path

TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="natayejna-auth-test-")
os.environ["AUTH_DATABASE_PATH"] = str(Path(TEST_DIRECTORY.name) / "accounts.sqlite3")
os.environ["FLASK_SECRET_KEY"] = "test-only-secret-key"
os.environ["SESSION_COOKIE_SECURE"] = "false"
os.environ["ADMIN_PASSWORD"] = "test-admin-password"

import app as website
from werkzeug.security import check_password_hash


class AccountAuthTests(unittest.TestCase):
    def setUp(self):
        website.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        with website.auth_db() as connection:
            connection.execute("DELETE FROM auth_rate_limits")
            connection.execute("DELETE FROM accounts")
        self.user_client = website.app.test_client()
        self.admin_client = website.app.test_client()
        self.csrf(self.user_client)

    @staticmethod
    def csrf(client):
        with client.session_transaction() as session:
            token = session.get("_csrf_token")
            if not token:
                token = "test-csrf-token"
                session["_csrf_token"] = token
            return token

    def register(self, client, email="student@example.com", password="correct-horse-battery-1", consent=True):
        data = {"csrf_token": self.csrf(client), "email": email, "password": password, "confirm_password": password}
        if consent:
            data["share_email"] = "on"
        return client.post("/register", data=data, follow_redirects=True)

    def admin_login(self):
        self.admin_client.get("/admin/login")
        token = self.csrf(self.admin_client)
        return self.admin_client.post("/admin/login", data={"csrf_token": token, "password": "test-admin-password"})

    def test_registration_requires_consent_and_hashes_password(self):
        response = self.register(self.user_client, consent=False)
        self.assertEqual(response.status_code, 400)
        with website.auth_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 0)

        response = self.register(self.user_client)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"student@example.com", response.data)
        with website.auth_db() as connection:
            user = connection.execute("SELECT * FROM accounts WHERE email = ?", ("student@example.com",)).fetchone()
        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], "correct-horse-battery-1")
        self.assertTrue(check_password_hash(user["password_hash"], "correct-horse-battery-1"))
        self.assertEqual(user["share_email"], 1)
        self.assertIsNotNone(user["share_email_consented_at"])
        self.assertNotIn(b"correct-horse-battery-1", response.data)

    def test_admin_sees_consented_email_and_user_can_withdraw_consent(self):
        self.register(self.user_client)
        self.assertEqual(self.admin_login().status_code, 302)
        response = self.admin_client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"student@example.com", response.data)
        self.assertNotIn(b"password_hash", response.data)
        self.assertNotIn(b"correct-horse-battery-1", response.data)
        token = self.csrf(self.user_client)
        self.user_client.post("/account", data={"csrf_token": token})
        response = self.admin_client.get("/admin/users")
        self.assertNotIn(b"student@example.com", response.data)

    def test_google_oauth_uses_state_and_shows_verified_email_in_owner_dashboard(self):
        env = {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_REDIRECT_URI": "https://example.test/auth/google/callback",
        }
        with patch.dict(os.environ, env):
            login_page = self.user_client.get("/login")
            self.assertEqual(login_page.status_code, 200)
            self.assertIn(b"/auth/google", login_page.data)
            self.assertIn("المتابعة باستخدام Google".encode(), login_page.data)
            missing_consent = self.user_client.post(
                "/auth/google", data={"csrf_token": self.csrf(self.user_client)}
            )
            self.assertEqual(missing_consent.status_code, 400)
            start = self.user_client.post("/auth/google", data={
                "csrf_token": self.csrf(self.user_client),
                "share_email": "on",
            })
            self.assertEqual(start.status_code, 302)
            authorization = urlparse(start.location)
            self.assertEqual(authorization.netloc, "accounts.google.com")
            params = parse_qs(authorization.query)
            self.assertEqual(params["scope"], ["openid email"])
            state = params["state"][0]
            with patch.object(website, "google_userinfo_from_code", return_value={
                "sub": "google-sub-123",
                "email": "google.student@example.com",
                "email_verified": True,
            }):
                callback = self.user_client.get(
                    "/auth/google/callback?code=test-code&state=" + state
                )
            self.assertEqual(callback.status_code, 302)
            self.assertEqual(callback.location, "/account")

        with website.auth_db() as connection:
            user = connection.execute(
                "SELECT email, password_hash, google_sub, share_email FROM accounts WHERE email = ?",
                ("google.student@example.com",),
            ).fetchone()
        self.assertIsNotNone(user)
        self.assertEqual(user["password_hash"], "")
        self.assertEqual(user["google_sub"], "google-sub-123")
        self.assertEqual(user["share_email"], 1)
        self.assertEqual(self.admin_login().status_code, 302)
        dashboard = self.admin_client.get("/admin/users")
        self.assertIn(b"google.student@example.com", dashboard.data)
        self.assertIn("Google".encode(), dashboard.data)

    def test_google_callback_rejects_an_invalid_state(self):
        response = self.user_client.get("/auth/google/callback?code=test-code&state=wrong")
        self.assertEqual(response.status_code, 400)

    def test_google_login_rejects_unverified_email(self):
        env = {
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env):
            start = self.user_client.post("/auth/google", data={
                "csrf_token": self.csrf(self.user_client),
                "share_email": "on",
            })
            state = parse_qs(urlparse(start.location).query)["state"][0]
            with patch.object(website, "google_userinfo_from_code", return_value={
                "sub": "google-sub-unverified",
                "email": "not-verified@example.com",
                "email_verified": False,
            }):
                response = self.user_client.get(
                    "/auth/google/callback?code=test-code&state=" + state
                )
        self.assertEqual(response.status_code, 403)
        with website.auth_db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 0)

    def test_admin_image_upload_still_works(self):
        self.assertEqual(self.admin_login().status_code, 302)
        response = self.admin_client.post(
            "/api/upload",
            data={
                "csrf_token": self.csrf(self.admin_client),
                "image": (BytesIO(b"fake-image-content"), "sample.jpg"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)

    def test_login_verifies_password_and_rejects_missing_csrf(self):
        self.register(self.user_client)
        self.user_client.post("/logout", data={"csrf_token": self.csrf(self.user_client)})
        response = self.user_client.post("/login", data={"csrf_token": self.csrf(self.user_client), "email": "student@example.com", "password": "wrong-password"})
        self.assertEqual(response.status_code, 401)
        response = self.user_client.post("/login", data={"email": "student@example.com", "password": "correct-horse-battery-1"})
        self.assertEqual(response.status_code, 400)
        response = self.user_client.post("/login", data={"csrf_token": self.csrf(self.user_client), "email": "student@example.com", "password": "correct-horse-battery-1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/account")

    def test_admin_email_list_requires_admin_authentication(self):
        response = self.admin_client.get("/admin/users")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/admin/login")


if __name__ == "__main__":
    unittest.main()
