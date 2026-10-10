import os
import tempfile
import unittest
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

    def register(self, client, email="student@example.com", password="correct-horse-battery-1", consent=False):
        data = {"csrf_token": self.csrf(client), "email": email, "password": password, "confirm_password": password}
        if consent:
            data["share_email"] = "on"
        return client.post("/register", data=data, follow_redirects=True)

    def admin_login(self):
        self.admin_client.get("/admin/login")
        token = self.csrf(self.admin_client)
        return self.admin_client.post("/admin/login", data={"csrf_token": token, "password": "test-admin-password"})

    def test_registration_hashes_password_and_defaults_to_private_email(self):
        response = self.register(self.user_client)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"student@example.com", response.data)
        with website.auth_db() as connection:
            user = connection.execute("SELECT * FROM accounts WHERE email = ?", ("student@example.com",)).fetchone()
        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], "correct-horse-battery-1")
        self.assertTrue(check_password_hash(user["password_hash"], "correct-horse-battery-1"))
        self.assertEqual(user["share_email"], 0)
        self.assertIsNone(user["share_email_consented_at"])
        self.assertNotIn(b"correct-horse-battery-1", response.data)

    def test_admin_sees_only_emails_with_current_consent(self):
        self.register(self.user_client)
        self.assertEqual(self.admin_login().status_code, 302)
        response = self.admin_client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"student@example.com", response.data)
        token = self.csrf(self.user_client)
        self.user_client.post("/account", data={"csrf_token": token, "share_email": "on"})
        response = self.admin_client.get("/admin/users")
        self.assertIn(b"student@example.com", response.data)
        self.assertNotIn(b"password_hash", response.data)
        self.assertNotIn(b"correct-horse-battery-1", response.data)
        token = self.csrf(self.user_client)
        self.user_client.post("/account", data={"csrf_token": token})
        response = self.admin_client.get("/admin/users")
        self.assertNotIn(b"student@example.com", response.data)

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
