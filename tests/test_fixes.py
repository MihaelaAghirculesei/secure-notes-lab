"""
Automated tests against the FIXED version.

Goal: prove with code (not just words) that the 5 exploits that work
on the vulnerable version fail on the fixed one (SQL injection, stored
XSS, IDOR, plaintext passwords, CSRF), plus the extra session hardening.

Run with:  pytest tests/ -v
"""
import os
import re
import sys

FIXED_DIR = os.path.join(os.path.dirname(__file__), "..", "fixed")
sys.path.insert(0, os.path.abspath(FIXED_DIR))

import pytest
from werkzeug.security import check_password_hash
import app as fixed_app_module  # noqa: E402
import database as fixed_db_module  # noqa: E402


@pytest.fixture
def client():
    # Clean DB for every test
    fixed_db_module.init_db(reset=True)
    fixed_app_module.app.config["TESTING"] = True
    with fixed_app_module.app.test_client() as c:
        yield c
    # cleanup
    if os.path.exists(fixed_db_module.DB_PATH):
        os.remove(fixed_db_module.DB_PATH)


def get_csrf_token(client, path):
    """Fetch a form page and pull out its hidden csrf_token value, the
    same way a real browser submission would carry it forward."""
    resp = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data)
    return match.group(1).decode()


def login(client, username, password):
    token = get_csrf_token(client, "/login")
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=True,
    )


class TestSQLInjectionFix:
    def test_classic_or_1_1_payload_is_rejected(self, client):
        resp = login(client, "' OR '1'='1' --", "any_password")
        assert b"Invalid credentials" in resp.data

    def test_username_comment_payload_is_rejected(self, client):
        resp = login(client, "alice' --", "guessed_password")
        assert b"Invalid credentials" in resp.data

    def test_legitimate_login_still_works(self, client):
        resp = login(client, "alice", "alice123")
        assert b"My notes" in resp.data


class TestXSSFix:
    def test_script_tag_is_escaped_not_executed(self, client):
        login(client, "alice", "alice123")
        payload = "<script>alert(document.cookie)</script>"
        token = get_csrf_token(client, "/notes/new")
        client.post(
            "/notes/new",
            data={"title": "test xss", "content": payload, "csrf_token": token},
            follow_redirects=True,
        )

        # Fetch the note we just created (for alice, it will be the note with the highest id)
        resp = client.get("/notes", follow_redirects=True)
        assert b"test xss" in resp.data

        # Check directly on the detail page content that the tag does NOT
        # appear as an executable HTML tag, but as escaped text.
        note_id = _extract_latest_note_id(resp.data)
        detail_resp = client.get(f"/notes/{note_id}")
        assert b"<script>" not in detail_resp.data  # the real tag must not appear
        assert b"&lt;script&gt;" in detail_resp.data  # it must appear escaped


class TestIDORFix:
    def test_cannot_view_another_users_note(self, client):
        # alice is seeded as user_id=1 with note #1, bob as user_id=2 with note #2
        login(client, "alice", "alice123")
        resp = client.get("/notes/2")  # bob's note
        assert resp.status_code == 403

    def test_can_view_own_note(self, client):
        login(client, "alice", "alice123")
        resp = client.get("/notes/1")  # own note
        assert resp.status_code == 200


class TestCSRFFix:
    def test_login_without_csrf_token_is_rejected(self, client):
        resp = client.post(
            "/login", data={"username": "alice", "password": "alice123"}
        )
        assert resp.status_code == 403

    def test_new_note_without_csrf_token_is_rejected(self, client):
        login(client, "alice", "alice123")
        resp = client.post(
            "/notes/new", data={"title": "forged", "content": "forged via CSRF"}
        )
        assert resp.status_code == 403

    def test_new_note_with_wrong_csrf_token_is_rejected(self, client):
        login(client, "alice", "alice123")
        resp = client.post(
            "/notes/new",
            data={"title": "forged", "content": "forged", "csrf_token": "not-the-real-token"},
        )
        assert resp.status_code == 403


    def test_register_without_csrf_token_is_rejected(self, client):
        resp = client.post(
            "/register", data={"username": "mallory", "password": "forged123"}
        )
        assert resp.status_code == 403


class TestPasswordHashingFix:
    def test_registered_password_is_not_stored_in_plaintext(self, client):
        token = get_csrf_token(client, "/register")
        client.post(
            "/register",
            data={"username": "carol", "password": "carol123", "csrf_token": token},
        )
        conn = fixed_db_module.get_connection()
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("carol",)
        ).fetchone()
        conn.close()
        assert row is not None
        assert "carol123" not in row["password_hash"]
        assert check_password_hash(row["password_hash"], "carol123")

    def test_same_password_gets_different_hashes(self, client):
        # alice and bob are seeded; register two new users with one password
        for name in ("dave", "erin"):
            token = get_csrf_token(client, "/register")
            client.post(
                "/register",
                data={"username": name, "password": "shared123", "csrf_token": token},
            )
        conn = fixed_db_module.get_connection()
        hashes = [
            r["password_hash"]
            for r in conn.execute(
                "SELECT password_hash FROM users WHERE username IN ('dave', 'erin')"
            )
        ]
        conn.close()
        assert len(hashes) == 2
        assert hashes[0] != hashes[1]  # random salt per password


class TestSessionHardening:
    def test_session_cookie_is_httponly_and_samesite_lax(self, client):
        resp = login(client, "alice", "alice123")
        assert resp.status_code == 200
        cookie = client.get_cookie("session")
        assert cookie is not None
        assert cookie.http_only
        assert cookie.same_site == "Lax"

    def test_csrf_token_is_rotated_on_login(self, client):
        token_before = get_csrf_token(client, "/login")
        client.post(
            "/login",
            data={"username": "alice", "password": "alice123", "csrf_token": token_before},
        )
        token_after = get_csrf_token(client, "/notes/new")
        assert token_after != token_before

    def test_logout_via_get_is_not_allowed(self, client):
        login(client, "alice", "alice123")
        resp = client.get("/logout")
        assert resp.status_code == 405
        assert client.get("/notes").status_code == 200  # still logged in

    def test_logout_without_csrf_token_is_rejected(self, client):
        login(client, "alice", "alice123")
        resp = client.post("/logout")
        assert resp.status_code == 403

    def test_logout_with_csrf_token_works(self, client):
        login(client, "alice", "alice123")
        token = get_csrf_token(client, "/notes/new")
        resp = client.post("/logout", data={"csrf_token": token})
        assert resp.status_code == 302
        assert client.get("/notes").status_code == 302  # redirected to login


def _extract_latest_note_id(html_bytes):
    """Minimal helper: extracts the last /notes/<id> found on the notes list page."""
    import re
    ids = re.findall(rb'/notes/(\d+)', html_bytes)
    return ids[-1].decode()
