"""
Automated tests against the FIXED version.

Goal: prove with code (not just words) that the 3 exploits that work
on the vulnerable version fail on the fixed one.

Run with:  pytest tests/ -v
"""
import os
import re
import sys

FIXED_DIR = os.path.join(os.path.dirname(__file__), "..", "fixed")
sys.path.insert(0, os.path.abspath(FIXED_DIR))

import pytest
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


def _extract_latest_note_id(html_bytes):
    """Minimal helper: extracts the last /notes/<id> found on the notes list page."""
    import re
    ids = re.findall(rb'/notes/(\d+)', html_bytes)
    return ids[-1].decode()
