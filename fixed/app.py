"""
SecureNotes Lab — FIXED VERSION
=====================================
Same application as the vulnerable version, with the 3 vulnerabilities
(+ 1 bonus) resolved. Compare line by line with vulnerable/app.py:
each "FIX N" comment corresponds to the "VULNERABILITY N" in the other
version.

  FIX 1: parameterized queries instead of string concatenation
  FIX 2: no |safe filter -> Jinja2 performs automatic escaping
  FIX 3: explicit authorization check (owner check) on every note
  FIX bonus: passwords hashed with werkzeug.security instead of plaintext
"""
import os
import secrets

from flask import Flask, request, redirect, url_for, render_template, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_connection, init_db

app = Flask(__name__)
# in production: set SECRET_KEY in the environment; falling back to a random
# key means sessions won't survive a restart, which is fine for this demo
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


@app.before_request
def ensure_db():
    init_db()


def current_user():
    return session.get("username")


@app.route("/")
def index():
    if not current_user():
        return redirect(url_for("login"))
    return redirect(url_for("notes"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # --- FIX 1: PARAMETERIZED QUERY ---
        # The "?" placeholder separates the data from the SQL code: whatever
        # the user writes is always treated as a value, never as an SQL command.
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        # --- FIX bonus: hash verification, never a plaintext comparison ---
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("notes"))
        error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_connection()
        cur = conn.cursor()
        try:
            # --- FIX bonus: password hash, never plaintext ---
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except Exception:
            error = "Username already taken."
            conn.close()
    return render_template("register.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/notes")
def notes():
    if not current_user():
        return redirect(url_for("login"))
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notes WHERE user_id = ?", (session["user_id"],))
    my_notes = cur.fetchall()
    conn.close()
    return render_template("notes.html", notes=my_notes, username=current_user())


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    if not current_user():
        return redirect(url_for("login"))
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], title, content),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("notes"))
    return render_template("new_note.html")


@app.route("/notes/<int:note_id>")
def view_note(note_id):
    if not current_user():
        return redirect(url_for("login"))

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note = cur.fetchone()
    conn.close()

    if note is None:
        return "Note not found", 404

    # --- FIX 3: EXPLICIT AUTHORIZATION CHECK ---
    # Even if the ID exists, we verify it belongs to the logged-in user.
    # Without this check, any authenticated user could read anyone else's
    # notes just by guessing/incrementing the ID in the URL.
    if note["user_id"] != session["user_id"]:
        abort(403)

    # --- FIX 2: NO |safe FILTER ---
    # Jinja2 performs automatic escaping by default: see
    # templates/note_detail.html, where the content is simply
    # {{ note['content'] }} without |safe.
    return render_template("note_detail.html", note=note)


if __name__ == "__main__":
    init_db(reset=True)
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, port=5001)
