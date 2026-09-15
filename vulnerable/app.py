"""
SecureNotes Lab — VULNERABLE VERSION
========================================
Demo application with 3 intentional vulnerabilities (OWASP Top 10):

  1. SQL Injection (login)       -> see login()
  2. Stored XSS (note content)   -> see view_note() / templates/note_detail.html
  3. IDOR (note viewing)         -> see view_note()

Intended use: local only, for educational/portfolio purposes.
Never expose this version on the internet or in production.
"""
from flask import Flask, request, redirect, url_for, render_template, session
from database import get_connection, init_db

app = Flask(__name__)
app.secret_key = "dev-secret-key-not-for-production"  # fine for a local demo, NEVER in production


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

        # --- VULNERABILITY 1: SQL INJECTION ---
        # The query is built by directly concatenating user input.
        # Try as username:  admin' --
        # or as username:   ' OR '1'='1
        # with any password: authentication is bypassed entirely.
        conn = get_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cur = conn.cursor()
        cur.execute(query)
        user = cur.fetchone()
        conn.close()

        if user:
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
            # Here too: password stored in plaintext (additional vulnerability,
            # see docs/VULNERABILITIES.md).
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
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

    # --- VULNERABILITY 3: IDOR (Insecure Direct Object Reference) ---
    # The note is fetched by ID only, WITHOUT checking that it belongs
    # to the logged-in user. While logged in as alice (user_id=1),
    # visit /notes/2: you'll see bob's private note.
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note = cur.fetchone()
    conn.close()

    if note is None:
        return "Note not found", 404

    # --- VULNERABILITY 2: STORED XSS ---
    # The note content is passed to the template and rendered with the
    # Jinja2 "|safe" filter, which DISABLES automatic escaping.
    # Create a note with content: <script>alert(document.cookie)</script>
    # then view it: the script is executed by the browser.
    return render_template("note_detail.html", note=note)


if __name__ == "__main__":
    init_db(reset=True)
    app.run(debug=True, port=5000)
