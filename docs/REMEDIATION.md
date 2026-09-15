# Remediation — before/after comparison

## FIX-01 — SQL Injection → parameterized queries

**Before** (`vulnerable/app.py`):
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cur.execute(query)
```

**After** (`fixed/app.py`):
```python
cur.execute("SELECT * FROM users WHERE username = ?", (username,))
```

**Why it works:** with a parameterized query, the SQLite driver treats the `?` placeholder and the supplied value as two separate things: the value is always interpreted as a literal, never as part of the SQL syntax. There's no string a user can enter to "escape" the boundaries of the expected value. This holds true for virtually every SQL driver (SQLite, PostgreSQL, MySQL) and every language: the rule is always "never build queries by concatenating user input."

---

## FIX-02 — Stored XSS → removing the `|safe` filter

**Before** (`vulnerable/templates/note_detail.html`):
```
{{ note['content'] | safe }}
```

**After** (`fixed/templates/note_detail.html`):
```
{{ note['content'] }}
```

**Why it works:** Jinja2 (Flask's templating engine) performs automatic HTML escaping by default — it turns `<` into `&lt;`, `>` into `&gt;`, and so on. The `|safe` filter exists for the (rare) cases where you deliberately want to insert raw, trusted HTML (e.g. content you wrote yourself, not a user); using it on arbitrary user input is the mistake. The general rule: **always escape on output by default**, and disable escaping only case by case when you're certain the content is safe.

---

## FIX-03 — IDOR → explicit authorization check

**Before** (`vulnerable/app.py`):
```python
cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
note = cur.fetchone()
# no further check
return render_template("note_detail.html", note=note)
```

**After** (`fixed/app.py`):
```python
cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
note = cur.fetchone()

if note["user_id"] != session["user_id"]:
    abort(403)

return render_template("note_detail.html", note=note)
```

**Why it works:** authentication (knowing *who* you are) does not imply authorization (what you're *allowed* to do/see). Whenever an endpoint accepts an ID pointing to a specific resource, you must explicitly verify that the logged-in user has the right to access *that* resource — being successfully logged in is not enough. This check needs to be repeated for every single resource "owned" by a user (notes, orders, messages, files...), not just once at a general level.

---

## FIX-04 (bonus) — Plaintext passwords → salted hashing

**Before** (`vulnerable/database.py` / `app.py`):
```python
cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
# ...
cur.execute(f"... AND password = '{password}'")
```

**After** (`fixed/database.py` / `app.py`):
```python
from werkzeug.security import generate_password_hash, check_password_hash

# on registration:
generate_password_hash(password)

# on login:
check_password_hash(user["password_hash"], password)
```

**Why it works:** Werkzeug's `generate_password_hash` (bundled with Flask) uses a hashing algorithm designed for passwords (with a random salt built in and a deliberately high computational cost, to slow down brute-force attacks against a stolen database). Even with direct access to the database, an attacker cannot recover the original password in a reasonable amount of time, and two users with the same password will have different hashes thanks to the salt.

---

## Why this comparison matters in an interview

Don't just say "I fixed a SQL injection." Be ready to explain **why** the fix works at the mechanism level (not just "you use placeholders"), because that's exactly the follow-up question a technical interviewer will ask — and it's the difference between "I copied a best practice" and "I understood the problem."
