# Vulnerability Report — SecureNotes Lab (vulnerable version)

Each entry follows the structure of a real vulnerability report: description, exploitation steps, impact, OWASP reference.

---

## VULN-01 — SQL Injection (authentication)

**Component:** `vulnerable/app.py`, `login()` function
**OWASP category:** A03:2021 — Injection

### Description
The login query is built by directly concatenating user input into an f-string, with no sanitization:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

### Exploitation steps
1. Go to `/login`.
2. As username, enter: `' OR '1'='1' --`
3. As password, enter anything (e.g. `x`).
4. Submit the form.

**Result:** successful login without knowing any valid credentials, because the executed query becomes logically always true and the `--` comments out the rest of the condition (including the password check).

### Impact
An attacker completely bypasses authentication and can log in as any user (in the `admin' --` variant, specifically as a chosen user).

---

## VULN-02 — Stored XSS (note content)

**Component:** `vulnerable/templates/note_detail.html`
**OWASP category:** A03:2021 — Injection (Cross-Site Scripting)

### Description
The note content is rendered in the template with the Jinja2 `| safe` filter, which disables automatic HTML escaping:

```
{{ note['content'] | safe }}
```

### Exploitation steps
1. Log in (e.g. `alice / alice123`).
2. Create a new note with content: `<script>alert(document.cookie)</script>`
3. Open the note you just created.

**Result:** the script is executed by the browser when the page is rendered, because the `<script>` tag ends up in the page's HTML exactly as written.

### Impact
In a real-world scenario (a note shared/viewed by other users, e.g. a public comment) this would allow session cookie theft, malicious redirects, or actions performed in the victim's browser without their knowledge.

---

## VULN-03 — IDOR (Insecure Direct Object Reference)

**Component:** `vulnerable/app.py`, `view_note()` function
**OWASP category:** A01:2021 — Broken Access Control

### Description
The note is fetched from the database based only on the ID passed in the URL, without checking that it belongs to the currently authenticated user:

```python
cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
note = cur.fetchone()
# no check on note['user_id'] == session['user_id']
```

### Exploitation steps
1. Log in as `alice` (user_id 1, note with id 1).
2. Go to `/notes/2` (bob's note, user_id 2).

**Result:** bob's note content is shown to alice, just by changing a number in the URL.

### Impact
Any authenticated user can read any other user's private data simply by enumerating IDs — one of the most common and most severe vulnerabilities in real applications, because it requires no advanced technical skill to exploit.

---

## VULN-04 (bonus) — Passwords stored in plaintext

**Component:** `vulnerable/database.py`, `vulnerable/app.py` (`register()` function)
**OWASP category:** A02:2021 — Cryptographic Failures

### Description
Passwords are stored in the database exactly as entered by the user, with no hashing.

### Impact
In the event of unauthorized access to the database (e.g. via VULN-01 with broader privileges, or an exposed backup), all user passwords would be immediately readable in plaintext — with consequences for other services too, since many users reuse passwords.

---

## VULN-05 (bonus) — CSRF (Cross-Site Request Forgery)

**Component:** `vulnerable/app.py` — `login()`, `register()`, `new_note()` (every state-changing POST)
**OWASP category:** A01:2021 — Broken Access Control (CSRF was its own OWASP category through the 2013 list; folded into Broken Access Control since 2017, but the mechanism and the fix are unchanged)

### Description
None of the POST forms include or check any per-session token. The server accepts a POST purely based on the session cookie the browser attaches automatically — it never confirms the request was actually initiated by a page the user is looking at.

### Exploitation steps
1. Log in to the vulnerable app (e.g. `alice / alice123`) in one browser tab.
2. In the same browser, open a separate, attacker-controlled page containing an auto-submitting form:
   ```html
   <form action="http://127.0.0.1:5000/notes/new" method="POST" id="f">
     <input type="hidden" name="title" value="pwned">
     <input type="hidden" name="content" value="posted without your consent">
   </form>
   <script>document.getElementById('f').submit()</script>
   ```
3. Visiting that page is enough — no click needed.

**Result:** the note is created under alice's account, even though alice never interacted with the vulnerable app's own UI to do it. The same pattern works against `/login` and `/register`.

### Impact
An attacker can make a logged-in victim's browser perform any state-changing action the app exposes (here: create notes; in a real app, this class of bug has been used to change email/password, transfer funds, or delete data) just by getting them to load a malicious page — no credential theft required.

---

## Methodological note

These issues are not theoretical textbook cases: they are mistakes found regularly in real code, often introduced due to time pressure or lack of awareness, not gross negligence. The `REMEDIATION.md` file shows how each one is fixed with a targeted change, not a full rewrite of the application — which is also why it's worth learning them well: the fix is almost always simpler than the vulnerability itself, once you know what to look for.
