"""
database.py (VULNERABLE VERSION)

Note: schema creation and seed data are identical to the fixed version.
What changes between the two versions is HOW the queries are EXECUTED
(see app.py), not the schema itself.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset=False):
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Seed data only if the DB is empty: two demo users, each with one note.
    # These are needed to demonstrate the IDOR: while logged in as alice,
    # visit /notes/2 (bob's note) and observe the difference between the
    # two versions.
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        # WARNING: plaintext password, vulnerable version only.
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", "alice123"))
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", "bob123"))
        cur.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (1, "Alice's private note", "This note should only be visible to Alice."),
        )
        cur.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (2, "Bob's private note", "This note should only be visible to Bob."),
        )

    conn.commit()
    conn.close()
