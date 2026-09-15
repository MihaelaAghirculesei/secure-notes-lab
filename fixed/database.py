"""
database.py (FIXED VERSION)

Same schema as the vulnerable version, but passwords are stored as
hashes (see app.py, register()/login() functions using
werkzeug.security), not in plaintext.
"""
import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "fixed.db")


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
            password_hash TEXT NOT NULL
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

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("alice", generate_password_hash("alice123")),
        )
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("bob", generate_password_hash("bob123")),
        )
        cur.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (1, "Alice's private note", "This note is only visible to Alice."),
        )
        cur.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (2, "Bob's private note", "This note is only visible to Bob."),
        )

    conn.commit()
    conn.close()
