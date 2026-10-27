import os
import sqlite3
from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  uploaded_at TEXT NOT NULL);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    con = sqlite3.connect(app.config["DATABASE"])
    con.executescript(SCHEMA)
    if app.config["SEED"] and con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # Dummy demo accounts - synthetic data only
        for i, (user, pw) in enumerate([("alice", "Alice@12345"), ("bob", "Bob@12345")], 1):
            con.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                        (user, generate_password_hash(pw)))
            stored = f"seed{i}0000000000000000000000000000.txt"
            body = f"Sample private document belonging to {user}.\nSynthetic data only.\n"
            with open(os.path.join(app.config["UPLOAD_DIR"], stored), "w") as fh:
                fh.write(body)
            con.execute("INSERT INTO documents(owner_id,original_name,stored_name,mime,size,uploaded_at)"
                        " VALUES(?,?,?,?,?,?)",
                        (i, f"{user}-notes.txt", stored, "text/plain", len(body), "2026-01-01 09:00"))
    con.commit()
    con.close()
