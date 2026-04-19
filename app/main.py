import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, request

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.password_utils import hash_password, verify_password
from config import DB_PATH, LOCK_DURATION_MINUTES, MAX_FAILED_ATTEMPTS, SUPPORTED_ALGORITHMS


app = Flask(__name__)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    UNIQUE NOT NULL,
                algo            TEXT    NOT NULL,
                password_hash   TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT
            );
            """
        )
        conn.commit()


@app.post("/register")
def register():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    algo = data.get("algo", "argon2id")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if algo not in SUPPORTED_ALGORITHMS:
        return jsonify({"error": f"invalid algorithm, choose one of: {sorted(SUPPORTED_ALGORITHMS)}"}), 400

    password_hash = hash_password(password, algo)

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, algo, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, algo, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        return jsonify({"status": "ok", "username": username, "algo": algo}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409


@app.post("/login")
def login():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")

    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user:
            return jsonify({"error": "invalid credentials"}), 401

        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now(timezone.utc) < locked_until:
                return jsonify({"error": "account temporarily locked"}), 423

        if verify_password(password, user["algo"], user["password_hash"]):
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            return jsonify({"status": "ok"})

        failed_attempts = user["failed_attempts"] + 1
        locked_until = None
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_DURATION_MINUTES)).isoformat()
            failed_attempts = 0

        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed_attempts, locked_until, user["id"]),
        )
        conn.commit()
        return jsonify({"error": "invalid credentials"}), 401


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
