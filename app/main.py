from datetime import datetime, timedelta
from pathlib import Path
import sqlite3

from flask import Flask, jsonify, request

from password_utils import (
    hash_argon2id,
    hash_bcrypt,
    hash_sha256,
    read_pepper,
    verify_argon2id,
    verify_bcrypt,
    verify_sha256,
)


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "users.db"
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 5

app = Flask(__name__)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                algo TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            );
            """
        )
        conn.commit()


def build_hash(password: str, algo: str) -> str:
    pepper = read_pepper()
    if algo == "sha256":
        return hash_sha256(password)
    if algo == "bcrypt":
        return hash_bcrypt(password)
    if algo == "argon2id":
        return hash_argon2id(password, pepper=pepper)
    raise ValueError("Unsupported algorithm")


def verify_hash(password: str, algo: str, password_hash: str) -> bool:
    pepper = read_pepper()
    if algo == "sha256":
        return verify_sha256(password, password_hash)
    if algo == "bcrypt":
        return verify_bcrypt(password, password_hash)
    if algo == "argon2id":
        return verify_argon2id(password, password_hash, pepper=pepper)
    return False


@app.post("/register")
def register():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    algo = data.get("algo", "argon2id")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if algo not in {"sha256", "bcrypt", "argon2id"}:
        return jsonify({"error": "invalid algorithm"}), 400

    password_hash = build_hash(password, algo)

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, algo, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, algo, password_hash, datetime.utcnow().isoformat()),
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
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            return jsonify({"error": "invalid credentials"}), 401

        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                return jsonify({"error": "account temporarily locked"}), 423

        is_valid = verify_hash(password, user["algo"], user["password_hash"])
        if is_valid:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            return jsonify({"status": "ok"})

        failed_attempts = user["failed_attempts"] + 1
        locked_until = None
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)).isoformat()
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
