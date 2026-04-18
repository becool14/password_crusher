from pathlib import Path
import sqlite3
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.password_utils import hash_argon2id, hash_bcrypt, hash_sha256, read_pepper
DB_PATH = BASE_DIR / "data" / "users.db"

TEST_USERS = [
    ("anna1", "123456", "sha256"),
    ("bartek1", "qwerty", "sha256"),
    ("celina1", "Password1", "sha256"),
    ("dawid1", "AlaMaKota1!", "bcrypt"),
    ("ewa1", "MojeHaslo2024", "bcrypt"),
    ("filip1", "Bezpieczne#Haslo7", "bcrypt"),
    ("gosia1", "ArgonMocne!1", "argon2id"),
    ("hubert1", "TopSekret!22", "argon2id"),
    ("iza1", "Niezgadniesz#44", "argon2id"),
]


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                algo TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            );
            """
        )
        conn.commit()


def hash_password(password: str, algo: str) -> str:
    pepper = read_pepper()
    if algo == "sha256":
        return hash_sha256(password)
    if algo == "bcrypt":
        return hash_bcrypt(password)
    if algo == "argon2id":
        return hash_argon2id(password, pepper=pepper)
    raise ValueError(f"Unsupported algorithm: {algo}")


def seed_users() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        for username, password, algo in TEST_USERS:
            password_hash = hash_password(password, algo)
            conn.execute(
                """
                INSERT OR REPLACE INTO users (id, username, algo, password_hash, created_at, failed_attempts, locked_until)
                VALUES (
                    (SELECT id FROM users WHERE username = ?),
                    ?, ?, ?, CURRENT_TIMESTAMP, 0, NULL
                );
                """,
                (username, username, algo, password_hash),
            )
        conn.commit()


if __name__ == "__main__":
    init_db()
    seed_users()
    print(f"Seeded {len(TEST_USERS)} users in {DB_PATH}")
