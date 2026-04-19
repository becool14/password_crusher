"""
Generate and seed mock users into the database.

Usage:
    python generate_users.py                  # 20 users, random algorithms
    python generate_users.py --count 50       # 50 users, random algorithms
    python generate_users.py --algo argon2id  # 20 users, all using argon2id
"""

import argparse
import random
import sqlite3
import sys
from pathlib import Path

from faker import Faker

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.password_utils import hash_password
from config import DB_PATH, SUPPORTED_ALGORITHMS


faker = Faker("pl_PL")

DEFAULT_USER_COUNT = 20


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed mock users into the database.")
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_USER_COUNT,
        help=f"Number of users to generate (default: {DEFAULT_USER_COUNT})",
    )
    parser.add_argument(
        "--algo",
        choices=sorted(SUPPORTED_ALGORITHMS) + ["random"],
        default="random",
        help="Hashing algorithm to use for all users, or 'random' to mix (default: random)",
    )
    return parser.parse_args()


def random_password() -> str:
    word = faker.word().capitalize()
    number = random.randint(10, 999)
    symbol = random.choice("!@#$%^&*")
    return f"{word}{number}{symbol}"


def generate_users(count: int, algo: str) -> list[tuple[str, str, str]]:
    seen_usernames: set[str] = set()
    users = []

    while len(users) < count:
        username = faker.user_name()
        if username in seen_usernames:
            continue
        seen_usernames.add(username)

        password = random_password()
        chosen_algo = algo if algo != "random" else random.choice(sorted(SUPPORTED_ALGORITHMS))
        users.append((username, password, chosen_algo))

    return users


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    UNIQUE NOT NULL,
                algo            TEXT    NOT NULL,
                password_hash   TEXT    NOT NULL,
                created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT
            );
            """
        )
        conn.commit()


def seed_users(users: list[tuple[str, str, str]]) -> int:
    seeded = 0
    with sqlite3.connect(DB_PATH) as conn:
        for username, password, algo in users:
            password_hash = hash_password(password, algo)
            try:
                conn.execute(
                    """
                    INSERT INTO users (username, algo, password_hash)
                    VALUES (?, ?, ?);
                    """,
                    (username, algo, password_hash),
                )
                seeded += 1
            except sqlite3.IntegrityError:
                print(f"  Skipped '{username}' — already exists.")
        conn.commit()
    return seeded


if __name__ == "__main__":
    args = parse_args()

    print(f"Generating {args.count} users (algo: {args.algo})...")
    users = generate_users(args.count, args.algo)

    init_db()
    seeded = seed_users(users)

    print(f"Done. Seeded {seeded}/{args.count} users into {DB_PATH}")
