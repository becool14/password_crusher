from pathlib import Path
import sqlite3


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "users.db"
OUT_DIR = BASE_DIR / "hashes"


def export() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT username, algo, password_hash FROM users ORDER BY id").fetchall()

    grouped = {"sha256": [], "bcrypt": [], "argon2id": []}
    for username, algo, password_hash in rows:
        grouped[algo].append((username, password_hash))

    for algo, items in grouped.items():
        file_path = OUT_DIR / f"{algo}.txt"
        with file_path.open("w", encoding="utf-8") as f:
            for username, password_hash in items:
                f.write(f"{username}:{password_hash}\n")
        print(f"Exported {len(items)} entries -> {file_path}")


if __name__ == "__main__":
    export()
