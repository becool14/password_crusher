import sys
from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import DB_PATH

OUT_DIR = BASE_DIR / "hashes"


def export() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT username, algo, password_hash FROM users ORDER BY id").fetchall()

    grouped: dict[str, list] = {}
    for username, algo, password_hash in rows:
        grouped.setdefault(algo, []).append((username, password_hash))

    for algo, items in grouped.items():
        file_path = OUT_DIR / f"{algo}.txt"
        with file_path.open("w", encoding="utf-8") as f:
            for username, password_hash in items:
                f.write(f"{username}:{password_hash}\n")
        print(f"Exported {len(items)} entries -> {file_path}")


if __name__ == "__main__":
    export()
