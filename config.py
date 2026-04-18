from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = BASE_DIR / "data" / "users.db"

MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION_MINUTES = 5
