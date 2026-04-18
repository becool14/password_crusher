from itertools import product
from pathlib import Path
import csv
import hashlib
import time

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


BASE_DIR = Path(__file__).resolve().parent.parent
HASH_DIR = BASE_DIR / "hashes"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_FILE = RESULTS_DIR / "attack_results.csv"

PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

DICTIONARY = [
    "123456",
    "qwerty",
    "password",
    "Password1",
    "AlaMaKota1!",
    "MojeHaslo2024",
    "ArgonMocne!1",
    "admin123",
    "letmein",
]


def load_hashes(algo: str):
    path = HASH_DIR / f"{algo}.txt"
    entries = []
    if not path.exists():
        return entries
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            username, password_hash = line.strip().split(":", 1)
            entries.append((username, password_hash))
    return entries


def verify_candidate(algo: str, candidate: str, password_hash: str) -> bool:
    if algo == "sha256":
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest() == password_hash
    if algo == "bcrypt":
        return bcrypt.checkpw(candidate.encode("utf-8"), password_hash.encode("utf-8"))
    if algo == "argon2id":
        try:
            return PH.verify(password_hash, candidate)
        except VerifyMismatchError:
            return False
    return False


def dictionary_attack(algo: str, entries):
    cracked = {}
    start = time.perf_counter()
    for username, password_hash in entries:
        for candidate in DICTIONARY:
            if verify_candidate(algo, candidate, password_hash):
                cracked[username] = candidate
                break
    elapsed = time.perf_counter() - start
    return cracked, elapsed


def brute_force_candidates(max_len=4, charset="abc123"):
    for length in range(1, max_len + 1):
        for chars in product(charset, repeat=length):
            yield "".join(chars)


def brute_force_attack(algo: str, entries, limit_seconds=20):
    cracked = {}
    start = time.perf_counter()
    candidates = brute_force_candidates()

    for username, password_hash in entries:
        user_start = time.perf_counter()
        for candidate in candidates:
            if verify_candidate(algo, candidate, password_hash):
                cracked[username] = candidate
                break
            if time.perf_counter() - start >= limit_seconds:
                return cracked, time.perf_counter() - start
            if time.perf_counter() - user_start > limit_seconds / max(len(entries), 1):
                break
    elapsed = time.perf_counter() - start
    return cracked, elapsed


def run():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for algo in ("sha256", "bcrypt", "argon2id"):
        entries = load_hashes(algo)
        total = len(entries)
        if total == 0:
            continue

        cracked_dict, t_dict = dictionary_attack(algo, entries)
        cracked_brute, t_brute = brute_force_attack(algo, entries, limit_seconds=20)

        rows.append(
            {
                "algorithm": algo,
                "total_hashes": total,
                "dictionary_cracked": len(cracked_dict),
                "dictionary_success_pct": round((len(cracked_dict) / total) * 100, 2),
                "dictionary_time_s": round(t_dict, 4),
                "bruteforce_cracked": len(cracked_brute),
                "bruteforce_success_pct": round((len(cracked_brute) / total) * 100, 2),
                "bruteforce_time_s": round(t_brute, 4),
            }
        )

    with RESULTS_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "algorithm",
                "total_hashes",
                "dictionary_cracked",
                "dictionary_success_pct",
                "dictionary_time_s",
                "bruteforce_cracked",
                "bruteforce_success_pct",
                "bruteforce_time_s",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved results to: {RESULTS_FILE}")
    for row in rows:
        print(row)


if __name__ == "__main__":
    run()
