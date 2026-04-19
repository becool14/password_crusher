from itertools import product
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse
import csv
import sys
import threading
import time

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.password_utils import verify_password
HASH_DIR = BASE_DIR / "hashes"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_FILE = RESULTS_DIR / "attack_results.csv"
WORDLIST_FILE = BASE_DIR / "data" / "wordlist.txt"

WORKERS: int = 4  # overridden by --workers at runtime


def load_wordlist() -> list[str]:
    if not WORDLIST_FILE.exists():
        print(f"[!] Wordlist not found at {WORDLIST_FILE}, using empty list.")
        return []
    with WORDLIST_FILE.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

LEET = str.maketrans("aAeEiIoOsS", "4433110055")

COMMON_NUMBERS = [
    str(n) for n in [
        10, 11, 12, 13, 21, 22, 23, 42, 69, 99,
        100, 111, 123, 321, 456, 789, 999, 2023, 2024,
    ]
]
COMMON_SYMBOLS = list("!@#$%^&*")


def generate_mutations(wordlist: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    def add(w: str) -> None:
        if w not in seen:
            seen.add(w)
            result.append(w)

    for word in wordlist:
        variants = {word, word.lower(), word.upper(), word.capitalize(), word.lower().translate(LEET)}
        for v in variants:
            add(v)
            for sym in COMMON_SYMBOLS:
                add(v + sym)
            for num in COMMON_NUMBERS:
                add(v + num)
                for sym in COMMON_SYMBOLS:
                    add(v + num + sym)

    return result


def crack_single(algo: str, password_hash: str, candidates: list[str]) -> str | None:
    stop = threading.Event()
    result: list[str] = []
    chunks = [candidates[i::WORKERS] for i in range(WORKERS)]

    def worker(chunk: list[str]) -> None:
        for c in chunk:
            if stop.is_set():
                return
            if verify_password(c, algo, password_hash):
                result.append(c)
                stop.set()
                return

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(worker, chunk) for chunk in chunks]
        for f in futures:
            f.result()

    return result[0] if result else None


def load_hashes(algo: str) -> list[tuple[str, str]]:
    path = HASH_DIR / f"{algo}.txt"
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return [tuple(line.strip().split(":", 1)) for line in f if line.strip()]


def dictionary_attack(algo: str, entries: list) -> tuple[dict, float]:
    candidates = generate_mutations(load_wordlist())
    cracked: dict[str, str] = {}
    start = time.perf_counter()
    total = len(entries)

    print(f"  Dictionary+rules attack ({len(candidates)} candidates, {WORKERS} workers):")
    for i, (username, password_hash) in enumerate(entries, 1):
        print(f"    [{i}/{total}] {username} ... ", end="", flush=True)
        found = crack_single(algo, password_hash, candidates)
        if found:
            cracked[username] = found
        print(f"CRACKED: '{found}'" if found else "not cracked")

    return cracked, time.perf_counter() - start


def brute_force_candidates(max_len: int = 5, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789!@#"):
    for length in range(1, max_len + 1):
        for chars in product(charset, repeat=length):
            yield "".join(chars)


def brute_force_attack(algo: str, entries: list, limit_seconds: int = 20) -> tuple[dict, float]:
    cracked: dict[str, str] = {}
    start = time.perf_counter()
    total = len(entries)

    print(f"  Brute-force attack (limit {limit_seconds}s, alphanum+symbols, max_len=5):")
    for i, (username, password_hash) in enumerate(entries, 1):
        print(f"    [{i}/{total}] {username} ... ", end="", flush=True)
        found = None
        user_start = time.perf_counter()

        for candidate in brute_force_candidates():
            if verify_password(candidate, algo, password_hash):
                found = candidate
                cracked[username] = candidate
                break
            if time.perf_counter() - start >= limit_seconds:
                print("time limit reached")
                return cracked, time.perf_counter() - start
            if time.perf_counter() - user_start > limit_seconds / max(total, 1):
                break

        print(f"CRACKED: '{found}'" if found else "not cracked")

    return cracked, time.perf_counter() - start


def run() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    algos = sorted(p.stem for p in HASH_DIR.glob("*.txt"))
    rows = []

    print(f"Found {len(algos)} algorithm(s): {', '.join(algos)}\n")

    for idx, algo in enumerate(algos, 1):
        entries = load_hashes(algo)
        total = len(entries)
        if total == 0:
            print(f"[{idx}/{len(algos)}] {algo}: no hashes, skipping\n")
            continue

        print(f"[{idx}/{len(algos)}] {algo.upper()} — {total} hashes")

        cracked_dict, t_dict = dictionary_attack(algo, entries)
        print(f"  => {len(cracked_dict)}/{total} cracked in {t_dict:.4f}s")

        cracked_brute, t_brute = brute_force_attack(algo, entries, limit_seconds=20)
        print(f"  => {len(cracked_brute)}/{total} cracked in {t_brute:.4f}s\n")

        rows.append({
            "algorithm": algo,
            "total_hashes": total,
            "dictionary_cracked": len(cracked_dict),
            "dictionary_success_pct": round(len(cracked_dict) / total * 100, 2),
            "dictionary_time_s": round(t_dict, 4),
            "bruteforce_cracked": len(cracked_brute),
            "bruteforce_success_pct": round(len(cracked_brute) / total * 100, 2),
            "bruteforce_time_s": round(t_brute, 4),
        })

    if not rows:
        print("No results to save.")
        return

    with RESULTS_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run dictionary and brute-force attacks.")
    parser.add_argument("--workers", type=int, default=WORKERS, help=f"Number of parallel workers (default: {WORKERS})")
    args = parser.parse_args()
    WORKERS = args.workers
    print(f"Using {WORKERS} worker(s)\n")
    run()
