import hashlib
import hmac
import os
from typing import Optional

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# --- Argon2id hasher (configured once, reused everywhere) ---

ARGON2_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

SUPPORTED_ALGORITHMS = {"md5", "sha1", "sha256", "pbkdf2_sha256", "scrypt", "bcrypt", "argon2id"}

# Algorithms kept only for educational comparison — not safe for real use.
WEAK_ALGORITHMS = {"md5", "sha1", "sha256"}


# --- Weak / legacy algorithms (no salt, shown for contrast) ---

def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def verify_md5(password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_md5(password), password_hash)


def hash_sha1(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def verify_sha1(password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_sha1(password), password_hash)


def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_sha256(password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_sha256(password), password_hash)


# --- Modern algorithms (salted, slow by design) ---

def hash_pbkdf2(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=260_000)
    return f"{salt.hex()}${key.hex()}"


def verify_pbkdf2(password: str, password_hash: str) -> bool:
    salt_hex, key_hex = password_hash.split("$")
    salt = bytes.fromhex(salt_hex)
    expected_key = bytes.fromhex(key_hex)
    actual_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=260_000)
    return hmac.compare_digest(actual_key, expected_key)


def hash_scrypt(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"{salt.hex()}${key.hex()}"


def verify_scrypt(password: str, password_hash: str) -> bool:
    salt_hex, key_hex = password_hash.split("$")
    salt = bytes.fromhex(salt_hex)
    expected_key = bytes.fromhex(key_hex)
    actual_key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(actual_key, expected_key)


def hash_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_bcrypt(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def hash_argon2id(password: str, pepper: Optional[str] = None) -> str:
    if pepper:
        password = f"{password}{pepper}"
    return ARGON2_HASHER.hash(password)


def verify_argon2id(password: str, password_hash: str, pepper: Optional[str] = None) -> bool:
    if pepper:
        password = f"{password}{pepper}"
    try:
        return ARGON2_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


# --- Unified interface used by the rest of the app ---

def read_pepper() -> Optional[str]:
    return os.environ.get("PASSWORD_PEPPER")


def hash_password(password: str, algo: str) -> str:
    pepper = read_pepper()
    dispatch = {
        "md5":          lambda p: hash_md5(p),
        "sha1":         lambda p: hash_sha1(p),
        "sha256":       lambda p: hash_sha256(p),
        "pbkdf2_sha256": lambda p: hash_pbkdf2(p),
        "scrypt":       lambda p: hash_scrypt(p),
        "bcrypt":       lambda p: hash_bcrypt(p),
        "argon2id":     lambda p: hash_argon2id(p, pepper=pepper),
    }
    if algo not in dispatch:
        raise ValueError(f"Unsupported algorithm: {algo!r}. Choose from: {sorted(dispatch)}")
    return dispatch[algo](password)


def verify_password(password: str, algo: str, password_hash: str) -> bool:
    pepper = read_pepper()
    dispatch = {
        "md5":           lambda p, h: verify_md5(p, h),
        "sha1":          lambda p, h: verify_sha1(p, h),
        "sha256":        lambda p, h: verify_sha256(p, h),
        "pbkdf2_sha256": lambda p, h: verify_pbkdf2(p, h),
        "scrypt":        lambda p, h: verify_scrypt(p, h),
        "bcrypt":        lambda p, h: verify_bcrypt(p, h),
        "argon2id":      lambda p, h: verify_argon2id(p, h, pepper=pepper),
    }
    if algo not in dispatch:
        return False
    return dispatch[algo](password, password_hash)
