import hashlib
import hmac
import os
from typing import Optional

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


ARGON2_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_sha256(password: str, password_hash: str) -> bool:
    calculated = hash_sha256(password)
    return hmac.compare_digest(calculated, password_hash)


def hash_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_bcrypt(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


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


def read_pepper() -> Optional[str]:
    return os.environ.get("PASSWORD_PEPPER")
