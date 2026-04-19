import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Callable, Optional

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ARGON2_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


@dataclass(frozen=True)
class AlgorithmSpec:
    hash:   Callable[[str], str]
    verify: Callable[[str, str], bool]


def read_pepper() -> Optional[str]:
    return os.environ.get("PASSWORD_PEPPER")


def _make_registry(pepper: Optional[str]) -> dict[str, AlgorithmSpec]:
    def _hash_hashlib(name: str) -> Callable[[str], str]:
        return lambda p: hashlib.new(name, p.encode()).hexdigest()

    def _verify_hashlib(name: str) -> Callable[[str, str], bool]:
        return lambda p, h: hmac.compare_digest(hashlib.new(name, p.encode()).hexdigest(), h)

    def _hash_pbkdf2(p: str) -> str:
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, iterations=260_000)
        return f"{salt.hex()}${key.hex()}"

    def _verify_pbkdf2(p: str, h: str) -> bool:
        salt_hex, key_hex = h.split("$")
        salt = bytes.fromhex(salt_hex)
        actual = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, iterations=260_000)
        return hmac.compare_digest(actual, bytes.fromhex(key_hex))

    def _hash_scrypt(p: str) -> str:
        salt = os.urandom(16)
        key = hashlib.scrypt(p.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return f"{salt.hex()}${key.hex()}"

    def _verify_scrypt(p: str, h: str) -> bool:
        salt_hex, key_hex = h.split("$")
        salt = bytes.fromhex(salt_hex)
        actual = hashlib.scrypt(p.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, bytes.fromhex(key_hex))

    def _hash_argon2id(p: str) -> str:
        return _ARGON2_HASHER.hash(f"{p}{pepper}" if pepper else p)

    def _verify_argon2id(p: str, h: str) -> bool:
        try:
            return _ARGON2_HASHER.verify(h, f"{p}{pepper}" if pepper else p)
        except VerifyMismatchError:
            return False

    return {
        "md5":           AlgorithmSpec(_hash_hashlib("md5"),    _verify_hashlib("md5")),
        "sha1":          AlgorithmSpec(_hash_hashlib("sha1"),   _verify_hashlib("sha1")),
        "sha256":        AlgorithmSpec(_hash_hashlib("sha256"), _verify_hashlib("sha256")),
        "pbkdf2_sha256": AlgorithmSpec(_hash_pbkdf2,            _verify_pbkdf2),
        "scrypt":        AlgorithmSpec(_hash_scrypt,            _verify_scrypt),
        "bcrypt":        AlgorithmSpec(
                             lambda p: bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12)).decode(),
                             lambda p, h: bcrypt.checkpw(p.encode(), h.encode()),
                         ),
        "argon2id":      AlgorithmSpec(_hash_argon2id, _verify_argon2id),
    }


def hash_password(password: str, algo: str) -> str:
    reg = _make_registry(read_pepper())
    if algo not in reg:
        raise ValueError(f"Unsupported algorithm: {algo!r}. Choose from: {sorted(reg)}")
    return reg[algo].hash(password)


def verify_password(password: str, algo: str, password_hash: str) -> bool:
    reg = _make_registry(read_pepper())
    if algo not in reg:
        return False
    return reg[algo].verify(password, password_hash)
