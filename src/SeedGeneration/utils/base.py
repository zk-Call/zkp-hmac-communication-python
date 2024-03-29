import hashlib
import random


def get_random_int():
    random_int = random.randint(0, 2 ** 20)
    return random_int


def hash_digest(combined_bytes: bytes) -> bytes:
    return hashlib.sha256(combined_bytes).digest()
