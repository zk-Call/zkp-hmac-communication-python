import secrets
from ..utils import get_random_int, hash_digest

# Secure random generation



class SeedGenerator:
    def __init__(self, phrase: str):
        self._phrase = phrase

    def _hash(self, lenght: int) -> bytes:
        combinated_bytes = secrets.token_bytes(lenght) + self._phrase.encode('utf-8')
        return hash_digest(combinated_bytes)

    def generate(self) -> bytes:
        return self._hash(get_random_int())
