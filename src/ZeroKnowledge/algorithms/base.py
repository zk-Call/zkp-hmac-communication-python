import hashlib
from jwt import register_algorithm
from jwt.algorithms import HMACAlgorithm

Hash_types = {
    name: getattr(hashlib, name) for name in (
        "md5", "sha1", "sha224", "sha256", "sha512", "sha3_224",
        "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
    )
}

# Register new JWT algorithms with supported hashlib algorithms
algorithms = {
    "HS3_224": hashlib.sha3_224,
    "HS3_256": hashlib.sha3_256,
    "HS3_384": hashlib.sha3_384,
    "HS3_512": hashlib.sha3_512,
    "HB2S": hashlib.blake2s,
    "HB2B": hashlib.blake2b
}

# Register each algorithm with its hash function
for algorithm, hash_function in algorithms.items():
    register_algorithm(algorithm, HMACAlgorithm(hash_function))
