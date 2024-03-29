from ecpy.curves import Curve  # Import Curve from ecpy.curves module
from ecpy.curves import Point  # Import Point from ecpy.curves module
from ..utils import convert  # Import convert module from the parent package
from typing import Union  # Import Union for type hints
from ..algorithms import Hash_types  # Import Hash_types from the parent package

def curve_by_name(name: str) -> Curve:
    """
    Get curve by name, case-insensitive
    """
    validNames = Curve.get_curve_names()  # Get all valid curve names
    for valid_name in validNames:  # Iterate through valid curve names
        if valid_name.lower() == name.lower():  # Check if the name matches (case-insensitive)
            return Curve.get_curve(valid_name)  # Return the curve corresponding to the name
    return None  # Return None if no matching curve is found

def mod(a: int, b: int) -> int:
    """
    Return a mod b, account for positive/negative numbers
    """
    return (a % b + b) % b  # Compute a mod b, considering positive/negative numbers

def hash_data(*values: Union[str, bytes, bytearray, int, Point], algorithm="sha3_256") -> bytes:
    """
    Convert all provided values to bytes, and return the digest in bytes
    """
    if algorithm not in Hash_types:  # Check if the hash algorithm is supported
        raise NotImplementedError(f"Hash algorithm '{algorithm}' is not supported")
    return Hash_types[algorithm](b"".join(map(convert.to_bytes, values))).digest()  # Compute hash of concatenated values

def hash_numeric(*values: Union[str, bytes, bytearray, int, Point], alg="sha3_256") -> int:
    """
    Compute the cryptographic hash of the provided values and return the digest in integer form
    """
    return convert.bytes_to_int(hash_data(*values, algorithm=alg))  # Convert hash digest to integer form
