from base64 import b64encode, b64decode  # Import base64 encoding and decoding functions
from dataclasses import is_dataclass  # Import function to check if an object is a dataclass
from typing import Union  # Import Union for type hints

from ecpy.curves import Point  # Import Point from ecpy.curves module


def bytes_to_int(value: Union[str, bytes, bytearray, Point]) -> int:
    """
    Convert any value to an integer from the big endian bytes representation
    """
    return int.from_bytes(to_bytes(value), byteorder="big")


def int_to_bytes(value: int) -> bytes:
    """
    Convert an integer value to bytes in big endian representation
    """
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")


def data_to_b64_str(data, strip=True) -> str:
    """
    Encode in base64, optionally strip padding
    """
    return to_str(b64encode(to_bytes(data)).rstrip(b"=" if strip else b"").decode())


def b64d(data, pad=True) -> bytes:
    """
    Decode base64 to bytes, append padding just in case
    """
    return b64decode(to_bytes(data) + b"===" if pad else b"")


def to_bytes(data, encoding="utf-8", errors="replace") -> bytes:
    """
    Convert data to bytes representation
    """
    if isinstance(data, bytearray):  # Check if data is a bytearray
        return bytes(data)  # Convert bytearray to bytes
    if isinstance(data, bytes):  # Check if data is already bytes
        return data  # Return data as is
    if isinstance(data, str):  # Check if data is a string
        return data.encode(encoding=encoding, errors=errors)  # Encode string to bytes
    if isinstance(data, int):  # Check if data is an integer
        return int_to_bytes(data)  # Convert integer to bytes
    if isinstance(data, Point):  # Check if data is a Point object
        c = data.curve  # Get the curve from the Point object
        from ecpy.curves import MontgomeryCurve, WeierstrassCurve, TwistedEdwardCurve
        if isinstance(c, (MontgomeryCurve, TwistedEdwardCurve)):  # Check curve type
            return bytes(c.encode_point(data))  # Encode point using curve
        if isinstance(c, WeierstrassCurve):  # Check curve type
            return bytes(c.encode_point(data, compressed=True))  # Encode point using curve with compression
        raise TypeError("Unknown Curve Type")  # Raise error for unknown curve type
    print("UNTYPED:", type(data), "\n", data)  # Print message for untyped data
    return bytes(data)  # Convert data to bytes (fall back)


def to_str(data, encoding="utf-8", errors="replace") -> str:
    """
    Convert to string representation of objects
    """
    if isinstance(data, str):  # Check if data is already a string
        return data  # Return data as is
    if is_dataclass(data):  # Check if data is a dataclass
        return data.to_json(separators=(",", ":"))  # Convert dataclass to JSON string
    if isinstance(data, bytes):  # Check if data is bytes
        return data.decode(encoding=encoding, errors=errors)  # Decode bytes to string
    if isinstance(data, bytearray):  # Check if data is a bytearray
        return bytes(data).decode(encoding=encoding, errors=errors)  # Decode bytearray to string
    if isinstance(data, int):  # Check if data is an integer
        return str(data)  # Convert integer to string
    return str(data)  # Convert any other type to string (fall back)
