"""
Methods used for conversion between types and encodings
"""



def to_bytes(data, encoding="utf-8") -> bytes:
    """
    Convert data to bytes representation
    """

    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode(encoding=encoding)


def to_str(data, encoding="utf-8") -> str:
    """
    Convert to string representation of objects
    """
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode(encoding=encoding)
