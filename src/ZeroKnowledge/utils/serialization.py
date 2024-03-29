def dump_object(dc):
    """
    Dump a JSON Dataclass to compressed JSON
    """
    return dc.to_json(separators=(",", ":"))