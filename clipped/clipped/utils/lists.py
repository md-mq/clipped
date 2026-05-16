from collections.abc import Mapping
import logging
from typing import Any, List


try:
    import numpy as np
except ImportError:
    np = None


def to_list(
    value: Any,
    check_none: bool = False,
    check_dict: bool = False,
    check_str: bool = False,
    to_unique: bool = False,
) -> List:
    def _to_unique(v):
        try:
            return list(dict.fromkeys(v))
        except Exception as e:
            logging.debug("Could not return unique value for list. Error %s", e)
            return list(v)

    if check_none and value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return _to_unique(value) if to_unique else list(value)
    if np and isinstance(value, np.ndarray):
        value = value.tolist()
        return _to_unique(value) if to_unique else value
    if check_dict and isinstance(value, Mapping):
        return list(value.items())

    if check_str and isinstance(value, str):
        parts = value.split(",")
        results = []
        for part in parts:
            part = part.strip()
            if part:
                results.append(part)
        return results
    return [value]
