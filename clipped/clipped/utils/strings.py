from collections.abc import Mapping
import datetime
from decimal import Decimal
from io import StringIO
import os
import re
from typing import Any, Callable
import unicodedata

from clipped.utils.json import orjson_dumps


def strip_spaces(value: str, sep=None, join=True):
    """Cleans trailing whitespaces and replaces also multiple whitespaces with a single space."""
    value = value.strip()
    value = [v.strip() for v in value.split(sep)]
    join_sep = sep or " "
    return join_sep.join(value) if join else value


def is_protected_type(obj: Any):
    """
    A check for preserving a type as-is when passed to force_text(strings_only=True).
    """
    return isinstance(
        obj,
        (
            type(None),
            int,
            float,
            Decimal,
            datetime.datetime,
            datetime.date,
            datetime.time,
        ),
    )


def force_bytes(
    value: Any,
    encoding: str = "utf-8",
    strings_only: bool = False,
    errors: str = "strict",
):
    """
    Resolve any value to strings.

    If `strings_only` is True, skip protected objects.
    """
    # Handle the common case first for performance reasons.
    if isinstance(value, bytes):
        if encoding == "utf-8":
            return value
        return value.decode("utf-8", errors).encode(encoding, errors)
    if strings_only and is_protected_type(value):
        return value
    if isinstance(value, memoryview):
        return bytes(value)
    return value.encode(encoding, errors)


def slugify(value: str, mark_safe: Callable = None) -> str:
    """
    Convert spaces/dots to hyphens.
    Remove characters that aren't alphanumerics, underscores, or hyphens.
    Also strip leading and trailing whitespace.
    """
    value = str(value)
    value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    )
    value = re.sub(r"[^\w\.\s-]", "", value).strip()
    value = re.sub(r"[-\.\s]+", "-", value)
    return mark_safe(value) if mark_safe else value


def validate_slug(value: str) -> bool:
    return value == slugify(value)


def to_camel_case(snake_str: str):
    parts = iter(snake_str.split("_"))
    return next(parts) + "".join(i.title() for i in parts)


def to_snake_case(camel_str: str):
    regex1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
    regex2 = re.compile(r"([a-z\d])([A-Z])")
    return regex2.sub(r"\1_\2", regex1.sub(r"\1_\2", camel_str)).lower()


def to_string(v: Any):
    base_types = (int, float, Mapping, list, tuple, set)
    if isinstance(v, base_types):
        return orjson_dumps(v)
    # Important to keep null to evaluate empty values
    if v is None:
        return v
    return str(v)


def validate_file_or_buffer(data: str):
    if data and not os.path.exists(data):
        data = StringIO(data)

    return data
