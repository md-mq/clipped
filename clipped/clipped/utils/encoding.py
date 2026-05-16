import base64
from typing import Optional, Union


BytesLike = Union[bytes, bytearray, memoryview]


def encode(value):
    return base64.b64encode(value.encode("utf-8")).decode("utf-8")


def decode(value):
    return base64.b64decode(value).decode("utf-8")


def urlsafe_b64decode(b64string):
    if isinstance(b64string, str):
        b64string = bytes(b64string, "utf-8")
    padded = b64string + b"=" * (4 - len(b64string) % 4)
    payload = base64.urlsafe_b64decode(padded)
    try:
        return payload.decode("utf-8")
    except Exception:  # noqa
        return payload


def as_bytes(data: BytesLike) -> bytes:
    """Coerce bytes/bytearray/memoryview to bytes; reject str."""
    if isinstance(data, str):
        raise TypeError("data must be bytes-like, not str")
    if isinstance(data, memoryview):
        return data.tobytes()
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    raise TypeError("data must be bytes-like")


def b64_data(data: Optional[BytesLike]) -> Optional[str]:
    """Base64-encode bytes-like input; return None if input is None."""
    if data is None:
        return None
    return base64.b64encode(as_bytes(data)).decode("ascii")
