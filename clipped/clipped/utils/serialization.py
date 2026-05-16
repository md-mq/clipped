# ruff: noqa: E731
from typing import Any

from clipped.compact.pydantic import (
    parse_date,
    parse_datetime,
    parse_duration,
    uuid_validator,
)


date_serialize = lambda x: x.isoformat()
date_deserialize = lambda x: parse_date(x)

datetime_serialize = lambda x: x.isoformat() if x else x
datetime_deserialize = lambda x: parse_datetime(x) if x else x

timedelta_serialize = lambda x: x.total_seconds() if x else x
timedelta_deserialize = lambda x: parse_duration(x) if x else x


class _DummyField:
    type_ = None


_dummy_field: Any = _DummyField()

uuid_serialize = lambda x: x.hex if x else x
uuid_deserialize = lambda x: uuid_validator(x, _dummy_field) if x else x
