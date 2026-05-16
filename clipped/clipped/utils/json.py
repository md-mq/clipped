import datetime
from typing import Any, Callable, Optional

import orjson


def default_timedelta(obj):
    if isinstance(obj, datetime.timedelta):
        return obj.total_seconds()
    raise TypeError


def orjson_dumps(
    obj: Any,
    *,
    option: Optional[int] = orjson.OPT_NAIVE_UTC | orjson.OPT_SERIALIZE_NUMPY,
    default: Optional[Callable[[Any], Any]] = None,
) -> str:
    default = default or default_timedelta
    return orjson.dumps(obj, default=default, option=option).decode()


orjson_loads = orjson.loads
orjson_pprint_option = (
    orjson.OPT_NAIVE_UTC
    | orjson.OPT_SERIALIZE_NUMPY
    | orjson.OPT_INDENT_2
    | orjson.OPT_SORT_KEYS
)
