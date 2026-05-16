from collections.abc import Mapping
import datetime
from typing import List, Optional


def assert_equal_dict(
    dict1,
    dict2,
    datetime_keys: Optional[List[str]] = None,
    date_keys: Optional[List[str]] = None,
    timedelta_keys: Optional[List[str]] = None,
):
    datetime_keys = datetime_keys or []
    timedelta_keys = timedelta_keys or []
    date_keys = date_keys or []
    for k, v in dict1.items():
        if v is None:
            continue
        if isinstance(v, Mapping):
            assert_equal_dict(v, dict2[k], datetime_keys, date_keys, timedelta_keys)
        else:
            if k in datetime_keys:
                v1, v2 = v, dict2[k]
                if not isinstance(v1, datetime.datetime):
                    v1 = datetime.datetime.fromisoformat(v1)
                if not isinstance(v2, datetime.datetime):
                    v2 = datetime.datetime.fromisoformat(v2)
                assert v1 == v2
            elif k in date_keys:
                v1, v2 = v, dict2[k]
                if not isinstance(v1, datetime.date):
                    v1 = datetime.date.fromisoformat(v1)
                if not isinstance(v2, datetime.date):
                    v2 = datetime.date.fromisoformat(v2)
                assert v1 == v2
            elif k in timedelta_keys:
                v1, v2 = v, dict2[k]
                if not isinstance(v1, datetime.timedelta):
                    v1 = datetime.timedelta(seconds=v1)
                if not isinstance(v2, datetime.timedelta):
                    v2 = datetime.timedelta(seconds=v2)
                assert v1 == v2
            else:
                assert v == dict2[k]
