from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Union

from clipped.compact.pydantic import (
    PYDANTIC_VERSION,
    StrictFloat,
    StrictInt,
    StrictStr,
    strict_str_validator,
)
from clipped.config.constants import PARAM_REGEX


if TYPE_CHECKING:
    from clipped.compact.pydantic import CallableGenerator


class RefField(StrictStr):
    if PYDANTIC_VERSION.startswith("2."):
        from pydantic_core import core_schema

        @classmethod
        def __get_pydantic_core_schema__(
            cls, *args, **kwargs
        ) -> core_schema.CoreSchema:
            from pydantic_core import core_schema

            def _validate(value):
                value = strict_str_validator(value)
                return cls.validate(value)

            return core_schema.no_info_after_validator_function(
                _validate,
                core_schema.str_schema(),
            )

    else:

        @classmethod
        def __get_validators__(cls) -> "CallableGenerator":
            yield strict_str_validator
            yield cls.validate

    @classmethod
    def validate(cls, value, **kwargs):
        if not isinstance(value, str):
            return value

        param = PARAM_REGEX.search(value)
        if not param:  # TODO: Fix error message
            raise ValueError(f"Value must be a reference, received `{value}` instead.")
        return value


BoolOrRef = Union[bool, RefField]
IntOrRef = Union[StrictInt, RefField]
StrictFloatOrRef = Union[StrictFloat, RefField]
FloatOrRef = Union[float, RefField]
DatetimeOrRef = Union[datetime, RefField]
TimeDeltaOrRef = Union[timedelta, RefField]
