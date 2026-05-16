from typing import TYPE_CHECKING
from uuid import UUID

from clipped.compact.pydantic import PYDANTIC_VERSION
from clipped.utils.json import orjson_dumps


if TYPE_CHECKING:
    from clipped.compact.pydantic import CallableGenerator


class GenericStr(str):
    if PYDANTIC_VERSION.startswith("2."):
        from pydantic_core import core_schema

        @classmethod
        def __get_pydantic_core_schema__(
            cls, *args, **kwargs
        ) -> core_schema.CoreSchema:
            from pydantic_core import core_schema

            return core_schema.no_info_before_validator_function(
                cls.validate,
                core_schema.str_schema(strict=True),
            )

    else:

        @classmethod
        def __get_validators__(cls) -> "CallableGenerator":
            yield cls.validate

    @classmethod
    def validate(cls, value, **kwargs):
        base_types = (int, float, dict, list, tuple, set)
        if isinstance(value, base_types):
            return orjson_dumps(value)
        if isinstance(value, str):
            return value
        if isinstance(value, UUID):
            return value.hex
        if value is None:
            return value
        try:
            return str(value)
        except Exception as e:
            raise TypeError(
                f"Value must be a valid str or a value that can be casted to a str, received `{value}` instead."
            ) from e
