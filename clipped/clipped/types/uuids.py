from typing import TYPE_CHECKING
from uuid import UUID

from clipped.compact.pydantic import PYDANTIC_VERSION, StrictStr


if TYPE_CHECKING:
    from clipped.compact.pydantic import CallableGenerator


class UUIDStr(StrictStr):
    if PYDANTIC_VERSION.startswith("2."):
        from pydantic_core import core_schema

        @classmethod
        def __get_pydantic_core_schema__(
            cls, *args, **kwargs
        ) -> core_schema.CoreSchema:
            from pydantic_core import core_schema

            return core_schema.no_info_before_validator_function(
                cls.validate,
                core_schema.str_schema(),
            )

    else:

        @classmethod
        def __get_validators__(cls) -> "CallableGenerator":
            yield cls.validate

    @classmethod
    def validate(cls, value):
        if isinstance(value, str):
            return UUID(value).hex
        if isinstance(value, UUID):
            return value.hex
        if not value:
            return value

        raise TypeError(f"Value must be a valid UUID, received `{value}` instead.")
