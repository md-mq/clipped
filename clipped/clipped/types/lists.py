from typing import TYPE_CHECKING

from clipped.compact.pydantic import PYDANTIC_VERSION
from clipped.utils.lists import to_list


if TYPE_CHECKING:
    from clipped.compact.pydantic import CallableGenerator


class ListStr(list):
    if PYDANTIC_VERSION.startswith("2."):
        from pydantic_core import core_schema

        @classmethod
        def __get_pydantic_core_schema__(
            cls, *args, **kwargs
        ) -> core_schema.CoreSchema:
            from pydantic_core import core_schema

            return core_schema.no_info_before_validator_function(
                cls.validate,
                core_schema.list_schema(),
            )

    else:

        @classmethod
        def __get_validators__(cls) -> "CallableGenerator":
            yield cls.validate

    @classmethod
    def validate(cls, value, **kwargs):
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return to_list(value, check_none=True, check_str=True)
        if not value:
            return value

        raise TypeError(f"Value must be a valid List, received `{value}` instead.")
