from typing import TYPE_CHECKING, Any, Type

from clipped.compact.pydantic import PYDANTIC_VERSION, AnyUrl


if TYPE_CHECKING:
    from clipped.compact.pydantic import BaseConfig, ModelField


class BaseUrl(AnyUrl):
    allowed_schemes = []
    __slots__ = ()

    if PYDANTIC_VERSION.startswith("2."):
        from pydantic import GetCoreSchemaHandler
        from pydantic_core import core_schema

        @classmethod
        def __get_pydantic_core_schema__(
            cls, source: Type["BaseUrl"], handler: GetCoreSchemaHandler
        ) -> core_schema.CoreSchema:
            from pydantic_core import core_schema

            def wrap_val(v, h):
                if isinstance(v, source):
                    return v
                if isinstance(v, BaseUrl):
                    v = str(v)
                core_url = h(v)
                try:
                    instance = source.__new__(source)
                    instance._url = core_url
                except Exception as _:
                    instance = source(v)
                cls._validate(instance)
                return instance

            urls_schema = {}
            if cls.allowed_schemes:
                urls_schema = {"allowed_schemes": cls.allowed_schemes}
            if hasattr(cls, "_constraints"):
                urls_schema.update(**cls._constraints.defined_constraints)
            return core_schema.no_info_wrap_validator_function(
                wrap_val,
                schema=core_schema.url_schema(**urls_schema),
                serialization=core_schema.to_string_ser_schema(),
            )

    @classmethod
    def validate(
        cls, value: Any, field: "ModelField", config: "BaseConfig"
    ) -> "AnyUrl":
        value = cls._validate(value)
        return super().validate(value=value, field=field, config=config)
