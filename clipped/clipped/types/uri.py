from typing import TYPE_CHECKING, Any, Dict, Type

from clipped.compact.pydantic import PYDANTIC_VERSION, AnyUrl


if TYPE_CHECKING:
    from clipped.compact.pydantic import BaseConfig, ModelField


class Uri(AnyUrl):
    __slots__ = ()

    if PYDANTIC_VERSION.startswith("2."):
        from pydantic import GetCoreSchemaHandler
        from pydantic_core import core_schema

        @classmethod
        def __get_pydantic_core_schema__(
            cls, source: Type["Uri"], handler: GetCoreSchemaHandler
        ) -> core_schema.CoreSchema:
            from pydantic_core import core_schema

            def wrap_val(v, h):
                if isinstance(v, source):
                    return v
                if isinstance(v, Uri):
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
            if hasattr(cls, "_constraints"):
                urls_schema.update(**cls._constraints.defined_constraints)
            return core_schema.no_info_wrap_validator_function(
                wrap_val,
                schema=core_schema.url_schema(**urls_schema),
                serialization=core_schema.to_string_ser_schema(),
            )

    @classmethod
    def _validate(cls, value: Any):
        if isinstance(value, Dict):
            _value = value.get("user")
            if not _value:
                raise ValueError("Received a wrong url definition: %s", value)
            password = value.get("password")
            if password:
                _value = "{}@{}".format(_value, password)
            host = value.get("host")
            if not host:
                raise ValueError("Received a wrong url definition: %s", value)
            _value = "{}/{}".format(_value, host)
        return value

    @classmethod
    def validate(
        cls, value: Any, field: "ModelField", config: "BaseConfig"
    ) -> "AnyUrl":
        value = cls._validate(value)
        if hasattr(AnyUrl, "validate"):
            return super(Uri, cls).validate(value=value, field=field, config=config)

    def to_param(self):
        return str(self)

    @property
    def host_port(self):
        value = self.host
        if self.port:
            value = "{}:{}".format(value, self.port)
        if self.scheme:
            value = "{}://{}".format(self.scheme, value)
        return value


V1UriType = Uri
