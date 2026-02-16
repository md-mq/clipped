from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Type, TypeVar

from clipped.utils.json import orjson_dumps, orjson_loads

T = TypeVar("T")
from pydantic.version import VERSION as PYDANTIC_VERSION

if PYDANTIC_VERSION.startswith("2."):
    from pydantic import AnyUrl, BaseConfig
    from pydantic import BaseModel as _BaseModel
    from pydantic import ByteSize, ConfigDict, Field
    from pydantic import ValidationInfo as ModelField
    from pydantic import (
        FiniteFloat,
        FutureDate,
        Json,
        NegativeFloat,
        NegativeInt,
        NonNegativeFloat,
        NonNegativeInt,
        NonPositiveFloat,
        NonPositiveInt,
        PastDate,
        PaymentCardNumber,
        PositiveFloat,
        PositiveInt,
        PrivateAttr,
        RootModel,
        SecretBytes,
        SecretStr,
        StrictBool,
        StrictBytes,
        StrictFloat,
        StrictInt,
        StrictStr,
        ValidationError,
        ValidationInfo,
        constr,
        create_model,
        field_validator,
        model_validator,
        validate_call,
    )
    from pydantic.deprecated.parse import Protocol, load_str_bytes
    from pydantic.deprecated.tools import NameFactory
    from pydantic.v1.datetime_parse import parse_date, parse_datetime, parse_duration
    from pydantic.v1.validators import strict_str_validator, uuid_validator

    validation_before = {"mode": "before"}
    validation_after = {"mode": "after"}
    validation_always = {}

    NAME_REGEX = r"^[-a-zA-Z0-9_]+\z"
    FULLY_QUALIFIED_NAME_REGEX = r"^[-a-zA-Z0-9_]+(:[-a-zA-Z0-9_.]+)?\z"

    def patter_constr(pattern):
        return constr(pattern=pattern)

    class PydanticConfig:
        populate_by_name = True
        validate_assignment = True
        arbitrary_types_allowed = True
        use_enum_values = True
        extra = "forbid"
        ser_json_timedelta = "float"
        protected_namespaces = ()

    class PydanticAllowConfig(PydanticConfig):
        extra = "allow"

    class PydanticAlwaysConfig(PydanticConfig):
        revalidate_instances = True

    def model_rebuild(model, **localns: Any) -> None:
        return model.model_rebuild(force=True, _types_namespace=localns)

    class PydanticTypeError(TypeError):
        pass

    class PydanticValueError(ValueError):
        pass

    def parse_obj_as(type_: Type[T], obj: Any, **type_forwarding) -> T:
        from pydantic import TypeAdapter

        adapter = TypeAdapter(type_)
        return adapter.validate_python(obj)

    class BaseModel(_BaseModel):
        def __init__(self, **data):
            if (
                hasattr(self, "_USE_DISCRIMINATOR")
                and hasattr(self, "_IDENTIFIER")
                and self._USE_DISCRIMINATOR
            ):
                data["kind"] = data.pop("kind", self._IDENTIFIER)
            super().__init__(**data)

        def model_dump(self, *args, **kwargs) -> Dict:
            # Handle custom fields
            exclude_fields = getattr(self, "_CUSTOM_DUMP_FIELDS", None)
            data = super().model_dump(*args, exclude=exclude_fields, **kwargs)
            if hasattr(self, "_dump_obj"):
                data = self._dump_obj(data)
            return data

        def dict(self, *args, **kwargs) -> Dict:
            return self.model_dump(*args, **kwargs)

    if TYPE_CHECKING:
        from pydantic.typing import CallableGenerator
else:
    from pydantic import AnyUrl, BaseConfig
    from pydantic import BaseModel as _BaseModel
    from pydantic import (
        ByteSize,
        Field,
        FiniteFloat,
        FutureDate,
        Json,
        NegativeFloat,
        NegativeInt,
        NonNegativeFloat,
        NonNegativeInt,
        NonPositiveFloat,
        NonPositiveInt,
        PastDate,
        PaymentCardNumber,
        PositiveFloat,
        PositiveInt,
        PrivateAttr,
        PydanticTypeError,
        PydanticValueError,
        SecretBytes,
        SecretStr,
        StrictBool,
        StrictBytes,
        StrictFloat,
        StrictInt,
        StrictStr,
        ValidationError,
        constr,
        create_model,
    )
    from pydantic import root_validator as model_validator
    from pydantic import validate_arguments as validate_call
    from pydantic import validator as field_validator
    from pydantic.datetime_parse import parse_date, parse_datetime, parse_duration
    from pydantic.fields import ModelField
    from pydantic.parse import Protocol, load_str_bytes
    from pydantic.tools import NameFactory, _get_parsing_type
    from pydantic.validators import strict_str_validator, uuid_validator

    validation_before = {"pre": True}
    validation_after = {"pre": False}
    validation_always = {"always": True}

    NAME_REGEX = r"^[-a-zA-Z0-9_]+\Z"
    FULLY_QUALIFIED_NAME_REGEX = r"^[-a-zA-Z0-9_]+(:[-a-zA-Z0-9_.]+)?\Z"

    def patter_constr(pattern):
        return constr(regex=pattern)

    def parse_obj_as(type_: Type[T], obj: Any, **type_forwarding) -> T:
        model_type = _get_parsing_type(
            type_,
        )
        model_type.update_forward_refs(**type_forwarding)
        return model_type(__root__=obj).__root__

    class PydanticConfig:
        allow_population_by_field_name = True
        validate_assignment = True
        arbitrary_types_allowed = True
        use_enum_values = True
        extra = "forbid"
        json_dumps: Callable[..., str] = orjson_dumps
        json_loads = orjson_loads

    class PydanticAllowConfig(PydanticConfig):
        extra = "allow"

    def model_rebuild(model, **localns: Any) -> None:
        return model.update_forward_refs(**localns)

    class RootModel(_BaseModel):
        pass

    class BaseModel(_BaseModel):
        def __init__(self, **data):
            if (
                hasattr(self, "_USE_DISCRIMINATOR")
                and hasattr(self, "_IDENTIFIER")
                and self._USE_DISCRIMINATOR
            ):
                data["kind"] = data.pop("kind", self._IDENTIFIER)
            super().__init__(**data)

        @property
        def model_fields(self):
            return self.__fields__

        @property
        def model_fields_set(self):
            return self.__fields_set__

        @classmethod
        def model_construct(cls, *args, **data):
            return cls.construct(*args, **data)

        def model_copy(self):
            return self.copy()

        def dict(self, *args, **kwargs) -> Dict:
            data = super().dict(*args, **kwargs)
            if hasattr(self, "_dump_obj"):
                data = self._dump_obj(data)
            return data

        def model_dump(self, *args, **kwargs) -> Dict:
            return self.dict(*args, **kwargs)

        def model_dump_json(self, *args, **kwargs) -> str:
            return self.json(*args, **kwargs)

        @classmethod
        def model_validate(cls, *args, **data) -> "Model":
            return cls.parse_obj(*args, **data)

        @classmethod
        def model_rebuild(cls, **localns: Any) -> None:
            return cls.update_forward_refs(**localns)

    if TYPE_CHECKING:
        from pydantic.typing import CallableGenerator
