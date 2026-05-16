import logging
from typing import Any, Callable, List, Optional, Type, TypeVar

from clipped.compact.pydantic import (
    NameFactory,
    Protocol,
    PydanticTypeError,
    PydanticValueError,
    ValidationError,
    load_str_bytes,
    parse_obj_as,
)
from clipped.config.constants import NO_VALUE_FOUND
from clipped.config.exceptions import SchemaError
from clipped.decorators.memoization import memoize
from clipped.utils.json import orjson_loads


_logger = logging.getLogger("clipped.parser")

T = TypeVar("T")


class ConfigParser:
    _SCHEMA_EXCEPTION = SchemaError

    @staticmethod
    @memoize
    def is_loadable(type_: Any):
        from clipped import types

        return type_ not in types.NON_LOADABLE

    @staticmethod
    @memoize
    def type_mapping():
        from clipped import types

        return types.MAPPING

    @staticmethod
    @memoize
    def type_forwarding():
        from clipped import types

        return types.FORWARDING

    @classmethod
    def parse_obj_as(
        cls, type_: Type[T], obj: Any, *, type_name: Optional[NameFactory] = None
    ) -> T:
        return parse_obj_as(type_, obj, **cls.type_forwarding())

    @classmethod
    def parse_raw_as(
        cls,
        type_: Type[T],
        b: Any,
        *,
        content_type: str = None,
        encoding: str = "utf8",
        proto: Protocol = None,
        allow_pickle: bool = False,
        json_loads: Callable[[str], Any] = orjson_loads,
        type_name: Optional[NameFactory] = None,
    ) -> T:
        obj = load_str_bytes(
            b,
            proto=proto,
            content_type=content_type,
            encoding=encoding,
            allow_pickle=allow_pickle,
            json_loads=json_loads,
        )
        return cls.parse_obj_as(type_, obj, type_name=type_name)

    @classmethod
    def _check_options(cls, key, value, options):
        if options and value not in options:
            raise cls._SCHEMA_EXCEPTION(
                "The value `{}` provided for key `{}` "
                "is not one of the possible values.".format(value, key)
            )

    @classmethod
    def _get_typed_value(
        cls,
        key,
        value,
        target_type,
        is_optional=False,
        default=None,
        options=None,
    ):
        """
        Return the value corresponding to the key converted to the given type.

        Args:
            key: the dict key.
            target_type: The type we expect the variable or key to be in.
            is_optional: To raise an error if key was not found.
            default: default value if is_optional is True.
            options: list/tuple if provided, the value must be one of these values.

        Returns:
            The corresponding value of the key converted.
        """
        if value is None or value == NO_VALUE_FOUND:
            if not is_optional:
                raise cls._SCHEMA_EXCEPTION(
                    "No value was provided for the non optional key `{}`.".format(key)
                )
            return default

        try:
            if cls.is_loadable(target_type) and isinstance(value, str):
                new_value = cls.parse_raw_as(
                    target_type, value, json_loads=orjson_loads
                )
            else:
                new_value = cls.parse_obj_as(target_type, value)
            cls._check_options(key=key, value=new_value, options=options)
            return new_value
        except (
            TypeError,
            ValueError,
            ValidationError,
            PydanticTypeError,
            PydanticValueError,
        ):
            raise cls._SCHEMA_EXCEPTION(
                "Cannot convert value `{}` (key: `{}`) to `{}`".format(
                    value, key, target_type
                )
            )

    @classmethod
    def parse(cls, target_type: Any) -> Callable:
        """
        Get the value corresponding to the key and converts it to `target_type` using `type_convert`.

        Args
            target_type: the type to parse the values to.
            type_convert: the converter to use to cast the values.
            base_types: Optional list of types to convert from if the type does not correspond to target type.

        Returns:
             `Callback`: A parser for specific for the target_type.
        """

        def _parse(
            key: Any,
            value: Any,
            is_list: bool = False,
            is_optional: bool = False,
            default: Any = None,
            options: List[Type] = None,
        ):
            """
            Get the value corresponding to the key and converts it to `target_type` using `type_convert`.

            Args
                key: the dict key.
                value: the value to parse.
                is_list: If this is one element or a list of elements.
                is_optional: To raise an error if key was not found.
                default: default value if is_optional is True.
                options: list/tuple if provided, the value must be one of these values.

            Returns:
                 `target_type`: value corresponding to the key.
            """
            _target_type = cls.type_mapping().get(target_type, target_type)

            def _get_name():
                if hasattr(_target_type, "_name"):
                    return _target_type._name
                if hasattr(_target_type, "__name__"):
                    return _target_type.__name__
                return "Any"

            if is_list:
                # _target_type = (
                #     _target_type if isinstance(_target_type, str) else _get_name()
                # )
                # _target_type = f"List[{_target_type}]"
                _target_type = List[_target_type]

            return cls._get_typed_value(
                key=key,
                value=value,
                target_type=_target_type,
                is_optional=is_optional,
                default=default,
                options=options,
            )

        return _parse
