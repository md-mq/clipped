import re
from typing import TYPE_CHECKING

from clipped.compact.pydantic import PYDANTIC_VERSION, StrictStr, strict_str_validator


if TYPE_CHECKING:
    from clipped.compact.pydantic import CallableGenerator


class EmailStr(StrictStr):
    USER_REGEX = re.compile(
        r"(^[-!#$%&'*+/=?^`{}|~\w]+(\.[-!#$%&'*+/=?^`{}|~\w]+)*\Z"  # dot-atom
        # quoted-string
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]'
        r'|\\[\001-\011\013\014\016-\177])*"\Z)',
        re.IGNORECASE | re.UNICODE,
    )

    DOMAIN_REGEX = re.compile(
        # domain
        r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
        r"(?:[A-Z]{2,6}|[A-Z0-9-]{2,})\Z"
        # literal form, ipv4 address (SMTP 4.1.3)
        r"|^\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)"
        r"(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]\Z",
        re.IGNORECASE | re.UNICODE,
    )

    DOMAIN_WHITELIST = ("localhost",)

    ERROR_MESSAGE = "Not a valid email address."

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
                core_schema.str_schema(strict=True),
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

        if not value or "@" not in value:
            raise ValueError(cls.ERROR_MESSAGE)

        user_part, domain_part = value.rsplit("@", 1)

        if not cls.USER_REGEX.match(user_part):
            raise ValueError(cls.ERROR_MESSAGE)

        if domain_part not in cls.DOMAIN_WHITELIST:
            if not cls.DOMAIN_REGEX.match(domain_part):
                try:
                    domain_part = domain_part.encode("idna").decode("ascii")
                except UnicodeError:
                    pass
                else:
                    if cls.DOMAIN_REGEX.match(domain_part):
                        return value
                raise ValueError(cls.ERROR_MESSAGE)

        return value
