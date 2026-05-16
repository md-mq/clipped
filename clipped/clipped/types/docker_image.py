from typing import TYPE_CHECKING

from clipped.compact.pydantic import PYDANTIC_VERSION
from clipped.config.constants import PARAM_REGEX


if TYPE_CHECKING:
    from clipped.compact.pydantic import CallableGenerator


def validate_image(image, allow_none=False):
    if not image:
        if allow_none:
            return
        else:
            raise ValueError("Image is required")

    if isinstance(image, dict):  # Backwards compatibility
        image = image.get("name")
    if not isinstance(image, str):
        raise TypeError("Image value should be a string")
    param = PARAM_REGEX.search(image)
    if param:
        return image
    if " " in image:
        raise ValueError("Invalid docker image `{}`".format(image))
    _image = image.strip("https://")
    _image = _image.strip("http://")
    tagged_image = _image.split(":")
    if len(tagged_image) > 3:
        raise ValueError("Invalid docker image `{}`".format(image))
    if len(tagged_image) == 3 and (
        "/" not in tagged_image[1] or tagged_image[1].startswith("/")
    ):
        raise ValueError("Invalid docker image `{}`".format(image))

    return image


class ImageStr(str):
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
        return validate_image(value)
