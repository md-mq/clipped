import functools
import logging
from typing import Optional, Tuple

from clipped.utils.versions import compare_versions


class DeprecatedWarning(DeprecationWarning):
    def __init__(self, message, details: Optional[str] = None):
        self.message = message
        self.details = details
        super(DeprecatedWarning, self).__init__(message, details)

    def __str__(self):
        return "%s\n%s" % (self.message, self.details)


class UnsupportedWarning(DeprecatedWarning):
    pass


def check_deprecation(
    current_version: Optional[str] = None,
    deprecation_version: Optional[str] = None,
    latest_version: Optional[str] = None,
) -> Tuple[bool, bool]:
    if deprecation_version is None and latest_version is not None:
        raise TypeError(
            "Cannot set `latest_version` to a value without also setting `deprecation_version`"
        )

    is_deprecated = False
    is_unsupported = False

    if current_version:
        if latest_version and compare_versions(current_version, latest_version, ">="):
            is_unsupported = True
        elif deprecation_version and compare_versions(
            current_version, deprecation_version, ">="
        ):
            is_deprecated = True
    else:
        # Automatically deprecate based if only deprecation version is provided.
        is_deprecated = True

    return is_deprecated, is_unsupported


def get_deprecation_warning_message(
    deprecation_version: str,
    latest_version: str,
    current_logic: str,
    new_logic: Optional[str] = None,
) -> str:
    message = [f"`{current_logic}` is deprecated as of `{deprecation_version}`"]
    if latest_version:
        message.append(f"it will be removed in `{latest_version}`")
    if new_logic:
        message.append(f"please use `{new_logic}` instead")
    return ", ".join(message) + "."


def warn_deprecation(
    deprecation_version: Optional[str] = None,
    latest_version: Optional[str] = None,
    current_version: Optional[str] = None,
    current_logic: Optional[str] = None,
    new_logic: Optional[str] = None,
    details: Optional[str] = None,
):
    is_deprecated, is_unsupported = check_deprecation(
        current_version=current_version,
        deprecation_version=deprecation_version,
        latest_version=latest_version,
    )

    if is_deprecated or is_unsupported:
        if is_unsupported:
            cls = UnsupportedWarning
        else:
            cls = DeprecatedWarning

        message = get_deprecation_warning_message(
            deprecation_version=deprecation_version,
            latest_version=latest_version,
            current_logic=current_logic,
            new_logic=new_logic,
        )
        logging.warning(cls(message, details))


def deprecated(
    deprecation_version: Optional[str] = None,
    latest_version: Optional[str] = None,
    current_version: Optional[str] = None,
    current_logic: Optional[str] = None,
    new_logic: Optional[str] = None,
    details: Optional[str] = None,
):
    """This decorator can be used to warn about deprecated functions.

    Example:
        # Class function
        class MyClass:
            @deprecated(deprecation_version=..., ...)
            def foo(self, a, b):
                ...

        # Function with other decorators
        @other_decorators_must_be_upper
        @deprecated(deprecation_version=..., ...)
        def my_func():
            pass
    """

    def wrapper(func):
        @functools.wraps(func)
        def _inner(*args, **kwargs):
            _current_logic = (
                current_logic
                or "The function `%(name)s` in file `%(filename)s` "
                "line number `%(line)s` is deprecated."
                % {
                    "name": func.__name__,
                    "filename": func.__code__.co_filename,
                    "line": func.__code__.co_firstlineno + 1,
                }
            )
            warn_deprecation(
                current_version=current_version,
                deprecation_version=deprecation_version,
                latest_version=latest_version,
                current_logic=_current_logic,
                new_logic=new_logic,
                details=details,
            )
            return func(*args, **kwargs)

        return _inner

    return wrapper
