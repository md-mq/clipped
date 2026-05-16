from contextlib import contextmanager
import sys
from typing import Callable, List, Tuple


NEWLINES = ("\n", "\r", "\r\n")
INDENT_CHAR = " "
INDENT_STRINGS = []
STDOUT = sys.stdout.write
STDERR = sys.stderr.write


def _indent(depth: int = 0, quote: str = ""):
    """Indent util function, compute new indent_string"""
    if depth > 0:
        indent_string = "".join((str(quote), (INDENT_CHAR * (depth - len(quote)))))
    else:
        indent_string = "".join((("\x08" * (-1 * (depth - len(quote)))), str(quote)))

    if indent_string:
        INDENT_STRINGS.append(indent_string)


@contextmanager
def _indent_context():
    """Indentation context manager."""
    try:
        yield
    finally:
        # Remove indent
        INDENT_STRINGS.pop()


def indent(depth: int = 4, quote: str = ""):
    """Indentation manager, return an indentation context manager."""
    _indent(depth, quote)
    return _indent_context()


def split_many(string: str, delimiters: Tuple[str, ...]) -> List[str]:
    """Behaves str.split but supports tuples of delimiters."""
    delimiters = tuple(delimiters)
    if len(delimiters) < 1:
        return [string]
    final_delimiter = delimiters[0]
    for i in delimiters[1:]:
        string = string.replace(i, final_delimiter)
    return string.split(final_delimiter)


def puts(s: str = "", newline: bool = True, stream: Callable = STDOUT):
    """Prints given string to stdout."""
    if newline:
        s = split_many(s, NEWLINES)
        s = map(str, s)
        indentation = "".join(INDENT_STRINGS)

        s = (str("\n" + indentation)).join(s)

    outputs = "".join(("".join(INDENT_STRINGS), str(s), "\n" if newline else ""))
    stream(outputs)
