import re
from typing import Optional, Union


# Quantities Kubernetes and the converters below read the same, up to sub-byte
# rounding of fractional memory; the converters also accept forms Kubernetes
# reads differently, e.g. memory 1m (milli vs mega).
_NUMBER = r"(\d+(\.\d*)?|\.\d+)"
_CPU_VALUE = re.compile(_NUMBER + r"[mun]?", re.ASCII)
_MEMORY_VALUE = re.compile(_NUMBER + r"([KMGTPE]i|[kMGTPE])?", re.ASCII)


def is_cpu_value(value: str) -> bool:
    """Whether Kubernetes and to_cpu_value agree on a cpu string, e.g. 500m."""
    return bool(_CPU_VALUE.fullmatch(value))


def is_memory_value(value: str) -> bool:
    """Whether Kubernetes and to_memory_bytes agree on a memory string."""
    return bool(_MEMORY_VALUE.fullmatch(value))


def _sanitize_value(value: Union[str, int, float]) -> Union[int, float]:
    fvalue = float(value)
    ivalue = int(fvalue)
    return ivalue if ivalue == fvalue else fvalue


def to_cpu_value(cpu_definition: Union[str, int, float]) -> float:
    try:
        return float(cpu_definition)
    except (ValueError, TypeError):
        pass

    cpu_definition = cpu_definition.lower()  # type: ignore[union-attr]
    cpu_unit = cpu_definition[-1]
    cpu_value = cpu_definition[:-1]
    if cpu_unit == "m":
        cpu = _sanitize_value(cpu_value) / 1000
    elif cpu_unit == "u":
        cpu = _sanitize_value(cpu_value) / 1000**2
    elif cpu_unit == "n":
        cpu = _sanitize_value(cpu_value) / 1000**3
    else:
        cpu = cpu_definition  # type: ignore[assignment]
    return _sanitize_value(cpu)


def to_memory_bytes(mem_definition: Union[str, int, float]) -> int:
    try:
        return int(float(mem_definition))
    except (ValueError, TypeError):
        pass

    def _get_value(unit, value, multiplier):
        if unit in multiplier.keys():
            return _sanitize_value(value) * multiplier.get(unit, 1)

    fixed_point_unit_multiplier = {
        "k": 1000,
        "m": 1000**2,
        "g": 1000**3,
        "t": 1000**4,
        "p": 1000**5,
        "e": 1000**6,
    }

    power_two_unit_multiplier = {
        "ki": 1024,
        "mi": 1024**2,
        "gi": 1024**3,
        "ti": 1024**4,
        "pi": 1024**5,
        "ei": 1024**6,
    }

    mem_definition = mem_definition.lower()  # type: ignore[union-attr]

    mem_unit = mem_definition[-2:]
    mem_value = mem_definition[:-2]
    memory = _get_value(mem_unit, mem_value, power_two_unit_multiplier)
    if memory is not None:
        return memory

    mem_unit = mem_definition[-1:]
    mem_value = mem_definition[:-1]
    memory = _get_value(mem_unit, mem_value, fixed_point_unit_multiplier)
    if memory is not None:
        return memory

    return 0


def to_unit_memory(
    number: Union[int, float],
    precision: int = 2,
    use_i: bool = False,
    use_space: bool = True,
) -> str:
    """Creates a string representation of memory size given `number`."""
    suffix = "i" if use_i else ""
    space = " " if use_space else ""
    kb = 1024

    number /= kb

    if number < 100:
        return "{}{}K{}".format(round(number, precision), space, suffix)

    number /= kb
    if number < 300:
        return "{}{}M{}".format(round(number, precision), space, suffix)

    number /= kb
    if number < 900:
        return "{}{}G{}".format(round(number, precision), space, suffix)

    number /= kb
    if number < 900:
        return "{}{}T{}".format(round(number, precision), space, suffix)

    number /= kb
    if number < 900:
        return "{}{}P{}".format(round(number, precision), space, suffix)

    number /= kb
    return "{}{}E{}".format(round(number, precision), space, suffix)


def number_percentage_format(
    x, precision: Optional[int] = None, use_comma: bool = False
) -> str:
    if precision is None:
        return x
    eps = 0.000000001
    comma = "," if use_comma else ""
    num_format = (
        "{{0:{}.0f}}".format(comma)
        if abs(int(x) - x) < eps
        else "{{0:{}.{}f}}".format(comma, precision)
    )
    return num_format.format(x)


def to_percentage(
    number, rounding: int = 2, precision: Optional[int] = None, use_comma: bool = False
) -> str:
    """Creates a percentage string representation from the given `number`. The
    number is multiplied by 100 before adding a '%' character.

    Raises `ValueError` if `number` cannot be converted to a number.
    """
    number = float(number) * 10**2
    number_as_int = int(number)
    rounded = round(number, rounding)
    value = (
        number_as_int
        if number_as_int == rounded
        else number_percentage_format(rounded, precision, use_comma)
    )

    return "{}%".format(value)


def format_sizeof(num: Union[int, float], suffix: str = "B") -> str:
    """
    Print in human friendly format
    """
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, "Yi", suffix)
