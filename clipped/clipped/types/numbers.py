from typing import Union

from clipped.compact.pydantic import StrictFloat, StrictInt


IntOrFloat = Union[int, float]
StrictIntOrFloat = Union[StrictInt, StrictFloat, float]
