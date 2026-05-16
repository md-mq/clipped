import math
from typing import Any, Dict


try:
    import numpy as np
except ImportError:
    np = None


def is_np_numerical_value_unsupported(value):
    return value is None or math.isnan(value) or math.isinf(value)


def sanitize_np_types(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if is_np_numerical_value_unsupported(value):
        return None
    if isinstance(value, (int, float, complex, type(None))):
        return value
    if np and np.isnan(value):
        return None
    if np and isinstance(value, np.integer):
        return int(value)
    if np and isinstance(value, np.floating):
        return float(value)
    return value


def to_np(value: Any) -> Any:
    if hasattr(value, "detach"):  # Torch detach handling
        value = value.detach()
    if hasattr(value, "numpy"):  # Torch numpy handling
        value = value.numpy()
    if isinstance(value, np.ndarray):
        return value
    if np.isscalar(value):
        return np.array([value])


def calculate_scale_factor(tensor: Any):
    converted = tensor.numpy() if not isinstance(tensor, np.ndarray) else tensor
    return 1 if converted.dtype == np.uint8 else 255


def sanitize_dict(s: Dict) -> Dict:
    return {k: sanitize_np_types(v) for k, v in s.items()}
