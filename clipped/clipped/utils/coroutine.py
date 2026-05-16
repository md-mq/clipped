import asyncio
from functools import partial, wraps
from typing import Callable


def coroutine(f: Callable):
    """https://github.com/pallets/click/issues/85#issuecomment-503464628"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


async def run_sync(func: Callable, *args, **kwargs):
    import anyio

    if kwargs:  # pragma: no cover
        # run_sync doesn't accept 'kwargs', so bind them in here
        func = partial(func, **kwargs)
    return await anyio.to_thread.run_sync(func, *args)
