import asyncio
from contextlib import asynccontextmanager, contextmanager
import logging
import os
import signal
import threading
from typing import Generator, Optional


_logger = logging.getLogger("clipped.workers")


def get_pool_workers() -> int:
    return min(32, (os.cpu_count() or 1) + 4)


def get_core_workers(per_core: int, max_workers: Optional[int] = None) -> int:
    count = int(per_core) * (os.cpu_count() or 1) + 1
    return max(count, int(max_workers)) if max_workers else count


@contextmanager
def sync_exit_context() -> Generator:
    exit_event = threading.Event()

    def _exit_handler(*args, **kwargs):
        _logger.info("Keyboard Interrupt received, exiting pool.")
        exit_event.set()

    original = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, _exit_handler)
        yield exit_event
    except SystemExit:
        pass
    finally:
        signal.signal(signal.SIGINT, original)


@asynccontextmanager
async def async_exit_context():
    exit_event = asyncio.Event()

    def _exit_handler(*args, **kwargs):
        _logger.info("Keyboard Interrupt received, exiting pool.")
        exit_event.set()

    original = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, _exit_handler)
        yield exit_event
    except SystemExit:
        pass
    finally:
        signal.signal(signal.SIGINT, original)


def get_wait(current: int, max_interval: Optional[int] = None) -> float:
    max_interval = max_interval or 6
    max_index = max_interval - 1

    if current >= max_index:
        current = max_index
    intervals = [0.25 * 2**i for i in range(max_interval)]
    return intervals[current]
