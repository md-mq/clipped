import asyncio
import operator
import sys
from types import ModuleType
from unittest import TestCase
from unittest.mock import AsyncMock, patch

from clipped.utils.coroutine import run_sync


class CoroutineTest(TestCase):
    def test_run_sync_imports_to_thread(self):
        anyio = ModuleType("anyio")
        anyio.__path__ = []
        to_thread = ModuleType("anyio.to_thread")
        to_thread.run_sync = AsyncMock(return_value=3)

        with patch.dict(
            sys.modules, {"anyio": anyio, "anyio.to_thread": to_thread}
        ):
            result = asyncio.run(run_sync(operator.add, 1, 2))

        assert result == 3
        to_thread.run_sync.assert_awaited_once_with(operator.add, 1, 2)
