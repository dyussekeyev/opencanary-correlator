"""Console log list: bounded storage and the async logging bridge."""

from __future__ import annotations

import logging
from typing import Any

from opencanary_correlator.audit import RedisLogHandler
from opencanary_correlator.constants import KEY_LOGS


async def test_push_log_keeps_the_newest_lines(store: Any) -> None:
    for index in range(5):
        await store.push_log(f"line-{index}", max_entries=3)

    assert await store.lrange(KEY_LOGS) == ["line-4", "line-3", "line-2"]


async def test_redis_log_handler_drains_records_to_the_store(store: Any) -> None:
    handler = RedisLogHandler(store, queue_size=10, max_entries=10)
    logger = logging.getLogger("opencanary_correlator.tests.console")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        await handler.start()
        logger.info("incident alert line")
        await handler.stop()
    finally:
        logger.removeHandler(handler)

    assert handler.dropped == 0
    assert await store.lrange(KEY_LOGS) == ["incident alert line"]
