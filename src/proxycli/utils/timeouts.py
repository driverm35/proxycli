from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import TypeVar

T = TypeVar("T")


def call_with_timeout(func: Callable[[], T], timeout: float) -> T:
    if timeout <= 0:
        raise TimeoutError("таймаут должен быть больше нуля")
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="proxycli")
    future = pool.submit(func)
    try:
        return future.result(timeout=timeout)
    except FuturesTimeout as exc:
        raise TimeoutError(f"превышено время ожидания {timeout:.1f} с") from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
