# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import functools
import inspect
import typing as t

# FUTURE: Remove once Python 3.8 is the minimum
try:
    from typing_extensions import Literal, SupportsIndex  # type: ignore
except ImportError:  # pragma: no cover
    from typing import Literal, SupportsIndex  # type: ignore


T = t.TypeVar("T")


def asyncio_create_task(coro: t.Coroutine[t.Any, t.Any, T]) -> "asyncio.Task[T]":
    """asyncio.create_task shim for Python 3.6"""
    # FUTURE: Remove once Python 3.7 is the minimum
    create_task = getattr(asyncio, "create_task", None)
    if create_task:  # pragma: no cover
        return create_task(coro)  # type: ignore [no-any-return]

    else:  # pragma: no cover
        loop = asyncio.get_event_loop()
        task = loop.create_task(coro)

        return task


def asyncio_get_running_loop() -> asyncio.AbstractEventLoop:
    """asyncio.get_running_loop shim for Python 3.6"""
    # FUTURE: Remove once Python 3.7 is the minimum
    get_running_loop = getattr(asyncio, "get_running_loop", None)
    if get_running_loop:
        return t.cast(asyncio.AbstractEventLoop, get_running_loop())

    else:
        return asyncio.get_event_loop()


def iscoroutinefunction(
    value: t.Any,
) -> bool:
    """Checks if a function is a coroutine even when wrapped by functools."""
    # FUTURE: Remove once Python 3.8 is the minimum
    while isinstance(value, functools.partial):
        value = value.func

    return inspect.iscoroutinefunction(value)


__all__ = [
    "Literal",
    "SupportsIndex",
    "asyncio_create_task",
    "iscoroutinefunction",
]
