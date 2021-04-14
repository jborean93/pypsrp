# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import contextlib
import functools
import inspect
import typing


# TODO: Remove once Python 3.6 is dropped.
if hasattr(contextlib, 'asynccontextmanager'):
    asynccontextmanager = contextlib.asynccontextmanager

else:
    from async_generator import asynccontextmanager


def asyncio_create_task(
        coro: typing.Awaitable,
) -> asyncio.Task:
    """ Replicates asyncio.create_task for Python 3.6+. """
    # TODO: Remove once Python 3.6 is dropped.
    if hasattr(asyncio, 'create_task'):
        return asyncio.create_task(coro)

    else:
        # This "should" return the running loop in Python 3.6.
        loop = asyncio.get_event_loop()
        return loop.create_task(coro)


def iscoroutinefunction(
        value: typing.Any,
) -> bool:
    """ Checks if a function is a coroutine even when wrapped by functools. """
    # TODO: Remove once Python 3.8 is minimum
    while isinstance(value, functools.partial):
        value = value.func

    return inspect.iscoroutinefunction(value)
