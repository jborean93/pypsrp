# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import functools
import inspect
import typing as t

# FUTURE: Remove once Python 3.8 is the minimum
try:
    from typing_extensions import Literal, SupportsIndex  # type: ignore
except ImportError:  # pragma: no cover
    from typing import Literal, SupportsIndex  # type: ignore


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
    "iscoroutinefunction",
]
