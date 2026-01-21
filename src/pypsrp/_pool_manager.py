# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import contextvars
import functools
import types
import typing as t

import requests.adapters
from requests.packages.urllib3.util.retry import Retry

T = t.TypeVar("T")


class NewConnectionDisabled(Exception):
    """Raised when new connections is being made but has been disabled in the current context."""


class DisableNewConnectionsContext:
    """Context manager to disable new connections from being created."""

    __slots__ = "_contextvar_token"

    _contextvar: t.ClassVar[contextvars.ContextVar] = contextvars.ContextVar("NewConnectionContext")
    _contextvar_token: contextvars.Token

    @classmethod
    def current(cls) -> DisableNewConnectionsContext | None:
        """Returns the current context or None if not set."""
        try:
            return cls._contextvar.get()
        except LookupError:
            return None

    def __enter__(self) -> DisableNewConnectionsContext:
        self._contextvar_token = self.__class__._contextvar.set(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool | None:
        self.__class__._contextvar.reset(self._contextvar_token)
        del self._contextvar_token

        return None


def _wrap(
    func: t.Callable[..., T],
    *,
    before: t.Callable[[], None] | None = None,
    after: t.Callable[[T], None] | None = None,
) -> t.Callable[..., T]:
    """Wraps a function with before and after callables."""

    @functools.wraps(func)
    def wrapper(*args: t.Any, **kwargs: t.Any) -> T:
        if before:
            before()

        res = func(*args, **kwargs)

        if after:
            after(res)

        return res

    return wrapper


def _raise_if_connections_disabled():
    if DisableNewConnectionsContext.current() is not None:
        raise NewConnectionDisabled()


def _create_new_connection_with_failure(connection):
    connection.connect = _wrap(connection.connect, before=_raise_if_connections_disabled)


def _create_connection_pool(pool):
    # This is called in the urllib3 pool when a new connection is needed. We
    # wrap it so we can wrap the connect method when a new connection is
    # created.
    pool.ConnectionCls = _wrap(pool.ConnectionCls, after=_create_new_connection_with_failure)


def create_request_adapter(  # type: ignore[no-any-unimported]  # requests does not have typing stubs for urllib3
    max_retries: Retry,
) -> requests.adapters.HTTPAdapter:
    """Creates a HTTPAdapter with support for disabling new connections via context."""
    adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)

    # pool_classes_by_scheme stores the urllib3 pool types used when creating
    # the connection pool for http/https. We wrap the __init__ method so we can
    # inject our custom ConnectionCls that wraps the connect method when
    # created.
    pool_classes = adapter.poolmanager.pool_classes_by_scheme
    for scheme, pool_cls in list(pool_classes.items()):
        pool_classes[scheme] = _wrap(pool_cls, after=_create_connection_pool)

    return adapter
