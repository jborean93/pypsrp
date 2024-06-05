# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

from . import events, exceptions
from ._auth import (
    AuthProvider,
    BasicAuth,
    NegotiateAuth,
    WSManCertificateAuth,
    WSManCredSSPAuth,
    WSManEncryptionProvider,
)
from ._client import WinRSClient, WSManClient
from ._http import AsyncWSManHTTP, SyncWSManHTTP
from ._http_proxy import HTTPProxy
from ._protocol import (
    NAMESPACES,
    CommandState,
    OptionSet,
    SelectorSet,
    SignalCode,
    WSManAction,
)
from ._proxy import Proxy
from ._tls import create_ssl_context

try:
    from ._socks import SOCKS5Proxy
except ImportError:

    class SOCKS5Proxy(Proxy):  # type: ignore[no-redef]
        def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
            raise Exception("Attempted to use SocksProxy but 'pypsrp[socks]' is not installed.")


__all__ = [
    "NAMESPACES",
    "AsyncWSManHTTP",
    "AuthProvider",
    "BasicAuth",
    "CommandState",
    "HTTPProxy",
    "NegotiateAuth",
    "OptionSet",
    "Proxy",
    "SelectorSet",
    "SignalCode",
    "SOCKS5Proxy",
    "SyncWSManHTTP",
    "WinRSClient",
    "WSManAction",
    "WSManCertificateAuth",
    "WSManClient",
    "WSManCredSSPAuth",
    "WSManEncryptionProvider",
    "create_ssl_context",
    "events",
    "exceptions",
]
