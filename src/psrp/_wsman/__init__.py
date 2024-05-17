# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

from ._auth import (
    AuthProvider,
    BasicAuth,
    NegotiateAuth,
    WSManCertificateAuth,
    WSManCredSSPAuth,
    WSManEncryptionProvider,
)
from ._client import (
    NAMESPACES,
    CommandEvent,
    CommandResponseEvent,
    CommandState,
    ConnectEvent,
    ConnectResponseEvent,
    CreateEvent,
    CreateResponseEvent,
    DeleteEvent,
    DeleteResponseEvent,
    DisconnectEvent,
    DisconnectResponseEvent,
    EnumerateEvent,
    EnumerateResponseEvent,
    FaultAddressingEvent,
    FaultEvent,
    GetEvent,
    GetResponseEvent,
    OptionSet,
    PullEvent,
    PullResponseEvent,
    PutEvent,
    PutResponseEvent,
    ReceiveEvent,
    ReceiveResponseEvent,
    ReconnectEvent,
    ReconnectResponseEvent,
    SelectorSet,
    SendEvent,
    SendResponseEvent,
    SignalCode,
    SignalEvent,
    SignalResponseEvent,
    WSManAction,
    WSManClient,
    WSManEvent,
)
from ._exceptions import (
    ErrorCancelled,
    OperationAborted,
    OperationTimedOut,
    ServiceStreamDisconnected,
    ShellDisconnected,
    UnexpectedSelectors,
    WSManAuthenticationError,
    WSManFault,
    WSManFaultCode,
    WSManHTTPError,
)
from ._http import AsyncWSManHTTP, SyncWSManHTTP
from ._http_proxy import HTTPProxy
from ._proxy import Proxy
from ._tls import create_ssl_context
from ._winrs import CommandInfo, WinRS

try:
    from ._socks import SOCKS5Proxy
except ImportError:

    class SOCKS5Proxy(Proxy):  # type: ignore[no-redef]
        def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
            raise Exception("Attempted to use SocksProxy but 'pypsrp[socks]' is not installed.")


__all__ = [
    "NAMESPACES",
    "AsyncWSManHTTP",
    "CommandEvent",
    "CommandInfo",
    "CommandResponseEvent",
    "CommandState",
    "ConnectEvent",
    "ConnectResponseEvent",
    "CreateEvent",
    "CreateResponseEvent",
    "DeleteEvent",
    "DeleteResponseEvent",
    "DisconnectEvent",
    "DisconnectResponseEvent",
    "EnumerateEvent",
    "EnumerateResponseEvent",
    "ErrorCancelled",
    "FaultAddressingEvent",
    "FaultEvent",
    "GetEvent",
    "GetResponseEvent",
    "HTTPProxy",
    "OperationAborted",
    "OperationTimedOut",
    "OptionSet",
    "Proxy",
    "PullEvent",
    "PullResponseEvent",
    "PutEvent",
    "PutResponseEvent",
    "ReceiveEvent",
    "ReceiveResponseEvent",
    "ReconnectEvent",
    "ReconnectResponseEvent",
    "SelectorSet",
    "SendEvent",
    "SendResponseEvent",
    "ServiceStreamDisconnected",
    "ShellDisconnected",
    "SignalCode",
    "SignalEvent",
    "SignalResponseEvent",
    "SOCKS5Proxy",
    "SyncWSManHTTP",
    "UnexpectedSelectors",
    "WSManAction",
    "AuthProvider",
    "WSManAuthenticationError",
    "BasicAuth",
    "WSManCertificateAuth",
    "WSManClient",
    "WSManConnectionData",
    "WSManCredSSPAuth",
    "WSManEncryptionProvider",
    "WSManEvent",
    "WSManFault",
    "WSManFaultCode",
    "WSManHTTPError",
    "NegotiateAuth",
    "WinRS",
    "create_ssl_context",
]
