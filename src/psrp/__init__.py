# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing as t

from psrp._async import (
    AsyncCommandMetaPipeline,
    AsyncPowerShell,
    AsyncPSDataCollection,
    AsyncPSDataStreams,
    AsyncRunspacePool,
)
from psrp._client import async_invoke_ps, copy_file, fetch_file, invoke_ps
from psrp._connection.connection import (
    AsyncConnection,
    AsyncEventCallable,
    ConnectionInfo,
    EnumerationPipelineResult,
    EnumerationRunspaceResult,
    OutputBufferingMode,
    SyncConnection,
    SyncEventCallable,
)
from psrp._connection.out_of_proc import (
    AsyncOutOfProcConnection,
    SyncOutOfProcConnection,
)
from psrp._connection.process import ProcessInfo
from psrp._connection.wsman import WSManInfo
from psrp._exceptions import (
    PipelineFailed,
    PipelineStopped,
    PSRPAuthenticationError,
    PSRPError,
    RunspaceNotAvailable,
)
from psrp._host import PSHost, PSHostRawUI, PSHostUI
from psrp._sync import (
    SyncCommandMetaPipeline,
    SyncPowerShell,
    SyncPSDataCollection,
    SyncPSDataStreams,
    SyncRunspacePool,
)

try:
    from psrp._connection.named_pipe import NamedPipeInfo
except Exception:  # pragma: no cover

    class NamedPipeInfo(ConnectionInfo):  # type: ignore[no-redef]

        def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
            raise Exception("Attempted to use NamedPipeInfo but 'pypsrp[named_pipe]' is not installed.")


try:
    from psrp._connection.ssh import SSHInfo, WinPSSSHInfo
except Exception:  # pragma: no cover

    class SSHInfo(ConnectionInfo):  # type: ignore[no-redef]

        def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
            raise Exception("Attempted to use SSHInfo but 'pypsrp[ssh]' is not installed.")

    class WinPSSSHInfo(ConnectionInfo):  # type: ignore[no-redef]

        def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
            raise Exception("Attempted to use WinPSSSHInfo but 'pypsrp[ssh]' is not installed.")


__all__ = [
    "AsyncCommandMetaPipeline",
    "AsyncConnection",
    "AsyncEventCallable",
    "AsyncOutOfProcConnection",
    "AsyncPowerShell",
    "AsyncPSDataCollection",
    "AsyncPSDataStreams",
    "AsyncRunspacePool",
    "ConnectionInfo",
    "EnumerationPipelineResult",
    "EnumerationRunspaceResult",
    "NamedPipeInfo",
    "OutputBufferingMode",
    "PipelineFailed",
    "PipelineStopped",
    "ProcessInfo",
    "PSHost",
    "PSHostRawUI",
    "PSHostUI",
    "PSRPAuthenticationError",
    "PSRPError",
    "RunspaceNotAvailable",
    "SSHInfo",
    "SyncCommandMetaPipeline",
    "SyncConnection",
    "SyncEventCallable",
    "SyncOutOfProcConnection",
    "SyncPowerShell",
    "SyncPSDataCollection",
    "SyncPSDataStreams",
    "SyncRunspacePool",
    "WinPSSSHInfo",
    "WSManInfo",
    "async_invoke_ps",
    "copy_file",
    "fetch_file",
    "invoke_ps",
]
