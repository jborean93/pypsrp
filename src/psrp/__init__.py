# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

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
    PSRPError,
    RunspaceNotAvailable,
    WSManAuthenticationError,
    WSManFault,
    WSManFaultCode,
    WSManHTTPError,
)
from psrp._host import PSHost, PSHostRawUI, PSHostUI
from psrp._sync import (
    SyncCommandMetaPipeline,
    SyncPowerShell,
    SyncPSDataCollection,
    SyncPSDataStreams,
    SyncRunspacePool,
)

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
    "OutputBufferingMode",
    "PipelineFailed",
    "PipelineStopped",
    "ProcessInfo",
    "PSHost",
    "PSHostRawUI",
    "PSHostUI",
    "PSRPError",
    "RunspaceNotAvailable",
    "SyncCommandMetaPipeline",
    "SyncConnection",
    "SyncEventCallable",
    "SyncOutOfProcConnection",
    "SyncPowerShell",
    "SyncPSDataCollection",
    "SyncPSDataStreams",
    "SyncRunspacePool",
    "WSManAuthenticationError",
    "WSManFault",
    "WSManFaultCode",
    "WSManHTTPError",
    "WSManInfo",
    "async_invoke_ps",
    "copy_file",
    "fetch_file",
    "invoke_ps",
]


try:
    from psrp._connection.named_pipe import NamedPipeInfo
except Exception:  # pragma: no cover
    log.exception("Optional Named Pipe connection failed to import")
else:  # pragma: no cover
    __all__.append("NamedPipeInfo")


try:
    from psrp._connection.ssh import SSHInfo, WinPSSSHInfo
except Exception:  # pragma: no cover
    log.exception("Optional SSH connection failed to import")
else:  # pragma: no cover
    __all__.extend(["SSHInfo", "WinPSSSHInfo"])
