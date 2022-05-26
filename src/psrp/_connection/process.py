# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import logging
import subprocess
import typing as t

from psrpcore import ClientRunspacePool

from psrp._connection.connection import (
    AsyncEventCallable,
    ConnectionInfo,
    SyncEventCallable,
)
from psrp._connection.out_of_proc import (
    AsyncOutOfProcConnection,
    SyncOutOfProcConnection,
)

log = logging.getLogger(__name__)


class ProcessInfo(ConnectionInfo):
    """ConnectionInfo for a Process.

    ConnectionInfo implementation for a native process. The data is read from
    the ``stdout`` pipe of the process and the input is read to the ``stdin``
    pipe. This can be used to create a Runspace Pool on a local PowerShell
    instance or any other process that can handle the raw PSRP OutOfProc
    messages.

    When targeting Windows PowerShell (`executable='powershell'`) the arguments
    must be set to `arguments='-Version 5.1 -NoProfile -ServerMode'`. The
    `-Version` entry is cruical to not running in version 2.0 compatibility
    mode.

    When using Python 3.6 or 3.7 on Windows the ``ProactorEventLoop`` event
    loop must be used to create an asyncio subprocess. This can be done by
    settings.

    Example:
        To set the ``ProactorEventLoop`` event loop on Windows do::

            asycnio.set_event_loop_policy(asyncio.ProactorEventLoop())

    Args:
        executable: The executable to run, defaults to `pwsh`.
        arguments: A list of arguments to run, when the executable is `pwsh`
            then this defaults to `-NoProfile -NoLogo -ServerMode`.
    """

    def __init__(
        self,
        executable: str = "pwsh",
        arguments: t.Optional[t.List[str]] = None,
    ) -> None:
        self.executable = executable
        self.arguments = arguments or []
        if arguments is None:
            self.arguments = ["-NoProfile", "-NoLogo", "-ServerMode"]

    def create_sync(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
    ) -> "SyncProcessConnection":
        arguments = [self.executable]
        arguments.extend(self.arguments)
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

        return SyncProcessConnection(pool, callback, process)

    async def create_async(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> "AsyncProcessConnection":
        process = await asyncio.create_subprocess_exec(
            self.executable,
            *self.arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            limit=32_768,
        )

        return AsyncProcessConnection(pool, callback, process)


class SyncProcessConnection(SyncOutOfProcConnection):
    """Synchronous Process Connection."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
        process: subprocess.Popen,
    ) -> None:
        super().__init__(pool, callback)

        self._process = process

    def read(self) -> t.Optional[bytes]:
        data = self._process.stdout.read(self.get_fragment_size()) or None  # type: ignore[union-attr] # Will be set
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s read %s", type(self).__name__, (data or b"").decode())

        return data

    def write(
        self,
        data: bytes,
    ) -> None:
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s write %s", type(self).__name__, data.decode())

        writer: t.IO[t.Any] = self._process.stdin  # type: ignore[assignment] # Will be set
        writer.write(data)
        writer.flush()

    def stop(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            self._process.wait()


class AsyncProcessConnection(AsyncOutOfProcConnection):
    """Asynchronous Process Connection."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
        process: asyncio.subprocess.Process,
    ) -> None:
        super().__init__(pool, callback)

        self._process = process

    async def read(self) -> t.Optional[bytes]:
        data = await self._process.stdout.read(32_768) or None  # type: ignore[union-attr] # Will be set
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s read %s", type(self).__name__, (data or b"").decode())

        return data

    async def write(
        self,
        data: bytes,
    ) -> None:
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s write %s", type(self).__name__, data.decode())

        writer: asyncio.StreamWriter = self._process.stdin  # type: ignore[assignment] # Will be set
        writer.write(data)
        await writer.drain()

    async def stop(self) -> None:
        self._process.terminate()
        await self._process.wait()
