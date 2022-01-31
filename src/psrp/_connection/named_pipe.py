# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import datetime
import logging
import os
import os.path
import struct
import typing as t

import psutil
from psrpcore import ClientRunspacePool

from psrp._compat import asyncio_get_running_loop
from psrp._connection.connection import AsyncEventCallable, ConnectionInfo
from psrp._connection.out_of_proc import AsyncOutOfProcConnection
from psrp._exceptions import PSRPError

if os.name == "nt":
    from psrp._connection._win32 import (
        PROCESS_QUERY_LIMITED_INFORMATION,
        close_handle,
        get_process_times,
        open_process,
    )

log = logging.getLogger(__name__)

# Epoch represented by the 100s of nanoseconds since 1601-01-01.
_EPOCH_FILETIME = 116444736000000000


def _posix_get_proc_start_time_and_name(pid: int) -> t.Tuple[str, str]:
    # FUTURE: Remove dep on psutil - probably not viable
    proc = psutil.Process(pid)

    # psutil returns the time as a naive datetime but in the local time.
    # Determining the FileTime from this means it needs to be converted to
    # UTC and then getting the duration since EPOCH.
    create_time = proc.create_time()
    epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    ct = datetime.datetime.fromtimestamp(create_time).astimezone()
    td = ct.astimezone(datetime.timezone.utc) - epoch

    # Python datetime is not precise enough to contain nanoseconds so the
    # original EPOCH float value is used to calculate the 100s of ns.
    td_total = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) * 10
    td_ns = round((create_time * 10000000) - td_total)

    # Number is EPOCH in FileTime format.
    start_time_ft = _EPOCH_FILETIME + td_total + td_ns

    # .NET does `.ToString("X8").Substring(1, 8)`. Using X8 will strip any
    # leading 0's from the hex which is replicated here.
    start_time = base64.b16encode(struct.pack(">Q", start_time_ft)).decode().lstrip("0")[1:9]

    return start_time, proc.name()


def _win32_get_proc_start_time(pid: int) -> str:
    """Get the Windows Process Start Time as a FILETIME value."""
    # Was originally using psutil to get this information but the way it
    # translated the raw FILETIME to a float meant it lost precision and the
    # resulting value was wrong. This uses ctypes instead to call the relevant
    # Win32 API.
    proc = open_process(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        return str(get_process_times(proc)[0])
    finally:
        close_handle(proc)


def _win32_get_proc_name(pid: int) -> str:
    """Get the Windows Process Name as done by .NET."""
    # FUTURE: Call nt_query_system_process_id_information if psutil is dropped.
    proc = psutil.Process(pid)
    proc_exe_name = proc.name()
    proc_name, proc_ext = os.path.splitext(proc_exe_name)

    # .NET doesn't return the extension if it ends with .exe which needs to be
    # replicated here
    return proc_name if proc_ext.lower() == ".exe" else proc_exe_name


class NamedPipeInfo(ConnectionInfo):
    """ConnectionInfo for a Named Pipe.

    Creates a connection to a Named Pipe (Windows) or Unix Domain Socket
    (non-Windows) of a PowerShell process or explicit pipe name. By passing in
    an integer for the name it will be configured to connect to the PowerShell
    host pipe of that process rather than an explicit pipe/socket name.

    When using Python 3.6 or 3.7 on Windows the ``ProactorEventLoop`` event
    loop must be used to create an asyncio pipe connection. This can be done by
    setting.

    Example:
        To set the ``ProactorEventLoop`` event loop on Windows do::

            asycnio.set_event_loop_policy(asyncio.ProactorEventLoop())

    Args:
        name: The pipe name or PowerShell process id to connect to.
    """

    def __init__(
        self,
        name: t.Union[int, str],
    ) -> None:
        self.name = name

    async def create_async(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> "AsyncOutOfProcConnection":
        name = self.name

        if isinstance(name, int):
            if os.name == "nt":
                start_time = _win32_get_proc_start_time(name)
                prefix = r"\\.\pipe\PSHost"
                app_domain = "DefaultAppDomain"
                proc_name = _win32_get_proc_name(name)
            else:
                # FIXME
                # UDS have a length limit of 108 (including NULL) so the name needs to
                # be stripped if needed.
                # https://github.com/PowerShell/PowerShell/issues/16994
                start_time, proc_name = _posix_get_proc_start_time_and_name(name)
                prefix = os.path.join(os.environ.get("TMPDIR", "/tmp"), "CoreFxPipe_PSHost")
                app_domain = "None"

            name = f"{prefix}.{start_time}.{name}.{app_domain}.{proc_name}"

        log.info("Creating Named Pipe connection to '%s'", name)

        if os.name == "nt":
            loop = asyncio_get_running_loop()
            if not isinstance(loop, asyncio.ProactorEventLoop):  # type: ignore[attr-defined] # Win specific
                raise PSRPError("Windows named pipe needs to be running under the ProactorEventLoop")

            reader = asyncio.StreamReader(loop=loop)
            protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
            transport, _ = await loop.create_pipe_connection(lambda: protocol, name)
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)

            return AsyncNamedPipeConnection(pool, callback, reader, writer)

        else:
            reader, writer = await asyncio.open_unix_connection(name)  # type: ignore[attr-defined] # Unix specific
            return AsyncNamedPipeConnection(pool, callback, reader, writer)


class AsyncNamedPipeConnection(AsyncOutOfProcConnection):
    """Async Named Pipe Connection."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        super().__init__(pool, callback)
        self._reader = reader
        self._writer = writer

    async def read(self) -> t.Optional[bytes]:
        data = await self._reader.read(self.get_fragment_size())
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s read %s", type(self).__name__, (data or b"").decode())

        return data

    async def write(
        self,
        data: bytes,
    ) -> None:
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s write %s", type(self).__name__, data.decode())

        self._writer.write(data)
        await self._writer.drain()

    async def stop(self) -> None:
        log.debug("Stopping Named Pipe connection")
        self._writer.close()
        # FUTURE: Call directly once 3.7 is the minimum.
        wait_closed = getattr(self._writer, "wait_closed", None)
        if wait_closed:  # pragma: no cover
            await wait_closed()
