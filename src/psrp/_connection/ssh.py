# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import logging
import typing as t

import asyncssh
from psrpcore import ClientRunspacePool

from psrp._connection.connection import AsyncEventCallable, ConnectionInfo
from psrp._connection.out_of_proc import AsyncOutOfProcConnection

log = logging.getLogger(__name__)

# To get SSH working against Windows PowerShell (5.1) a special stub must be
# invoked that properly handles the input data from the stdin of the process as
# .NET Framework has a problem with how sshd on Windows works. This stub will
# spawn the actual Windows PowerShell server target and pass just pass in the
# data as is and output the responses back over SSH making it work. See the
# following for more information around why .NET Framework needs such a thing:
# https://gist.github.com/jborean93/7d4cb107fa06251b080fa10ec844893e
WIN_PWSH_STUB = r"""
[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'

Add-Type -Namespace PSSSH -Name NativeMethods -MemberDefinition @'
[DllImport("Kernel32.dll", EntryPoint = "GetStdHandle", SetLastError = true)]
private static extern IntPtr GetStdHandleNative(
    int nStdHandle);

public static Microsoft.Win32.SafeHandles.SafeFileHandle GetStdHandle(int handleId)
{
    IntPtr handle = GetStdHandleNative(handleId);
    if (handle == (IntPtr)(-1)) {
        throw new System.ComponentModel.Win32Exception();
    }

    return new Microsoft.Win32.SafeHandles.SafeFileHandle(handle, false);
}
'@

$stdin = [PSSSH.NativeMethods]::GetStdHandle(-10)
$stdinFS = [System.IO.FileStream]::new($stdin, 'Read')

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo.FileName = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$proc.StartInfo.Arguments = '-Version 5.1 -NoLogo -ServerMode'
$proc.StartInfo.CreateNoWindow = $true
$proc.StartInfo.RedirectStandardInput = $true
$proc.StartInfo.UseShellExecute = $false
$null = $proc.Start()
try {
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $stdinSR = [System.IO.StreamReader]::new($stdinFS, $utf8)

    while ($true) {
        $line = $stdinSR.ReadLine()
        $proc.StandardInput.WriteLine($line)
        $proc.StandardInput.Flush()

        if ($line.StartsWith("<CloseAck PSGuid='00000000-0000-0000-0000-000000000000' />")) {
            break
        }
    }
}
finally {
    $proc | Stop-Process -Force
}
"""


class SSHInfo(ConnectionInfo):
    """ConnectionInfo for an SSH connection.

    ConnectionInfo implementation for an SSH connection. The data is exchanged
    either over a subsystem channel or a remote process' stdio pipes. By
    the connection is set to connect to the `powershell` subsystem which is how
    the actual PowerShell client works for Windows. A custom subsystem can be
    defined to match whatever is in the target's `sshd_config`. As well as this
    the connection can use an explicit executable and arguments to spawn and is
    used as for the communication.

    For example if the target host does not have a subsystem defined it can
    start a connection to an explicit `pwsh` process with:

        >>> info = psrp.SSHInfo(
        ...     "server",
        ...     executable="pwsh",
        ...     arguments=["-NoLogo", "-SSHServerMode"]
        ... )

    To target Windows PowerShell use :class:`WinPSSSHInfo` instead as it
    requires a special setup process to get working.

    Note:
        There is no synchronous implementation for SSH, this will only work for
        asynchronous Runspace Pools.

    Args:
        hostname: The host to connect to.
        port: The port to connect with, defaults to 22.
        subsystem: The target subsystem to create, defaults to `powershell`.
        executable: Start this executable instead of connecting to a subsystem.
        arguments: Use these arguments when starting the executable.
        options: AsyncSSH options to use when creating the connection. This
            provides fine control over how the connection is made.
    """

    def __init__(
        self,
        hostname: str,
        port: int = 22,
        subsystem: str = "powershell",
        executable: t.Optional[str] = None,
        arguments: t.Optional[t.List[str]] = None,
        options: t.Optional[asyncssh.SSHClientConnectionOptions] = None,
    ) -> None:
        self.hostname = hostname
        self.port = port
        self.subsystem = subsystem
        self.executable = executable
        self.arguments = arguments or []
        self.options = options

    async def create_async(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> "AsyncSSHConnection":
        log.info("Creating async SSH connection for %s:%s", self.hostname, self.port)
        ssh = await asyncssh.connect(
            self.hostname,
            port=self.port,
            options=self.options,
        )

        cmd: t.Union[str, t.Tuple[()]] = ()
        if self.executable:
            cmd = " ".join([self.executable] + self.arguments)
            subsystem = None

        else:
            subsystem = self.subsystem

        channel, session = await ssh.create_session(
            _ClientSession,
            command=cmd,
            subsystem=subsystem,
            encoding=None,
        )

        return AsyncSSHConnection(
            pool,
            callback,
            ssh,
            channel,
            session,  # type: ignore[arg-type] # It is this type based on the factory passed in
        )


class WinPSSSHInfo(SSHInfo):
    """ConnectionInfo for a Windows PowerShell SSH connection.

    ConnectionInfo implementation for an SSH connection that targets Windows
    PowerShell rather than PowerShell (Core). This uses the same mechanism as
    :class:`SSHInfo` but uses a custom PowerShell script as the executable and
    arguments to get Windows PowerShell to spawn.

    Note:
        There is no synchronous implementation for SSH, this will only work for
        asynchronous Runspace Pools.

    Args:
        hostname: The host to connect to.
        port: The port to connect with, defaults to 22.
        options: AsyncSSH options to use when creating the connection. This
            provides fine control over how the connection is made.
    """

    def __init__(
        self,
        hostname: str,
        port: int = 22,
        options: t.Optional[asyncssh.SSHClientConnectionOptions] = None,
    ) -> None:
        enc_script = base64.b64encode(WIN_PWSH_STUB.encode("utf-16-le")).decode()
        super().__init__(
            hostname,
            port=port,
            executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=["-NoProfile", "-NoLogo", "-EncodedCommand", enc_script],
            options=options,
        )


class _ClientSession(asyncssh.SSHClientSession):
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[t.Optional[bytes]] = asyncio.Queue()

    def data_received(
        self,
        data: bytes,
        datatype: t.Optional[int],
    ) -> None:
        # Special edge case with WinPSSSHInfo as -EncodedCommand always outputs this
        if datatype == 1 and data == b"#< CLIXML\r\n":
            return

        self.incoming.put_nowait(data)


class AsyncSSHConnection(AsyncOutOfProcConnection):
    """Async SSH Connection."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
        ssh: asyncssh.SSHClientConnection,
        channel: asyncssh.SSHClientChannel,
        session: _ClientSession,
    ) -> None:
        super().__init__(pool, callback)

        self._ssh = ssh
        self._channel = channel
        self._session = session

    async def read(self) -> t.Optional[bytes]:
        data = await self._session.incoming.get()
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s read %s", type(self).__name__, (data or b"").decode())

        return data

    async def write(
        self,
        data: bytes,
    ) -> None:
        if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
            log.debug("%s write %s", type(self).__name__, data.decode())
        self._channel.write(data)

    async def stop(self) -> None:
        log.debug("Stopping ssh connection")
        self._channel.kill()
        self._ssh.close()
        self._session.incoming.put_nowait(None)
