# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import contextlib
import hashlib
import logging
import os
import pathlib
import pkgutil
import shutil
import tempfile
import typing as t

from psrp._async import AsyncPowerShell, AsyncPSDataStreams, AsyncRunspacePool
from psrp._connection.connection import ConnectionInfo
from psrp._exceptions import PSRPError
from psrp._host import PSHost
from psrp._sync import (
    SyncPowerShell,
    SyncPSDataCollection,
    SyncPSDataStreams,
    SyncRunspacePool,
)

log = logging.getLogger(__name__)


LocalPath = t.TypeVar("LocalPath", bytes, str, pathlib.Path)


def copy_file(
    connection: t.Union[ConnectionInfo, SyncRunspacePool],
    src: LocalPath,
    dest: str,
    *,
    expand_variables: bool = False,
) -> str:
    """Copies a file to the remote connection.

    Copies a local file to the remote PowerShell connection. The file transfer
    will not be as fast as a transfer over SMB or SSH due to the extra overhead
    that the PSRP layer adds but it will work on whatever connection type is
    used.

    By default the src and dest paths will be used as is without any environment
    variable expansions. By setting `expand_variables=True` the src will be
    expanded using the Python syntax `$ENV_VAR/path` whereas the dst path will
    be expanded using the CMD/Windows syntax `%ENV_VAR%/path`.

    Args:
        connection: The PSRP connection info to use for the copy or an opened
            synchronous Runspace Pool. A connection info object will open a new
            pool and close once the copy has completed whereas a Runspace Pool
            object will use what has already been opened and share the same
            state.
        src: The local path to copy from. This can be a string, bytes, or a
            pathlib Path object.
        dest: The destination path to copy the file to. This must be a string
            and relative paths are resolved from the current location of the
            connection which is based on the connection type.
        expand_variables: Expand the src and dest paths for any variables.

    Returns:
        str: The absolute path to the remote destination that the local file
        was copied to.
    """
    src_path: pathlib.Path
    if isinstance(src, bytes):
        src_path = pathlib.Path(src.decode("utf-8", errors="surrogatepass"))

    elif isinstance(src, str):
        src_path = pathlib.Path(src)

    else:
        src_path = src

    if expand_variables:
        src_path = pathlib.Path(os.path.expanduser(os.path.expandvars(src_path)))

    def read_buffer(path: pathlib.Path, buffer_size: int) -> t.Iterator[bytes]:
        sha1 = hashlib.sha1()

        with open(path, mode="rb") as fd:
            for data in iter((lambda: fd.read(buffer_size)), b""):
                sha1.update(data)
                yield data

        yield sha1.hexdigest().encode("utf-8")

    with _sync_connection_or_rp(connection) as rp:
        ps = SyncPowerShell(rp)
        ps.add_script(_get_pwsh_script("copy.ps1"))
        ps.add_parameters(
            Path=dest,
            ExpandVariables=expand_variables,
        )

        if log.isEnabledFor(logging.DEBUG):
            ps.add_parameter("Verbose", True)
        ps.streams.verbose.data_added += lambda m: log.debug(m.Message)

        output = ps.invoke(
            input_data=read_buffer(src_path, rp.max_payload_size),
            buffer_input=False,
        )

    return t.cast(str, output[0])


def fetch_file(
    connection: t.Union[ConnectionInfo, SyncRunspacePool],
    src: str,
    dest: LocalPath,
    *,
    expand_variables: bool = False,
) -> LocalPath:
    """Fetches a file from the remote connection.

    Fetches a file from the remote PowerShell connection and copies it to the
    local path specified. The file transfer will not be as fast as a transfer
    over SMB or SSH due to the extra overhead that the PSRP layer adds but it
    will work on whatever connection type is used.

    By default the src and dest paths will be used as is without any environment
    variable expansions. By setting `expand_variables=True` the src will be
    expanded using the CMD/Windows syntax `%ENV_VAR%/path` whereas the dst path
    will be expanded using the Python syntax `$ENV_VAR/path`.

    Args:
        connection: The PSRP connection info to use for the fetch or an opened
            synchronous Runspace Pool. A connection info object will open a new
            pool and close once the copy has completed whereas a Runspace Pool
            object will use what has already been opened and share the same
            state.
        src: The renmove path to copy from. This must be a string and relative
            paths are resolved from the current location of the connection
            which is based on the connection type.
        dest: The destination path to copy the file to. This can either be a
            str, byte string, or pathlib Path object.
        expand_variables: Expand the src and dest paths for any variables.

    Returns:
        bytes, str, pathlib.Path: The absolute path to the local destination
        that the remote file was fetch to. The type is dependent on the type
        specified by the dest argument.
    """
    dest_path: pathlib.Path
    if isinstance(dest, bytes):
        dest_path = pathlib.Path(dest.decode("utf-8", errors="surrogatepass"))

    elif isinstance(dest, str):
        dest_path = pathlib.Path(dest)
    else:
        dest_path = dest

    if expand_variables:
        dest_path = pathlib.Path(os.path.expanduser(os.path.expandvars(dest_path)))

    with tempfile.TemporaryDirectory() as temp_dir, _sync_connection_or_rp(connection) as rp:
        ps = SyncPowerShell(rp)
        ps.add_script(_get_pwsh_script("fetch.ps1"))
        ps.add_parameters(
            Path=src,
            BufferSize=rp.max_payload_size,
            ExpandVariables=expand_variables,
        )

        if log.isEnabledFor(logging.DEBUG):
            ps.add_parameter("Verbose", True)
        ps.streams.verbose.data_added += lambda m: log.debug(m.Message)

        out = SyncPSDataCollection[t.Any]()
        temp_file = os.path.join(temp_dir, "psrp-fetch-temp")
        with open(temp_file, mode="wb") as temp_fd:
            sha1 = hashlib.sha1()

            def on_data(data: t.Union[bytes, str]) -> None:
                if isinstance(data, bytes):
                    sha1.update(data)  # type: ignore[has-type] # Nested func is problematic
                    temp_fd.write(data)  # type: ignore[has-type] # Ditto above

            out.data_added += on_data
            ps.invoke(output_stream=out)

        expected_file_hash = out[-1]
        actual_file_hash = sha1.hexdigest()
        if actual_file_hash != expected_file_hash:
            raise PSRPError(f"Invalid hash of retrieved file - {actual_file_hash} != {expected_file_hash}")

        shutil.move(temp_file, dest_path)

    dest_path = dest_path.absolute()
    if isinstance(dest, pathlib.Path):
        return dest_path

    else:
        str_dest = str(dest_path)
        if isinstance(dest, bytes):
            return str_dest.encode("utf-8", errors="surrogatepass")

        else:
            return str_dest


async def async_invoke_ps(
    connection: t.Union[ConnectionInfo, AsyncRunspacePool],
    script: str,
    *,
    arguments: t.Optional[t.Union[t.List[t.Any], t.Dict[str, t.Any]]] = None,
    input_data: t.Optional[t.Union[t.AsyncIterable[t.Any], t.Iterable[t.Any]]] = None,
    cwd: t.Optional[str] = None,
    environment: t.Optional[t.Dict[str, str]] = None,
    host: t.Optional[PSHost] = None,
    expand_variables: bool = False,
) -> t.Tuple[t.List[t.Any], AsyncPSDataStreams, bool]:
    """Invokes a PowerShell script asynchronously.

    Invokes a PowerShell script asynchronously on a new connection or on the
    Runspace Pool provided. This is a high level wrapper over
    :class:`psrp.AsyncPowerShell` designed to make it easier to invoke a script.

    The current working directory can be set to a file system path on the
    target or any other PowerShell provider path. If the cwd is a file system
    path both the PSProvider path will be set as well as the current process
    working directory. Relying on the current process working directory is not
    thread safe and can impact other running pipelines on the same pool if
    used concurrently.

    By default no host is used for the Runspace Pool or Pipeline being run.
    This means any host interaction, like `Write-Host`, will be a no-op or
    failure if a prompt is expected. Either specify your own custom host
    through the host kwarg or pass in a Runspace Pool as the connection which
    was opened with a PSHost if you wish to use host interaction in your script.

    Args:
        connection: The connection info object or opened asynchronous Runspace
            Pool to use for the script.
        script: The PowerShell script to invoke.
        arguments: Either a list of arguments passed positionally or a dict of
            arguments passed by name to the script.
        input_data: Any data to send as input to the script.
        cwd: The PowerShell location to set as the current working directory.
        environment: Any environment variables to set in the script.
        host: The PSHost to use with the pipeline.
        expand_variables: Will expand the `cwd` for environment variables. Env
            vars need to be defined in the format `%ENV_VAR%`.

    Returns:
        Tuple[List[Any], AsyncPSDataStreams, bool]: Returns a tuple with the 3
        values:
            List[Any]: The output from the pipeline
            AsyncPSDataStreams: All the PS data streams except the output stream
            bool: Whether the pipeline reported an error or not.
    """
    if isinstance(connection, ConnectionInfo):
        rp = AsyncRunspacePool(connection)
        await rp.open()
        close_rp = True
    else:
        rp = connection
        close_rp = False

    try:
        ps = AsyncPowerShell(rp, host=host)
        _setup_invoke_pipeline(
            ps,
            script,
            cwd=cwd,
            environment=environment,
            arguments=arguments,
            expand_variables=expand_variables,
        )

        output = await ps.invoke(input_data=input_data)

    finally:
        if close_rp:
            await rp.close()

    return output, ps.streams, ps.had_errors


def invoke_ps(
    connection: t.Union[ConnectionInfo, SyncRunspacePool],
    script: str,
    *,
    arguments: t.Optional[t.Union[t.List[t.Any], t.Dict[str, t.Any]]] = None,
    input_data: t.Optional[t.Iterable[t.Any]] = None,
    cwd: t.Optional[str] = None,
    environment: t.Optional[t.Dict[str, str]] = None,
    host: t.Optional[PSHost] = None,
    expand_variables: bool = False,
) -> t.Tuple[t.List[t.Any], SyncPSDataStreams, bool]:
    """Invokes a PowerShell script synchronously.

    Invokes a PowerShell script synchronously on a new connection or on the
    Runspace Pool provided. This is a high level wrapper over
    :class:`psrp.SyncPowerShell` designed to make it easier to invoke a script.

    The current working directory can be set to a file system path on the
    target or any other PowerShell provider path. If the cwd is a file system
    path both the PSProvider path will be set as well as the current process
    working directory. Relying on the current process working directory is not
    thread safe and can impact other running pipelines on the same pool if
    used concurrently.

    By default no host is used for the Runspace Pool or Pipeline being run.
    This means any host interaction, like `Write-Host`, will be a no-op or
    failure if a prompt is expected. Either specify your own custom host
    through the host kwarg or pass in a Runspace Pool as the connection which
    was opened with a PSHost if you wish to use host interaction in your script.

    Args:
        connection: The connection info object or opened synchronous Runspace
            Pool to use for the script.
        script: The PowerShell script to invoke.
        arguments: Either a list of arguments passed positionally or a dict of
            arguments passed by name to the script.
        input_data: Any data to send as input to the script.
        cwd: The PowerShell location to set as the current working directory.
        environment: Any environment variables to set in the script.
        host: The PSHost to use with the pipeline.
        expand_variables: Will expand the `cwd` for environment variables. Env
            vars need to be defined in the format `%ENV_VAR%`.

    Returns:
        Tuple[List[Any], SyncPSDataStreams, bool]: Returns a tuple with the 3
        values:
            List[Any]: The output from the pipeline
            SyncPSDataStreams: All the PS data streams except the output stream
            bool: Whether the pipeline reported an error or not.
    """
    with _sync_connection_or_rp(connection) as rp:
        ps = SyncPowerShell(rp, host=host)
        _setup_invoke_pipeline(
            ps,
            script,
            cwd=cwd,
            environment=environment,
            arguments=arguments,
            expand_variables=expand_variables,
        )

        output = ps.invoke(input_data=input_data)

    return output, ps.streams, ps.had_errors


def _setup_invoke_pipeline(
    ps: t.Union[AsyncPowerShell, SyncPowerShell],
    script: str,
    cwd: t.Optional[str] = None,
    environment: t.Optional[t.Dict[str, str]] = None,
    arguments: t.Optional[t.Union[t.List[t.Any], t.Dict[str, t.Any]]] = None,
    expand_variables: bool = False,
) -> None:
    if cwd:
        log.debug(f"Setting current working directory to '{cwd}'")
        ps.add_script(
            """
            [CmdletBinding()]
            param (
                [string]$Path,
                [switch]$Expand
            )

            if ($Expand) {
                $Path = [System.Environment]::ExpandEnvironmentVariables($Path)
            }

            $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            if (-not $item) {
                throw "Working Directory path is not valid."
            }

            Set-Location -LiteralPath $item.PSPath
            if ($item.PSProvider.Name -eq "FileSystem") {
                [System.Environment]::CurrentDirectory = $item.FullName
            }
            """
        ).add_parameters(Path=cwd, Expand=expand_variables)
        ps.add_statement()

    if environment:
        for env_key, env_value in environment.items():
            log.debug(f"Setting env var '{env_key}={env_value}'")
            ps.add_command("New-Item").add_parameters(
                Path="env:",
                Name=env_key,
                Value=env_value,
                Force=True,
            ).add_command("Out-Null").add_statement()

    log.debug(f"Invoking script: {script}")
    ps.add_script(script)
    if arguments:
        if isinstance(arguments, dict):
            ps.add_parameters(**arguments)
        else:
            for arg in arguments:
                ps.add_argument(arg)


def _get_pwsh_script(
    name: str,
) -> str:
    """Get the contents of a known PowerShell script.

    Get the contents of a PowerShell script inside the ``psrp._pwsh`` package.
    Will also strip out any empty lines and comments to reduce the data we send
    across as much as possible.

    Args:
        name: The script filename inside ``psrp._pwsh`` to get.

    Returns:
        The scripts contents.
    """
    script = (pkgutil.get_data("psrp._pwsh", name) or b"").decode("utf-8")

    block_comment = False
    new_lines = []
    for line in script.splitlines():

        line = line.strip()
        if block_comment:
            block_comment = not line.endswith("#>")
        elif line.startswith("<#"):
            block_comment = True
        elif line and not line.startswith("#"):
            new_lines.append(line)

    return "\n".join(new_lines)


@contextlib.contextmanager
def _sync_connection_or_rp(
    connection: t.Union[ConnectionInfo, SyncRunspacePool],
) -> t.Generator[SyncRunspacePool, None, None]:
    if isinstance(connection, ConnectionInfo):
        rp = SyncRunspacePool(connection)
        rp.open()
        close_rp = True
    else:
        rp = connection
        close_rp = False

    try:
        yield rp

    finally:
        if close_rp:
            rp.close()
