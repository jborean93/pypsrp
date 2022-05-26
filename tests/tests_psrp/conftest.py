import asyncio
import os
import subprocess
import sys
import typing as t

import pytest

import psrp


def which(program: str) -> t.Optional[str]:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        exe = os.path.join(path, program)
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            return exe

    return None


PWSH_PATH = which("pwsh.exe" if os.name == "nt" else "pwsh")


@pytest.fixture(scope="function")
def psrp_proc() -> t.Iterator[psrp.ConnectionInfo]:
    if not PWSH_PATH:
        pytest.skip("Process integration test requires pwsh")

    yield psrp.ProcessInfo(executable=PWSH_PATH)


@pytest.fixture(scope="function")
def psrp_wsman() -> t.Iterator[psrp.ConnectionInfo]:
    server = os.environ.get("PYPSRP_SERVER", None)
    username = os.environ.get("PYPSRP_USERNAME", None)
    password = os.environ.get("PYPSRP_PASSWORD", None)
    auth = os.environ.get("PYPSRP_AUTH", "negotiate")
    port = int(os.environ.get("PYPSRP_PORT", "5985"))

    if not server:
        pytest.skip("WSMan integration tests requires PYPSRP_SERVER to be defined")

    yield psrp.WSManInfo(
        server=server,
        port=port,
        username=username,
        password=password,
        auth=auth,  # type: ignore[arg-type]
    )


@pytest.fixture(scope="function")
def psrp_ssh() -> t.Iterator[psrp.ConnectionInfo]:
    asyncssh = pytest.importorskip("asyncssh")

    server = os.environ.get("PYPSRP_SSH_SERVER", None)
    username = os.environ.get("PYPSRP_SSH_USERNAME", None)
    password = os.environ.get("PYPSRP_SSH_PASSWORD", None)
    key_path = os.environ.get("PYPSRP_SSH_KEY_PATH", None)

    if not server:
        pytest.skip("SSH integration tests requires PYPSRP_SSH_SERVER to be defined")

    connection_kwargs: t.Dict[str, t.Any] = {}
    if username:
        connection_kwargs["username"] = username
        connection_kwargs["password"] = password
    elif key_path:
        connection_kwargs["client_keys"] = [key_path]

    options = asyncssh.SSHClientConnectionOptions(
        known_hosts=None,
        **connection_kwargs,
    )

    yield psrp.SSHInfo(server, options=options)


@pytest.fixture(scope="function")
def psrp_win_ps_ssh() -> t.Iterator[psrp.ConnectionInfo]:
    asyncssh = pytest.importorskip("asyncssh")

    server = os.environ.get("PYPSRP_SSH_SERVER", None)
    username = os.environ.get("PYPSRP_SSH_USERNAME", None)
    password = os.environ.get("PYPSRP_SSH_PASSWORD", None)
    key_path = os.environ.get("PYPSRP_SSH_KEY_PATH", None)
    is_win_pwsh = os.environ.get("PYPSRP_SSH_IS_WINDOWS", "false").lower() == "true"

    if not server or not is_win_pwsh:
        pytest.skip("Win SSH integration tests requires PYPSRP_SSH_SERVER and PYPSRP_SSH_IS_WINDOWS to be defined")

    connection_kwargs: t.Dict[str, t.Any] = {}
    if username:
        connection_kwargs["username"] = username
        connection_kwargs["password"] = password
    elif key_path:
        connection_kwargs["client_keys"] = [key_path]

    options = asyncssh.SSHClientConnectionOptions(
        known_hosts=None,
        **connection_kwargs,
    )

    yield psrp.WinPSSSHInfo(server, options=options)


@pytest.fixture(scope="function")
def psrp_named_pipe() -> t.Iterator[psrp.ConnectionInfo]:
    if not hasattr(psrp, "NamedPipeInfo"):
        pytest.skip("Named pipe dependencies not installed")

    if not PWSH_PATH:
        pytest.skip("Process integration test requires pwsh")

    proc = subprocess.Popen(
        [PWSH_PATH, "-NoExit", "-Command", "'started'"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
    )
    # By waiting for the raw output the UDS should be available
    proc.stdout.readline()  # type: ignore[union-attr]
    try:
        yield psrp.NamedPipeInfo(proc.pid)

    finally:
        proc.terminate()


@pytest.fixture()
def event_loop():
    # Older Python versions on Windows use a event loop policy that doesn't
    # support subprocesses. Will need to use the ProactorEventLoop to test out
    # those scenarios on the older versions.
    # https://github.com/pytest-dev/pytest-asyncio/issues/227
    if sys.platform == "win32" and sys.version_info < (3, 8):
        loop = asyncio.ProactorEventLoop()
    else:
        loop = asyncio.get_event_loop_policy().get_event_loop()

    try:
        yield loop
    finally:
        loop.close()
