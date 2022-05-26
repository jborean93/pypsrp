import hashlib
import logging
import os
import pathlib
import shutil
import typing as t

import pytest
import pytest_mock

import psrp


@pytest.fixture(scope="function")
def local_tmp(tmpdir: pathlib.Path) -> t.Iterator[pathlib.Path]:
    # psrp-tmp “tést’ dir - 🎵
    dirname = "psrp-tmp \u201Ct\u00E9st\u2019 dir - \U0001F3B5"
    if os.name == "nt":
        dirname += " - \ud83c"

    else:
        dirname += " - \udcef"

    local_tmpdir = tmpdir / dirname
    local_tmpdir.mkdir()

    try:
        yield pathlib.Path(local_tmpdir)
    finally:
        shutil.rmtree(local_tmpdir)


@pytest.fixture(scope="function")
def remote_tmp(conn: str, request: pytest.FixtureRequest) -> t.Iterator[pathlib.Path]:
    connection = request.getfixturevalue(f"psrp_{conn}")
    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)

        # Remote a tempdir with a complex prefix. I tried to get Linux to
        # create a dir with invalid UTF-8 bytes.
        ps.add_script(
            """
            $tmpDir = [System.IO.Path]::GetTempPath()

            $eAcute = [Char]0x00E9  # é
            $leftSmartDoubleQuote = [Char]0x201C  # “
            $rightSmartSingleQuote = [Char]0x2019  # ’
            $musicalNote = [Char]::ConvertFromUtf32(0x0001F3B5)  # 🎵
            $prefix = "psrp-tmp {0}t{1}st{2} dir - {3}" -f (
                $leftSmartDoubleQuote,
                $eAcute,
                $rightSmartSingleQuote,
                $musicalNote
            )

            $IsWindows = if (Get-Variable -Name IsWindows -ValueOnly -ErrorActionSilentlyContinue) {
                $IsWindows
            }
            else {
                $true
            }
            if ($IsWindows) {
                $prefix += " - $($musicalNote[0])"
            }

            $folderName = "$prefix - $([Guid]::NewGuid())"
            $global:tmpPath = Join-Path $tmpDir $folderName
            New-Item -Path $global:tmpPath -ItemType Directory -Force | Out-Null
            $global:tmpPath
            """
        )
        out = ps.invoke()

        try:
            yield pathlib.Path(out[0])
        finally:
            ps = psrp.SyncPowerShell(rp)
            ps.add_script("Remove-Item -LiteralPath $global:tmpPath -Force -Recurse")
            ps.invoke()


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_copy_empty_file(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
    caplog: pytest.LogCaptureFixture,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    src = local_tmp / "test.txt"
    with open(src, mode="wb") as fd:
        pass

    dst = remote_tmp / "test.txt"
    with caplog.at_level(logging.DEBUG, "psrp._client"):
        actual_path = psrp.copy_file(connection, str(src), str(dst))
    assert isinstance(actual_path, str)

    hash_info = psrp.invoke_ps(connection, "Get-FileHash -LiteralPath $args[0]", arguments=[actual_path])[0][0]
    actual_hash = hash_info.Hash

    assert actual_hash == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

    assert len(caplog.messages) == 3
    assert caplog.messages[0].startswith("Creating remote temp file at '")
    assert caplog.messages[1].startswith("Copy expected hash ")
    assert caplog.messages[2].startswith("Moving copied file to final path")


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_copy_file(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    src = local_tmp / "test.txt"
    with open(src, mode="wb") as fd:
        fd.write(b"Testing")

    dst = remote_tmp / "test.txt"
    actual_path = psrp.copy_file(connection, str(src).encode("utf-8", errors="surrogatepass"), str(dst))
    assert isinstance(actual_path, str)

    hash_info = psrp.invoke_ps(connection, "Get-FileHash -LiteralPath $args[0]", arguments=[actual_path])[0][0]
    actual_hash = hash_info.Hash

    assert actual_hash == "E806A291CFC3E61F83B98D344EE57E3E8933CCCECE4FB45E1481F1F560E70EB1"


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_copy_large_file(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    src = local_tmp / "test.txt"
    with open(src, mode="wb") as fd:
        fd.write(b"data\n" * 1_048_576)

    dst = remote_tmp / "test.txt"
    actual_path = psrp.copy_file(connection, src, str(dst))
    assert isinstance(actual_path, str)

    hash_info = psrp.invoke_ps(connection, "Get-FileHash -LiteralPath $args[0]", arguments=[actual_path])[0][0]
    actual_hash = hash_info.Hash

    assert actual_hash == "53B5B621B6736B270F5024ED6F6912FE4197E0FA4215BF31333B11670FB631D5"


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_copy_file_expand_environment(
    local_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    env_info = psrp.invoke_ps(
        connection,
        """
        $IsWindows = if (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) {
            $IsWindows
        }
        else {
            $true
        }
        if ($IsWindows) {
            "%TEMP%\\test.txt"
            $tmpPath = (Get-Item -Path $env:TEMP).FullName
        }
        else {
            "%HOME%/test.txt"
            $tmpPath = $env:HOME
        }

        Join-Path $tmpPath "test.txt"
        """,
    )[0]
    dst = env_info[0]
    expected_path = env_info[1]

    monkeypatch.setenv("PSRP_LOCAL_VAR", str(local_tmp))
    src = local_tmp / "test.txt"
    with open(src, mode="wb") as fd:
        fd.write(b"test")

    actual_path = psrp.copy_file(
        connection,
        pathlib.Path("$PSRP_LOCAL_VAR") / "test.txt",
        dst,
        expand_variables=True,
    )
    try:
        assert expected_path == actual_path

        hash_info = psrp.invoke_ps(connection, "Get-FileHash -LiteralPath $args[0]", arguments=[actual_path])[0][0]
        actual_hash = hash_info.Hash

        assert actual_hash == "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"

    finally:
        psrp.invoke_ps(
            connection, "if (Test-Path $args[0]) { Remove-Item -Path $args[0] -Force }", arguments=[actual_path]
        )


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_copy_file_missing_target_dir(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    local_file = local_tmp / "test.txt"
    with open(local_file, mode="wb") as fd:
        fd.write(b"data")

    with pytest.raises(psrp.PipelineFailed, match="Target path directory '.*' does not exist"):
        psrp.copy_file(connection, local_file, str(remote_tmp / "missing" / "test.txt"))


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_fetch_empty_file(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
    caplog: pytest.LogCaptureFixture,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    src = remote_tmp / "test.txt"
    psrp.invoke_ps(
        connection, "([System.IO.File]::Open($args[0], 'Create', 'Write', 'None')).Dispose()", arguments=[str(src)]
    )

    dst = local_tmp / "test.txt"
    with caplog.at_level(logging.DEBUG, "psrp._client"):
        actual_path = psrp.fetch_file(connection, str(src), str(dst).encode("utf-8", errors="surrogatepass"))
    assert isinstance(actual_path, bytes)
    assert actual_path == str(dst).encode("utf-8", errors="surrogatepass")

    sha256 = hashlib.sha256()
    with open(dst, mode="rb") as fd:
        while True:
            data = fd.read()
            if not data:
                break
            sha256.update(data)

    actual_hash = sha256.hexdigest().upper()
    assert actual_hash == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

    assert len(caplog.messages) == 2
    assert caplog.messages[0].startswith("Starting remote fetch operation for '")
    assert caplog.messages[1].startswith("Hash value for remote file is ")


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_fetch_file(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    src = remote_tmp / "test.txt"
    psrp.invoke_ps(connection, "[System.IO.File]::WriteAllText($args[0], 'Testing')", arguments=[str(src)])

    dst = local_tmp / "test.txt"
    actual_path = psrp.fetch_file(connection, str(src), dst)
    assert isinstance(actual_path, pathlib.Path)
    assert actual_path == dst

    sha256 = hashlib.sha256()
    with open(dst, mode="rb") as fd:
        while True:
            data = fd.read()
            if not data:
                break
            sha256.update(data)

    actual_hash = sha256.hexdigest().upper()
    assert actual_hash == "E806A291CFC3E61F83B98D344EE57E3E8933CCCECE4FB45E1481F1F560E70EB1"


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_fetch_large_file(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    src = remote_tmp / "test.txt"
    psrp.invoke_ps(connection, '[System.IO.File]::WriteAllText($args[0], ("data`n" * 1048576))', arguments=[str(src)])

    dst = local_tmp / "test.txt"
    actual_path = psrp.fetch_file(connection, str(src), str(dst))
    assert isinstance(actual_path, str)
    assert actual_path == str(dst)

    sha256 = hashlib.sha256()
    with open(dst, mode="rb") as fd:
        while True:
            data = fd.read()
            if not data:
                break
            sha256.update(data)

    actual_hash = sha256.hexdigest().upper()
    assert actual_hash == "53B5B621B6736B270F5024ED6F6912FE4197E0FA4215BF31333B11670FB631D5"


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_fetch_file_expand_environment(
    local_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    env_info = psrp.invoke_ps(
        connection,
        """
        $IsWindows = if (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) {
            $IsWindows
        }
        else {
            $true
        }
        if ($IsWindows) {
            "%TEMP%\\test.txt"
            $actual = "$env:TEMP\\test.txt"
        }
        else {
            "%HOME%/test.txt"
            $actual = "$env:HOME/test.txt"
        }

        [System.IO.File]::WriteAllText($actual, 'test')
        """,
    )[0]

    try:
        src = env_info[0]

        monkeypatch.setenv("PSRP_LOCAL_VAR", str(local_tmp))
        dst = local_tmp / "test.txt"

        actual_path = psrp.fetch_file(
            connection,
            src,
            pathlib.Path("$PSRP_LOCAL_VAR") / "test.txt",
            expand_variables=True,
        )
        assert isinstance(actual_path, pathlib.Path)
        assert actual_path == dst

        sha256 = hashlib.sha256()
        with open(dst, mode="rb") as fd:
            while True:
                data = fd.read()
                if not data:
                    break
                sha256.update(data)

        actual_hash = sha256.hexdigest().upper()
        assert actual_hash == "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"

    finally:
        psrp.invoke_ps(connection, "if (Test-Path $args[0]) { Remove-Item -Path $args[0] -Force }", arguments=[src])


def test_fetch_file_invalid_remote_path(
    psrp_proc: psrp.ProcessInfo,
) -> None:
    with pytest.raises(psrp.PipelineFailed, match="The path at '.*' does not exist"):
        psrp.fetch_file(psrp_proc, "-invalid\\path/or folder", "/tmp")


@pytest.mark.parametrize("conn", ["proc"])
def test_fetch_file_invalid_hash(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    mock_sha1 = mocker.MagicMock()
    mock_sha1.return_value.hexdigest.return_value = "0000000000000000000000000000000000000000"
    monkeypatch.setattr(hashlib, "sha1", mock_sha1)

    src = remote_tmp / "test.txt"
    psrp.invoke_ps(connection, "[System.IO.File]::WriteAllText($args[0], 'Testing')", arguments=[str(src)])

    dst = local_tmp / "test.txt"

    with pytest.raises(psrp.PSRPError, match="Invalid hash of retrieved file - \\d+ != \\d+"):
        psrp.fetch_file(connection, str(src), dst)


@pytest.mark.parametrize("conn", ["proc"])
def test_fetch_file_replace_existing(
    local_tmp: pathlib.Path,
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    src = remote_tmp / "test.txt"
    psrp.invoke_ps(connection, "[System.IO.File]::WriteAllText($args[0], 'Testing')", arguments=[str(src)])

    dst = local_tmp / "test.txt"
    dst.write_bytes(b"random")

    psrp.fetch_file(connection, str(src), dst)

    dst.read_bytes() == "Testing"


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_connection(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    actual_out, actual_streams, actual_had_errors = psrp.invoke_ps(connection, "'hi'")
    assert actual_out == ["hi"]
    assert isinstance(actual_streams, psrp.SyncPSDataStreams)
    assert not actual_had_errors


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_runspace(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script("$myVar = 'test'", use_local_scope=False).invoke()

        actual_out, actual_streams, actual_had_errors = psrp.invoke_ps(rp, "$myVar")
        assert actual_out == ["test"]
        assert isinstance(actual_streams, psrp.SyncPSDataStreams)
        assert not actual_had_errors


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_arguments(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = psrp.invoke_ps(connection, "$args[0]", arguments=["test"])[0]
    assert actual == ["test"]

    actual = psrp.invoke_ps(connection, "param($NamedParam); $NamedParam", arguments={"NamedParam": "test"})[0]
    assert actual == ["test"]


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_input_data(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = psrp.invoke_ps(connection, "$input", input_data=[1, "2", 3])[0]
    assert len(actual) == 3
    assert actual[0] == 1
    assert actual[1] == "2"
    assert actual[2] == 3


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_cwd(
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = psrp.invoke_ps(
        connection,
        "$pwd.ProviderPath; [System.Environment]::CurrentDirectory",
        cwd=str(remote_tmp),
    )[0]
    assert actual[0] == actual[1]
    assert actual[0] == str(remote_tmp)


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_cwd_expand(
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script("$env:PSRP_ENV_VAR = $args[0]").add_argument(str(remote_tmp)).invoke()

        actual = psrp.invoke_ps(
            rp,
            "$pwd.ProviderPath; [System.Environment]::CurrentDirectory",
            cwd="%PSRP_ENV_VAR%",
            expand_variables=True,
        )[0]
        assert actual[0] == actual[1]
        assert actual[0] == str(remote_tmp)


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_cwd_other_provider(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = psrp.invoke_ps(
        connection,
        "$pwd.Path; [System.Environment]::CurrentDirectory",
        cwd="Variable:/",
    )[0]
    assert actual[0] == "Microsoft.PowerShell.Core\\Variable::"
    assert actual[0] != actual[1]


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_environment(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = psrp.invoke_ps(connection, "$env:MyEnvVar", environment={"MyEnvVar": "test"})[0]
    assert actual == ["test"]


@pytest.mark.parametrize("conn", ["proc", "wsman"])
def test_invoke_ps_with_host(
    conn: str,
    request: pytest.FixtureRequest,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    host_ui = psrp.PSHostUI()
    host = psrp.PSHost(ui=host_ui)
    write_line = mocker.MagicMock()
    monkeypatch.setattr(host_ui, "write_line", write_line)
    monkeypatch.setattr(host_ui, "write_progress", mocker.MagicMock())  # WinPS will write a progress record

    actual_out, actual_streams, actual_had_errors = psrp.invoke_ps(connection, "Write-Host 'host'", host=host)
    assert actual_out == []
    assert len(actual_streams.information) == 1
    assert actual_streams.information[0].MessageData.Message == "host"
    assert not actual_had_errors
    write_line.assert_called_once_with("host")


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_connection(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    actual_out, actual_streams, actual_had_errors = await psrp.async_invoke_ps(connection, "'hi'")
    assert actual_out == ["hi"]
    assert isinstance(actual_streams, psrp.AsyncPSDataStreams)
    assert not actual_had_errors


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_runspace(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")
    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        await ps.add_script("$myVar = 'test'", use_local_scope=False).invoke()

        actual_out, actual_streams, actual_had_errors = await psrp.async_invoke_ps(rp, "$myVar")
        assert actual_out == ["test"]
        assert isinstance(actual_streams, psrp.AsyncPSDataStreams)
        assert not actual_had_errors


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_arguments(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = psrp.invoke_ps(connection, "$args[0]", arguments=["test"])[0]
    assert actual == ["test"]

    actual = psrp.invoke_ps(connection, "param($NamedParam); $NamedParam", arguments={"NamedParam": "test"})[0]
    assert actual == ["test"]


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_input_data(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = (await psrp.async_invoke_ps(connection, "$input", input_data=[1, "2", 3]))[0]
    assert len(actual) == 3
    assert actual[0] == 1
    assert actual[1] == "2"
    assert actual[2] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_cwd(
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = (
        await psrp.async_invoke_ps(
            connection,
            "$pwd.ProviderPath; [System.Environment]::CurrentDirectory",
            cwd=str(remote_tmp),
        )
    )[0]
    assert actual[0] == actual[1]
    assert actual[0] == str(remote_tmp)


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_cwd_expand(
    remote_tmp: pathlib.Path,
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        await ps.add_script("$env:PSRP_ENV_VAR = $args[0]").add_argument(str(remote_tmp)).invoke()

        actual = (
            await psrp.async_invoke_ps(
                rp,
                "$pwd.ProviderPath; [System.Environment]::CurrentDirectory",
                cwd="%PSRP_ENV_VAR%",
                expand_variables=True,
            )
        )[0]
        assert actual[0] == actual[1]
        assert actual[0] == str(remote_tmp)


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_cwd_other_provider(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = (
        await psrp.async_invoke_ps(
            connection,
            "$pwd.Path; [System.Environment]::CurrentDirectory",
            cwd="Variable:/",
        )
    )[0]
    assert actual[0] == "Microsoft.PowerShell.Core\\Variable::"
    assert actual[0] != actual[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_environment(
    conn: str,
    request: pytest.FixtureRequest,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    actual = (await psrp.async_invoke_ps(connection, "$env:MyEnvVar", environment={"MyEnvVar": "test"}))[0]
    assert actual == ["test"]


@pytest.mark.asyncio
@pytest.mark.parametrize("conn", ["proc", "wsman"])
async def test_async_invoke_ps_with_host(
    conn: str,
    request: pytest.FixtureRequest,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = request.getfixturevalue(f"psrp_{conn}")

    host_ui = psrp.PSHostUI()
    host = psrp.PSHost(ui=host_ui)
    write_line = mocker.MagicMock()
    monkeypatch.setattr(host_ui, "write_line", write_line)
    monkeypatch.setattr(host_ui, "write_progress", mocker.MagicMock())  # WinPS will write a progress record

    actual_out, actual_streams, actual_had_errors = await psrp.async_invoke_ps(
        connection, "Write-Host 'host'", host=host
    )
    assert actual_out == []
    assert len(actual_streams.information) == 1
    assert actual_streams.information[0].MessageData.Message == "host"
    assert not actual_had_errors
    write_line.assert_called_once_with("host")
