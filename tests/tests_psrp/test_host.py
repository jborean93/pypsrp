import typing as t
import uuid

import psrpcore
import pytest
import pytest_mock

import psrp
from psrp._host import get_host_method


class MockPSHostRawUI(psrp.PSHostRawUI):
    def get_foreground_color(self) -> psrpcore.types.ConsoleColor:
        return psrpcore.types.ConsoleColor.White

    def get_background_color(self) -> psrpcore.types.ConsoleColor:
        return psrpcore.types.ConsoleColor.Black

    def get_cursor_position(self) -> psrpcore.types.Coordinates:
        return psrpcore.types.Coordinates(X=0, Y=0)

    def get_window_position(self) -> psrpcore.types.Coordinates:
        return psrpcore.types.Coordinates(X=0, Y=0)

    def get_cursor_size(self) -> int:
        return 10

    def get_buffer_size(self) -> psrpcore.types.Size:
        return psrpcore.types.Size(Width=80, Height=60)

    def get_window_size(self) -> psrpcore.types.Size:
        return psrpcore.types.Size(Width=80, Height=60)

    def get_max_window_size(self) -> psrpcore.types.Size:
        return psrpcore.types.Size(Width=80, Height=60)

    def get_max_physical_window_size(self) -> psrpcore.types.Size:
        return psrpcore.types.Size(Width=80, Height=60)

    def get_window_title(self) -> str:
        return "pypsrp test"


def get_rp_pair() -> t.Tuple[psrpcore.ClientRunspacePool, psrpcore.ServerRunspacePool]:
    client = psrpcore.ClientRunspacePool()
    server = psrpcore.ServerRunspacePool()

    client.open()
    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    while server.next_event():
        pass
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    while client.next_event():
        pass

    client.exchange_key()
    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    while server.next_event():
        pass
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    while client.next_event():
        pass

    return client, server


@pytest.mark.asyncio
async def test_host_get_name(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_name()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    get_name = mocker.MagicMock(return_value="name")
    monkeypatch.setattr(host, "get_name", get_name)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_name.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetName
    assert host_resp.result == "name"


@pytest.mark.asyncio
async def test_host_get_version(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_version()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    get_version = mocker.MagicMock(return_value=psrpcore.types.PSVersion("1.2.3.4"))
    monkeypatch.setattr(host, "get_version", get_version)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_version.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetVersion
    assert host_resp.result == psrpcore.types.PSVersion("1.2.3.4")


@pytest.mark.asyncio
async def test_host_get_instance_id(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_instance_id()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    get_instance_id = mocker.MagicMock(return_value=uuid.UUID(int=1))
    monkeypatch.setattr(host, "get_instance_id", get_instance_id)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_instance_id.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetInstanceId
    assert host_resp.result == uuid.UUID(int=1)


@pytest.mark.asyncio
async def test_host_get_current_culture(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_current_culture()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    get_current_culture = mocker.MagicMock(return_value="en-US")
    monkeypatch.setattr(host, "get_current_culture", get_current_culture)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_current_culture.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetCurrentCulture
    assert host_resp.result == "en-US"


@pytest.mark.asyncio
async def test_host_get_current_ui_culture(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_current_ui_culture()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    get_current_ui_culture = mocker.MagicMock(return_value="en-US")
    monkeypatch.setattr(host, "get_current_ui_culture", get_current_ui_culture)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_current_ui_culture.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetCurrentUICulture
    assert host_resp.result == "en-US"


@pytest.mark.asyncio
async def test_host_enter_nested_prompt(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.enter_nested_prompt()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    enter_nested_prompt = mocker.MagicMock()
    monkeypatch.setattr(host, "enter_nested_prompt", enter_nested_prompt)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is None
    host_method[0]()

    enter_nested_prompt.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_exit_nested_prompt(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.exit_nested_prompt()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    exit_nested_prompt = mocker.MagicMock()
    monkeypatch.setattr(host, "exit_nested_prompt", exit_nested_prompt)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is None
    host_method[0]()

    exit_nested_prompt.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_notify_begin_application(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.notify_begin_application()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    notify_begin_application = mocker.MagicMock()
    monkeypatch.setattr(host, "notify_begin_application", notify_begin_application)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is None
    host_method[0]()

    notify_begin_application.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_notify_end_application(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.notify_end_application()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost()
    notify_end_application = mocker.MagicMock()
    monkeypatch.setattr(host, "notify_end_application", notify_end_application)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is None
    host_method[0]()

    notify_end_application.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_set_should_exit(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_should_exit = mocker.MagicMock()
    host = psrp.PSHost()
    monkeypatch.setattr(host, "set_should_exit", set_should_exit)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.SetShouldExit(1)")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        set_should_exit.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_host_ui_read_line(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_line = mocker.MagicMock()
    read_line.return_value = "line"
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "read_line", read_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.ReadLine()")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == ["line"]
        read_line.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_ui_read_line_as_secure_string(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_line_as_secure_string = mocker.MagicMock()
    read_line_as_secure_string.return_value = psrpcore.types.PSSecureString("secret")
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "read_line_as_secure_string", read_line_as_secure_string)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.ReadLineAsSecureString()")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.PSSecureString)
        assert actual[0].decrypt() == "secret"
        read_line_as_secure_string.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_ui_write1(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write", write)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.Write('value')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write.assert_called_once_with("value")


@pytest.mark.asyncio
async def test_host_ui_write2(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write", write)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.Write('Black', 'Red', 'value')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write.assert_called_once_with(
            "value",
            foreground_color=psrpcore.types.ConsoleColor.Black,
            background_color=psrpcore.types.ConsoleColor.Red,
        )


@pytest.mark.asyncio
async def test_host_ui_writeline1(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_line", write_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteLine()")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_line.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_ui_writeline2(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_line", write_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteLine('line')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_line.assert_called_once_with("line")


@pytest.mark.asyncio
async def test_host_ui_writeline3(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_line", write_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteLine('Black', 'Red', 'line')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_line.assert_called_once_with(
            "line",
            foreground_color=psrpcore.types.ConsoleColor.Black,
            background_color=psrpcore.types.ConsoleColor.Red,
        )


@pytest.mark.asyncio
async def test_host_ui_write_error_line(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_error_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_error_line", write_error_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteErrorLine('line')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_error_line.assert_called_once_with("line")


@pytest.mark.asyncio
async def test_host_ui_write_debug_line(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_debug_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_debug_line", write_debug_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteDebugLine('line')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_debug_line.assert_called_once_with("line")


@pytest.mark.asyncio
async def test_host_ui_write_progress(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_progress = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_progress", write_progress)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $rec = [System.Management.Automation.ProgressRecord]::new(1, 'activity', 'status')
            $host.UI.WriteProgress(10, $rec)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_progress.assert_called_once_with(
            10,
            1,
            "activity",
            "status",
            current_operation=None,
            parent_activity_id=-1,
            percent_complete=-1,
            record_type=psrpcore.types.ProgressRecordType.Processing,
            seconds_remaining=-1,
        )


@pytest.mark.asyncio
async def test_host_ui_write_verbose_line(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_verbose_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_verbose_line", write_verbose_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteVerboseLine('line')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_verbose_line.assert_called_once_with("line")


@pytest.mark.asyncio
async def test_host_ui_write_warning_line(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_warning_line = mocker.MagicMock()
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "write_warning_line", write_warning_line)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.WriteWarningLine('line')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        write_warning_line.assert_called_once_with("line")


@pytest.mark.asyncio
async def test_host_ui_prompt(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = mocker.MagicMock()
    prompt.return_value = {
        "name 1": 1,
        "name 2": "two",
    }
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "prompt", prompt)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $field1 = [System.Management.Automation.Host.FieldDescription]::new("name 1")
            $field1.SetParameterType([int])

            $descriptions = @(
                $field1,
                [System.Management.Automation.Host.FieldDescription]::new("name 2")
            )
            $host.UI.Prompt("caption", "message", $descriptions)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == [
            {
                "name 1": 1,
                "name 2": "two",
            }
        ]

        fields = prompt.call_args[0][2]
        assert isinstance(fields, list)
        assert isinstance(fields[0], psrpcore.types.FieldDescription)
        assert fields[0].Name == "name 1"
        assert fields[0].ParameterTypeName == "Int32"
        assert fields[0].ParameterTypeFullName == "System.Int32"

        assert isinstance(fields[1], psrpcore.types.FieldDescription)
        assert fields[1].Name == "name 2"
        assert fields[1].ParameterTypeName == "String"
        assert fields[1].ParameterTypeFullName == "System.String"

        prompt.assert_called_once_with(
            "caption",
            "message",
            fields,
        )


@pytest.mark.asyncio
async def test_host_ui_prompt_for_credential1(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PowerShell doesn't seem to send PromptForCredential1
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.prompt_for_credential("caption", "message")
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    host = psrp.PSHost(ui=psrp.PSHostUI())
    prompt_for_credential = mocker.MagicMock()
    prompt_for_credential.return_value = psrpcore.types.PSCredential(
        UserName="username",
        Password=psrpcore.types.PSSecureString("password"),
    )
    monkeypatch.setattr(host.ui, "prompt_for_credential", prompt_for_credential)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    prompt_for_credential.assert_called_once_with("caption", "message", username=None, target="")

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.PromptForCredential1
    assert isinstance(host_resp.result, psrpcore.types.PSCredential)
    assert host_resp.result.UserName == "username"
    assert host_resp.result.Password.decrypt() == "password"


@pytest.mark.asyncio
async def test_host_ui_prompt_for_credential2(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt_for_credential = mocker.MagicMock()
    prompt_for_credential.return_value = psrpcore.types.PSCredential(
        UserName="username",
        Password=psrpcore.types.PSSecureString("password"),
    )
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "prompt_for_credential", prompt_for_credential)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.PromptForCredential("caption", "message", "userName", "targetName")
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.PSCredential)
        assert actual[0].UserName == "username"
        assert isinstance(actual[0].Password, psrpcore.types.PSSecureString)
        assert actual[0].Password.decrypt() == "password"

        prompt_for_credential.assert_called_once_with(
            "caption",
            "message",
            username="userName",
            target_name="targetName",
            allowed_credential_types=psrpcore.types.PSCredentialTypes.Default,
            options=psrpcore.types.PSCredentialUIOptions.ValidateUserNameSyntax,
        )


@pytest.mark.asyncio
async def test_host_ui_prompt_for_choice(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt_for_choice = mocker.MagicMock()
    prompt_for_choice.return_value = 0
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "prompt_for_choice", prompt_for_choice)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $choices = @(
                [System.Management.Automation.Host.ChoiceDescription]::new("name 1"),
                [System.Management.Automation.Host.ChoiceDescription]::new("name 2", "help msg")
            )
            $host.UI.PromptForChoice("caption", "message", $choices, 1)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == [0]

        choices = prompt_for_choice.call_args[0][2]
        assert isinstance(choices, list)
        assert len(choices) == 2
        assert isinstance(choices[0], psrpcore.types.ChoiceDescription)
        assert choices[0].Label == "name 1"
        assert choices[0].HelpMessage == ""

        assert isinstance(choices[1], psrpcore.types.ChoiceDescription)
        assert choices[1].Label == "name 2"
        assert choices[1].HelpMessage == "help msg"

        prompt_for_choice.assert_called_once_with(
            "caption",
            "message",
            choices,
            default_choice=1,
        )


@pytest.mark.asyncio
async def test_host_ui_prompt_for_multiple_choice(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt_for_multiple_choice = mocker.MagicMock()
    prompt_for_multiple_choice.return_value = [1, 2]
    host = psrp.PSHost(ui=psrp.PSHostUI())
    monkeypatch.setattr(host.ui, "prompt_for_multiple_choice", prompt_for_multiple_choice)

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $default = [System.Collections.ObjectModel.Collection[int]]::new()
            $default.Add(0)
            $default.Add(1)
            $choices = @(
                [System.Management.Automation.Host.ChoiceDescription]::new("name 1"),
                [System.Management.Automation.Host.ChoiceDescription]::new("name 2", "help msg"),
                [System.Management.Automation.Host.ChoiceDescription]::new("name 3", "other help msg")
            )
            $host.UI.PromptForChoice("caption", "message", $choices, $default)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == [1, 2]

        choices = prompt_for_multiple_choice.call_args[0][2]
        assert isinstance(choices, list)
        assert len(choices) == 3
        assert isinstance(choices[0], psrpcore.types.ChoiceDescription)
        assert choices[0].Label == "name 1"
        assert choices[0].HelpMessage == ""

        assert isinstance(choices[1], psrpcore.types.ChoiceDescription)
        assert choices[1].Label == "name 2"
        assert choices[1].HelpMessage == "help msg"

        assert isinstance(choices[2], psrpcore.types.ChoiceDescription)
        assert choices[2].Label == "name 3"
        assert choices[2].HelpMessage == "other help msg"

        prompt_for_multiple_choice.assert_called_once_with(
            "caption",
            "message",
            choices,
            default_choices=[0, 1],
        )


@pytest.mark.asyncio
async def test_host_raw_ui_get_foreground_color(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_foreground_color()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_foreground_color = mocker.MagicMock(return_value=psrpcore.types.ConsoleColor.Cyan)
    monkeypatch.setattr(raw_ui, "get_foreground_color", get_foreground_color)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_foreground_color.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetForegroundColor
    assert host_resp.result == psrpcore.types.ConsoleColor.Cyan


@pytest.mark.asyncio
async def test_host_raw_ui_set_foreground_color(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_foreground_color = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_foreground_color", set_foreground_color)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.RawUI.ForegroundColor = 'Blue'; $host.UI.RawUI.ForegroundColor")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == [psrpcore.types.ConsoleColor.Blue]

        set_foreground_color.assert_called_once_with(actual[0])


@pytest.mark.asyncio
async def test_host_raw_ui_get_background_color(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_background_color()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_background_color = mocker.MagicMock(return_value=psrpcore.types.ConsoleColor.Cyan)
    monkeypatch.setattr(raw_ui, "get_background_color", get_background_color)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_background_color.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetBackgroundColor
    assert host_resp.result == psrpcore.types.ConsoleColor.Cyan


@pytest.mark.asyncio
async def test_host_raw_ui_set_background_color(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_background_color = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_background_color", set_background_color)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.RawUI.BackgroundColor = 'Blue'; $host.UI.RawUI.BackgroundColor")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == [psrpcore.types.ConsoleColor.Blue]

        set_background_color.assert_called_once_with(actual[0])


@pytest.mark.asyncio
async def test_host_raw_ui_get_cursor_position(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_cursor_position()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_cursor_position = mocker.MagicMock(return_value=psrpcore.types.Coordinates(X=1, Y=2))
    monkeypatch.setattr(raw_ui, "get_cursor_position", get_cursor_position)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_cursor_position.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetCursorPosition
    assert isinstance(host_resp.result, psrpcore.types.Coordinates)
    assert host_resp.result.X == 1
    assert host_resp.result.Y == 2


@pytest.mark.asyncio
async def test_host_raw_ui_set_cursor_position(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_cursor_position = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_cursor_position", set_cursor_position)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.RawUI.CursorPosition = [System.Management.Automation.Host.Coordinates]::new(10, 20)
            $host.UI.RawUI.CursorPosition
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.Coordinates)
        assert actual[0].X == 10
        assert actual[0].Y == 20

        set_cursor_position.assert_called_once_with(10, 20)


@pytest.mark.asyncio
async def test_host_raw_ui_get_window_position(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_window_position()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_window_position = mocker.MagicMock(return_value=psrpcore.types.Coordinates(X=1, Y=2))
    monkeypatch.setattr(raw_ui, "get_window_position", get_window_position)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_window_position.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetWindowPosition
    assert isinstance(host_resp.result, psrpcore.types.Coordinates)
    assert host_resp.result.X == 1
    assert host_resp.result.Y == 2


@pytest.mark.asyncio
async def test_host_raw_ui_set_window_position(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_window_position = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_window_position", set_window_position)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.RawUI.WindowPosition = [System.Management.Automation.Host.Coordinates]::new(10, 20)
            $host.UI.RawUI.WindowPosition
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.Coordinates)
        assert actual[0].X == 10
        assert actual[0].Y == 20

        set_window_position.assert_called_once_with(10, 20)


@pytest.mark.asyncio
async def test_host_raw_ui_get_cursor_size(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_cursor_size()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_cursor_size = mocker.MagicMock(return_value=10)
    monkeypatch.setattr(raw_ui, "get_cursor_size", get_cursor_size)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_cursor_size.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetCursorSize
    assert host_resp.result == 10


@pytest.mark.asyncio
async def test_host_raw_ui_set_cursor_size(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_cursor_size = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_cursor_size", set_cursor_size)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.RawUI.CursorSize = 50
            $host.UI.RawUI.CursorSize
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == [50]

        set_cursor_size.assert_called_once_with(50)


@pytest.mark.asyncio
async def test_host_raw_ui_get_buffer_size(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_buffer_size()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_buffer_size = mocker.MagicMock(return_value=psrpcore.types.Size(Width=10, Height=20))
    monkeypatch.setattr(raw_ui, "get_buffer_size", get_buffer_size)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_buffer_size.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetBufferSize
    assert isinstance(host_resp.result, psrpcore.types.Size)
    assert host_resp.result.Width == 10
    assert host_resp.result.Height == 20


@pytest.mark.asyncio
async def test_host_raw_ui_set_buffer_size(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_buffer_size = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_buffer_size", set_buffer_size)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.RawUI.BufferSize = [System.Management.Automation.Host.Size]::new(120, 100)
            $host.UI.RawUI.BufferSize
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.Size)
        assert actual[0].Width == 120
        assert actual[0].Height == 100

        set_buffer_size.assert_called_once_with(120, 100)


@pytest.mark.asyncio
async def test_host_raw_ui_get_window_size(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_window_size()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_window_size = mocker.MagicMock(return_value=psrpcore.types.Size(Width=10, Height=20))
    monkeypatch.setattr(raw_ui, "get_window_size", get_window_size)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_window_size.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetWindowSize
    assert isinstance(host_resp.result, psrpcore.types.Size)
    assert host_resp.result.Width == 10
    assert host_resp.result.Height == 20


@pytest.mark.asyncio
async def test_host_raw_ui_set_window_size(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_window_size = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_window_size", set_window_size)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.RawUI.WindowSize = [System.Management.Automation.Host.Size]::new(120, 100)
            $host.UI.RawUI.WindowSize
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.Size)
        assert actual[0].Width == 120
        assert actual[0].Height == 100

        set_window_size.assert_called_once_with(120, 100)


@pytest.mark.asyncio
async def test_host_raw_ui_get_window_title(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_window_title()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_window_title = mocker.MagicMock(return_value="title")
    monkeypatch.setattr(raw_ui, "get_window_title", get_window_title)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_window_title.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetWindowTitle
    assert host_resp.result == "title"


@pytest.mark.asyncio
async def test_host_raw_ui_set_window_title(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_window_title = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_window_title", set_window_title)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $host.UI.RawUI.WindowTitle = "new title"
            $host.UI.RawUI.WindowTitle
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == ["new title"]

        set_window_title.assert_called_once_with("new title")


@pytest.mark.asyncio
async def test_host_raw_ui_get_max_window_size(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_max_window_size()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_max_window_size = mocker.MagicMock(return_value=psrpcore.types.Size(Width=10, Height=20))
    monkeypatch.setattr(raw_ui, "get_max_window_size", get_max_window_size)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_max_window_size.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetMaxWindowSize
    assert isinstance(host_resp.result, psrpcore.types.Size)
    assert host_resp.result.Width == 10
    assert host_resp.result.Height == 20


@pytest.mark.asyncio
async def test_host_raw_ui_get_max_physical_window_size(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_max_physical_window_size()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_max_physical_window_size = mocker.MagicMock(return_value=psrpcore.types.Size(Width=10, Height=20))
    monkeypatch.setattr(raw_ui, "get_max_physical_window_size", get_max_physical_window_size)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_max_physical_window_size.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetMaxPhysicalWindowSize
    assert isinstance(host_resp.result, psrpcore.types.Size)
    assert host_resp.result.Width == 10
    assert host_resp.result.Height == 20


@pytest.mark.asyncio
async def test_host_raw_ui_key_available(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_key_available()
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = psrp.PSHostRawUI()
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))
    get_key_available = mocker.MagicMock(return_value=False)
    monkeypatch.setattr(raw_ui, "get_key_available", get_key_available)

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    get_key_available.assert_called_once_with()

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetKeyAvailable
    assert host_resp.result is False


@pytest.mark.asyncio
async def test_host_raw_ui_read_key1(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    read_key = mocker.MagicMock()
    read_key.return_value = psrpcore.types.KeyInfo(
        VirtualKeyCode=0x41,
        Character=psrpcore.types.PSChar("a"),
        ControlKeyState=psrpcore.types.ControlKeyStates.none,
        KeyDown=True,
    )
    monkeypatch.setattr(raw_ui, "read_key", read_key)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.RawUI.ReadKey()")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.KeyInfo)
        assert actual[0].VirtualKeyCode == 0x41
        assert actual[0].Character == 97
        assert actual[0].ControlKeyState == "0"
        assert actual[0].KeyDown is True
        read_key.assert_called_once_with(options=psrpcore.types.ReadKeyOptions.IncludeKeyDown)


@pytest.mark.asyncio
async def test_host_raw_ui_read_key2(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    read_key = mocker.MagicMock()
    read_key.return_value = psrpcore.types.KeyInfo(
        VirtualKeyCode=0x41,
        Character=psrpcore.types.PSChar("a"),
        ControlKeyState=psrpcore.types.ControlKeyStates.none,
        KeyDown=True,
    )
    monkeypatch.setattr(raw_ui, "read_key", read_key)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.RawUI.ReadKey('AllowCtrlC, IncludeKeyUp')")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert len(actual) == 1
        assert isinstance(actual[0], psrpcore.types.KeyInfo)
        assert actual[0].VirtualKeyCode == 0x41
        assert actual[0].Character == 97
        assert actual[0].ControlKeyState == "0"
        assert actual[0].KeyDown is True
        read_key.assert_called_once_with(
            options=psrpcore.types.ReadKeyOptions.AllowCtrlC | psrpcore.types.ReadKeyOptions.IncludeKeyUp
        )


@pytest.mark.asyncio
async def test_host_raw_ui_flush_input_buffer(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    flush_input_buffer = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "flush_input_buffer", flush_input_buffer)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script("$host.UI.RawUI.FlushInputBuffer()")

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        flush_input_buffer.assert_called_once_with()


@pytest.mark.asyncio
async def test_host_raw_ui_set_buffer_contents1(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_buffer_cells = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_buffer_cells", set_buffer_cells)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $rec = [System.Management.Automation.Host.Rectangle]::new(0, 1, 10, 11)
            $cell = [System.Management.Automation.Host.BufferCell]::new('a', 'White', 'Gray', 'Complete')
            $host.UI.RawUI.SetBufferContents($rec, $cell)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []
        set_buffer_cells.assert_called_once_with(
            0,
            1,
            10,
            11,
            psrpcore.types.PSChar("a"),
            foreground=psrpcore.types.ConsoleColor.White,
            background=psrpcore.types.ConsoleColor.Gray,
        )


@pytest.mark.asyncio
async def test_host_raw_ui_set_buffer_contents2(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    set_buffer_contents = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "set_buffer_contents", set_buffer_contents)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $coordinates = [System.Management.Automation.Host.Coordinates]::new(1, 2)
            $cell = [System.Management.Automation.Host.BufferCell]::new('a', 'White', 'Gray', 'Complete')
            $cells = $Host.UI.RawUI.NewBufferCellArray(3, 4, $cell)
            $host.UI.RawUI.SetBufferContents($coordinates, $cells)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []

        contents = set_buffer_contents.call_args[0][2]
        assert isinstance(contents, list)
        assert len(contents) == 4

        for row in contents:
            assert isinstance(row, list)
            assert len(row) == 3
            for column in row:
                assert isinstance(column, psrpcore.types.BufferCell)
                assert column.Character == psrpcore.types.PSChar("a")
                assert column.ForegroundColor == psrpcore.types.ConsoleColor.White
                assert column.BackgroundColor == psrpcore.types.ConsoleColor.Gray
                assert column.BufferCellType == psrpcore.types.BufferCellType.Complete

        set_buffer_contents.assert_called_once_with(
            1,
            2,
            contents,
        )


@pytest.mark.asyncio
async def test_host_raw_ui_get_buffer_contents(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = get_rp_pair()
    client_host = psrpcore.ClientHostResponder(client)
    server_host = psrpcore.ServerHostRequestor(server)

    server_host.get_buffer_contents(0, 1, 2, 3)
    client.receive_data(t.cast(psrpcore.PSRPPayload, server.data_to_send()))
    host_call = client.next_event()
    assert isinstance(host_call, psrpcore.RunspacePoolHostCallEvent)

    raw_ui = MockPSHostRawUI()
    get_buffer_contents = mocker.MagicMock()

    cell = psrpcore.types.BufferCell(
        "a",
        psrpcore.types.ConsoleColor.White,
        psrpcore.types.ConsoleColor.Black,
        psrpcore.types.BufferCellType.Complete,
    )
    get_buffer_contents.return_value = [
        [cell, cell],
        [cell, cell],
        [cell, cell],
    ]

    monkeypatch.setattr(raw_ui, "get_buffer_contents", get_buffer_contents)
    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    host_method = get_host_method(
        host,
        client_host,
        host_call.ci,
        host_call.method_identifier,
        host_call.method_parameters,
    )
    assert host_method[1] is not None
    res = host_method[0]()
    host_method[1](res)

    server.receive_data(t.cast(psrpcore.PSRPPayload, client.data_to_send()))
    host_resp = server.next_event()
    assert isinstance(host_resp, psrpcore.RunspacePoolHostResponseEvent)
    assert host_resp.ci == host_call.ci
    assert host_resp.error is None
    assert host_resp.method_identifier == psrpcore.types.HostMethodIdentifier.GetBufferContents

    result = host_resp.result
    assert isinstance(result, list)
    assert len(result) == 3
    for row in result:
        assert isinstance(row, list)
        assert len(row) == 2
        for cell in row:
            assert isinstance(cell, psrpcore.types.BufferCell)
            assert cell.Character == psrpcore.types.PSChar("a")
            assert cell.ForegroundColor == psrpcore.types.ConsoleColor.White
            assert cell.BackgroundColor == psrpcore.types.ConsoleColor.Black
            assert cell.BufferCellType == psrpcore.types.BufferCellType.Complete


@pytest.mark.asyncio
async def test_host_raw_ui_scroll_buffer_contents(
    psrp_proc: psrp.ProcessInfo,
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_ui = MockPSHostRawUI()
    scroll_buffer_contents = mocker.MagicMock()
    monkeypatch.setattr(raw_ui, "scroll_buffer_contents", scroll_buffer_contents)

    host = psrp.PSHost(ui=psrp.PSHostUI(raw_ui=raw_ui))

    async with psrp.AsyncRunspacePool(psrp_proc, host=host) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(
            """
            $rec = [System.Management.Automation.Host.Rectangle]::new(0, 1, 10, 11)
            $coordinates = [System.Management.Automation.Host.Coordinates]::new(1, 2)
            $cell = [System.Management.Automation.Host.BufferCell]::new('a', 'White', 'Gray', 'Complete')
            $host.UI.RawUI.ScrollBufferContents($rec, $coordinates, $rec, $cell)
            """
        )

        actual = await ps.invoke()
        assert len(ps.streams.error) == 0
        assert actual == []

        scroll_buffer_contents.assert_called_once_with(
            0,
            1,
            10,
            11,
            1,
            2,
            0,
            1,
            10,
            11,
            psrpcore.types.PSChar("a"),
            foreground=psrpcore.types.ConsoleColor.White,
            background=psrpcore.types.ConsoleColor.Gray,
        )


@pytest.mark.asyncio
async def test_host_get_unknown_method(
    mocker: pytest_mock.MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = psrpcore.ClientRunspacePool()
    client_host = psrpcore.ClientHostResponder(client)

    host_method = get_host_method(
        psrp.PSHost(),
        client_host,
        1,
        psrpcore.types.HostMethodIdentifier.GetRunspace,
        [],
    )
    assert host_method[1] is None
    with pytest.raises(NotImplementedError):
        host_method[0]()
