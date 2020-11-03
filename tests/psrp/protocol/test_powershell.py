# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

from psrp.dotnet.complex_types import (
    ApartmentState,
    ConsoleColor,
    Coordinates,
    HostDefaultData,
    HostInfo,
    PSInvocationState,
    PSThreadOptions,
    RemoteStreamOptions,
    RunspacePoolState,
    Size,
)

from psrp.dotnet.primitive_types import (
    PSSecureString,
    PSString,
)

from psrp.exceptions import (
    MissingCipherError,
    RunspacePoolWantRead,
)

from psrp.protocol.powershell import (
    ClientPowerShell,
    RunspacePool,
    ServerPowerShell,
    ServerRunspacePool,
    StreamType,
)

from psrp.protocol.powershell_events import (
    ApplicationPrivateDataEvent,
    CreatePipelineEvent,
    EncryptedSessionKeyEvent,
    InitRunspacePoolEvent,
    PipelineOutputEvent,
    PipelineStateEvent,
    PublicKeyEvent,
    PublicKeyRequestEvent,
    RunspacePoolStateEvent,
    SessionCapabilityEvent,
)


def get_runspace_pair():
    client = RunspacePool()
    server = ServerRunspacePool()

    client.open()
    server.receive_data(client.data_to_send())
    server.next_event()
    server.next_event()
    client.receive_data(server.data_to_send())
    client.next_event()
    client.next_event()
    client.next_event()
    
    return client, server


def test_open_runspacepool():
    client = RunspacePool()
    server = ServerRunspacePool()
    assert client.state == RunspacePoolState.BeforeOpen
    assert server.state == RunspacePoolState.BeforeOpen

    client.open()
    assert client.state == RunspacePoolState.Opening

    first = client.data_to_send()
    assert len(first.data) > 0
    assert first.stream_type == StreamType.default
    assert first.pipeline_id is None
    assert client.state == RunspacePoolState.NegotiationSent

    assert client.data_to_send() is None

    server.receive_data(first)
    session_cap = server.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert session_cap.ps_object.PSVersion == server.their_capability.PSVersion
    assert session_cap.ps_object.SerializationVersion == server.their_capability.SerializationVersion
    assert session_cap.ps_object.protocolversion == server.their_capability.protocolversion
    assert client.state == RunspacePoolState.NegotiationSent
    assert server.state == RunspacePoolState.NegotiationSucceeded
    assert server.runspace_id == client.runspace_id

    second = server.data_to_send()
    assert len(second.data) > 0
    assert second.stream_type == StreamType.default
    assert second.pipeline_id is None

    client.receive_data(second)
    session_cap = client.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert session_cap.ps_object.PSVersion == client.their_capability.PSVersion
    assert session_cap.ps_object.SerializationVersion == client.their_capability.SerializationVersion
    assert session_cap.ps_object.protocolversion == client.their_capability.protocolversion
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.NegotiationSucceeded

    init_runspace_pool = server.next_event()
    assert isinstance(init_runspace_pool, InitRunspacePoolEvent)
    assert init_runspace_pool.ps_object.ApartmentState == ApartmentState.Unknown
    assert init_runspace_pool.ps_object.ApplicationArguments == {}
    assert init_runspace_pool.ps_object.HostInfo._isHostNull
    assert init_runspace_pool.ps_object.HostInfo._isHostRawUINull
    assert init_runspace_pool.ps_object.HostInfo._isHostUINull
    assert init_runspace_pool.ps_object.HostInfo._useRunspaceHost
    assert init_runspace_pool.ps_object.MaxRunspaces == 1
    assert init_runspace_pool.ps_object.MinRunspaces == 1
    assert init_runspace_pool.ps_object.PSThreadOptions == PSThreadOptions.Default
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    with pytest.raises(RunspacePoolWantRead):
        server.next_event()

    third = server.data_to_send()
    assert len(third.data) > 0
    assert third.stream_type == StreamType.default
    assert third.pipeline_id is None

    assert server.data_to_send() is None

    client.receive_data(third)
    private_data = client.next_event()
    assert isinstance(private_data, ApplicationPrivateDataEvent)
    assert private_data.ps_object.ApplicationPrivateData == {}
    assert client.application_private_data == {}
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    runspace_state = client.next_event()
    assert isinstance(runspace_state, RunspacePoolStateEvent)
    assert client.state == RunspacePoolState.Opened
    assert server.state == RunspacePoolState.Opened

    with pytest.raises(RunspacePoolWantRead):
        client.next_event()

    assert client.data_to_send() is None


def test_open_runspacepool_small():
    client = RunspacePool()
    server = ServerRunspacePool()
    assert client.state == RunspacePoolState.BeforeOpen
    assert server.state == RunspacePoolState.BeforeOpen

    client.open()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    first = client.data_to_send(60)
    assert len(first.data) == 60
    assert first.stream_type == StreamType.default
    assert first.pipeline_id is None

    server.receive_data(first)
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    session_cap = server.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert client.state == RunspacePoolState.NegotiationSent
    assert server.state == RunspacePoolState.NegotiationSucceeded
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()

    client.receive_data(server.data_to_send())
    assert server.data_to_send() is None
    session_cap = client.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.NegotiationSucceeded
    with pytest.raises(RunspacePoolWantRead):
        client.next_event()

    server.receive_data(client.data_to_send())
    init_runspace = server.next_event()
    assert isinstance(init_runspace, InitRunspacePoolEvent)
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    client.receive_data(server.data_to_send())
    assert server.data_to_send() is None
    private_data = client.next_event()
    assert isinstance(private_data, ApplicationPrivateDataEvent)
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    runspace_state = client.next_event()
    assert isinstance(runspace_state, RunspacePoolStateEvent)
    assert client.state == RunspacePoolState.Opened
    assert server.state == RunspacePoolState.Opened

    with pytest.raises(RunspacePoolWantRead):
        client.next_event()


def test_create_pipeline():
    client, server = get_runspace_pair()

    c_pipeline = ClientPowerShell(client)
    assert c_pipeline.state == PSInvocationState.NotStarted
    
    c_pipeline.add_script('testing')
    c_pipeline.invoke()
    assert c_pipeline.state == PSInvocationState.Running

    c_command = client.data_to_send()
    server.receive_data(c_command)
    create_pipeline = server.next_event(c_command.pipeline_id)
    s_pipeline = create_pipeline.pipeline
    assert isinstance(create_pipeline, CreatePipelineEvent)
    assert isinstance(s_pipeline, ServerPowerShell)
    assert s_pipeline.add_to_history is False
    assert s_pipeline.apartment_state == ApartmentState.Unknown
    assert len(s_pipeline.commands) == 1
    assert s_pipeline.commands[0].command_text == 'testing'
    assert s_pipeline.commands[0].end_of_statement is True
    assert s_pipeline.commands[0].is_script is True
    assert s_pipeline.commands[0].parameters == []
    assert s_pipeline.commands[0].use_local_scope is None
    assert s_pipeline.history is None
    assert isinstance(s_pipeline.host, HostInfo)
    assert s_pipeline.host.host_default_data is None
    assert s_pipeline.host.is_host_null is True
    assert s_pipeline.host.is_host_raw_ui_null is True
    assert s_pipeline.host.is_host_ui_null is True
    assert s_pipeline.host.use_runspace_host is True
    assert s_pipeline.is_nested is False
    assert s_pipeline.no_input is True
    assert s_pipeline.pipeline_id == c_pipeline.pipeline_id
    assert s_pipeline.redirect_shell_error_to_out is True
    assert s_pipeline.remote_stream_options == RemoteStreamOptions.none
    assert s_pipeline.runspace_pool == server
    assert s_pipeline.state == PSInvocationState.NotStarted
    assert len(server.pipeline_table) == 1
    assert server.pipeline_table[s_pipeline.pipeline_id] == s_pipeline

    s_pipeline.write_output('output msg')
    s_pipeline.close()
    client.receive_data(server.data_to_send())
    out = client.next_event(c_pipeline.pipeline_id)
    assert server.pipeline_table == {}
    assert isinstance(out, PipelineOutputEvent)
    assert out.ps_object == 'output msg'
    
    state = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state, PipelineStateEvent)
    assert state.state == PSInvocationState.Completed
    assert c_pipeline.state == PSInvocationState.Completed
    assert client.pipeline_table == {}


def test_create_pipeline_host_data():
    client, server = get_runspace_pair()
    
    c_host_data = HostDefaultData(
        foreground_color=ConsoleColor.Red,
        background_color=ConsoleColor.White,
        cursor_position=Coordinates(1, 2),
        window_position=Coordinates(3, 4),
        cursor_size=5,
        buffer_size=Size(6, 7),
        window_size=Size(8, 9),
        max_window_size=Size(10, 11),
        max_physical_window_size=Size(12, 13),
        window_title='Test Title',
    )
    c_host = HostInfo(
        use_runspace_host=False,
        is_host_null=False,
        is_host_ui_null=False,
        is_host_raw_ui_null=False,
        host_default_data=c_host_data,
    )

    c_pipeline = ClientPowerShell(client, host=c_host)
    c_pipeline.add_script('testing')
    c_pipeline.invoke()
    
    server.receive_data(client.data_to_send())
    create_pipeline = server.next_event(c_pipeline.pipeline_id)
    s_pipeline = create_pipeline.pipeline
    s_host = s_pipeline.host
    
    assert isinstance(s_host, HostInfo)
    assert s_host.is_host_null is False
    assert s_host.is_host_ui_null is False
    assert s_host.is_host_raw_ui_null is False
    assert s_host.use_runspace_host is False
    assert isinstance(s_host.host_default_data, HostDefaultData)
    assert s_host.host_default_data.foreground_color == ConsoleColor.Red
    assert s_host.host_default_data.background_color == ConsoleColor.White
    assert s_host.host_default_data.cursor_position.X == 1
    assert s_host.host_default_data.cursor_position.Y == 2
    assert s_host.host_default_data.window_position.X == 3
    assert s_host.host_default_data.window_position.Y == 4
    assert s_host.host_default_data.cursor_size == 5
    assert s_host.host_default_data.buffer_size.Width == 6
    assert s_host.host_default_data.buffer_size.Height == 7
    assert s_host.host_default_data.window_size.Width == 8
    assert s_host.host_default_data.window_size.Height == 9
    assert s_host.host_default_data.max_window_size.Width == 10
    assert s_host.host_default_data.max_window_size.Height == 11
    assert s_host.host_default_data.max_physical_window_size.Width == 12
    assert s_host.host_default_data.max_physical_window_size.Height == 13
    assert s_host.host_default_data.window_title == 'Test Title'


def test_exchange_key_client():
    client, server = get_runspace_pair()

    client.exchange_key()
    server.receive_data(client.data_to_send())
    public_key = server.next_event()
    assert isinstance(public_key, PublicKeyEvent)
    
    client.receive_data(server.data_to_send())
    enc_key = client.next_event()
    assert isinstance(enc_key, EncryptedSessionKeyEvent)
    
    c_pipeline = ClientPowerShell(client)
    c_pipeline.add_script('command')
    c_pipeline.add_argument(PSSecureString('my secret'))
    c_pipeline.invoke()
    c_pipeline_data = client.data_to_send()
    assert b'my_secret' not in c_pipeline_data.data
    
    server.receive_data(c_pipeline_data)
    create_pipeline = server.next_event(c_pipeline.pipeline_id)
    assert isinstance(create_pipeline, CreatePipelineEvent)
    
    s_pipeline = create_pipeline.pipeline
    assert len(s_pipeline.commands) == 1
    assert s_pipeline.commands[0].command_text == 'command'
    assert s_pipeline.commands[0].parameters == [(None, 'my secret')]
    assert isinstance(s_pipeline.commands[0].parameters[0][1], PSSecureString)
    
    s_pipeline.write_output(PSSecureString('secret output'))
    s_pipeline.close()
    s_output = server.data_to_send()
    assert s_pipeline.state == PSInvocationState.Completed
    assert server.pipeline_table == {}
    assert b'secret output' not in s_output
    
    client.receive_data(s_output)
    out = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(out, PipelineOutputEvent)
    assert isinstance(out.ps_object, PSSecureString)
    assert out.ps_object == 'secret output'
    
    state = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state, PipelineStateEvent)
    assert state.state == PSInvocationState.Completed
    
    assert c_pipeline.state == PSInvocationState.Completed
    assert client.pipeline_table == {}


def test_exchange_key_request():
    client, server = get_runspace_pair()

    c_pipeline = ClientPowerShell(client)
    c_pipeline.add_script('command')
    c_pipeline.invoke()
    server.receive_data(client.data_to_send())
    s_pipeline = server.next_event(c_pipeline.pipeline_id).pipeline
    
    with pytest.raises(MissingCipherError):
        s_pipeline.write_output(PSSecureString('secret'))

    server.request_key()
    client.receive_data(server.data_to_send())
    pub_key_req = client.next_event()
    assert isinstance(pub_key_req, PublicKeyRequestEvent)

    with pytest.raises(MissingCipherError):
        s_pipeline.write_output(PSSecureString('secret'))

    server.receive_data(client.data_to_send())
    pub_key = server.next_event()
    assert isinstance(pub_key, PublicKeyEvent)
    
    s_pipeline.write_output(PSSecureString('secret'))
    s_pipeline.close()
    assert s_pipeline.state == PSInvocationState.Completed
    assert server.pipeline_table == {}

    client.receive_data(server.data_to_send())
    enc_key = client.next_event()
    assert isinstance(enc_key, EncryptedSessionKeyEvent)

    b_data = server.data_to_send()
    client.receive_data(b_data)
    assert b'secret' not in b_data
    
    out = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(out, PipelineOutputEvent)
    assert isinstance(out.ps_object, PSSecureString)
    assert out.ps_object == 'secret'
    
    state = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state, PipelineStateEvent)
    assert state.state == PSInvocationState.Completed
    assert c_pipeline.state == PSInvocationState.Completed
    assert client.pipeline_table == {}
