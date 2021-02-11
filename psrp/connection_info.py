# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import enum
import base64
import threading
import typing
import xml.etree.ElementTree as ElementTree

from ._compat import (
    asyncio_create_task,
)

from .dotnet.complex_types import (
    RunspacePoolState,
)

from .dotnet.psrp_messages import (
    PSRPMessageType,
)

from .exceptions import (
    OperationAborted,
    OperationTimedOut,
    RunspacePoolWantRead,
    ServiceStreamDisconnected,
)

from .io.process import (
    AsyncProcess,
    Process,
)

from .io.wsman import (
    AsyncWSManConnection,
)

from .protocol.powershell import (
    PSRPPayload,
    RunspacePool,
    StreamType,
)

from .protocol.powershell_events import (
    PSRPEvent,
)

from .protocol.winrs import (
    WinRS,
)

from .protocol.wsman import (
    CommandState,
    NAMESPACES,
    OptionSet,
    ReceiveResponseEvent,
    SignalCode,
    WSMan,
)


class OutputBufferingMode(enum.Enum):
    none = enum.auto()
    block = enum.auto()
    drop = enum.auto()


class _MessageEvent:

    def __init__(self):
        self._events = {}
        self._event_lock = threading.Lock()

    def wait(
            self,
            identifier: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        key = f'{identifier}:{(pipeline_id or "").upper()}'
        wait_event = self._get_event(key)
        wait_event.wait()

    def set(
            self,
            identifier: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        key = f'{identifier}:{(pipeline_id or "").upper()}'
        event = self._get_event(key)
        event.set()
        event.clear()

    def _get_event(
            self,
            identifier: typing.Union[str, int],
    ) -> threading.Event:
        with self._event_lock:
            if identifier not in self._events:
                self._events[identifier] = threading.Event()

        return self._events[identifier]


class _AsyncMessageEvent:
    """ Asyncio queue that allows the caller to wait and put messages based on a unique identifier. """

    def __init__(self):
        self._events = {}
        self._event_lock = asyncio.Lock()

    async def wait(
            self,
            identifier: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        key = f'{identifier}:{(pipeline_id or "").upper()}'
        wait_event = await self._get_event(key)
        await wait_event.wait()

    async def set(
            self,
            identifier: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        key = f'{identifier}:{(pipeline_id or "").upper()}'
        event = await self._get_event(key)
        event.set()
        event.clear()

    async def _get_event(
            self,
            identifier: typing.Union[str, int],
    ) -> asyncio.Event:
        async with self._event_lock:
            if identifier not in self._events:
                self._events[identifier] = asyncio.Event()

        return self._events[identifier]


class ConnectionInfo:

    def __new__(cls, *args, **kwargs):
        if cls in [ConnectionInfo, AsyncConnectionInfo]:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'PSRP connection implementations.')

        return super().__new__(cls)

    def __init__(
            self,
    ):
        self.runspace_pool: typing.Optional[RunspacePool] = None
        self.fragment_size = 32_768
        self._buffer = bytearray()

    def set_runspace_pool(
            self,
            pool: RunspacePool,
    ):
        """Set the Runspace Pool.

        Used internally to set the RunspacePool that this connection info uses.

        Args:
            pool: The Runspace Pool protocol object to set.
        """
        self.runspace_pool = pool

    def next_payload(
            self,
            buffer: bool = False,
    ) -> typing.Optional[PSRPPayload]:
        """Get the next payload.

        Get the next payload to exchange if there are any.

        Args:
            buffer: Wait until the buffer as set by `self.fragment_size`  has been reached before sending the payload.

        Returns:
            (Optional[PSRPPayload]): The transport payload to send if there is one.
        """
        fragment_size = self.fragment_size - len(self._buffer)
        transport_action = self.runspace_pool.data_to_send(fragment_size)
        if not transport_action:
            return

        self._buffer += transport_action.data
        if buffer and len(self._buffer) < self.fragment_size:
            return

        transport_action = PSRPPayload(
            self._buffer,
            transport_action.stream_type,
            transport_action.pipeline_id,
        )
        self._buffer = bytearray()

        return transport_action

    def wait_event(
            self,
            pipeline_id: typing.Optional[str] = None,
            message_type: typing.Optional[PSRPMessageType] = None,
    ):
        raise NotImplementedError()

    ######################
    # Connection Methods #
    ######################

    def start(self):
        """ Starts the connection to the peer. """
        raise NotImplementedError()

    def stop(self):
        """ Stops the connection to the peer. """
        raise NotImplementedError()

    ################
    # PSRP Methods #
    ################

    def command(
            self,
            pipeline_id: str,
    ):
        return NotImplemented

    def close(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        return NotImplemented

    def create(
            self,
    ):
        return NotImplemented

    def send_all(
            self,
    ):
        while True:
            sent = self.send()
            if not sent:
                return

    def send(
            self,
            buffer: bool = False,
    ) -> bool:
        return NotImplemented

    def signal(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        return NotImplemented

    #####################
    # Optional Features #
    #####################

    def connect(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        return NotImplemented

    def disconnect(
            self,
    ):
        return NotImplemented

    def reconnect(
            self,
    ):
        return NotImplemented

    def enumerate(
            self,
            runspace_id: typing.Optional[str] = None,
    ):
        return NotImplemented


class AsyncConnectionInfo(ConnectionInfo):

    async def wait_event(
            self,
            pipeline_id: typing.Optional[str] = None,
            message_type: typing.Optional[PSRPMessageType] = None,
    ):
        raise NotImplementedError()

    async def start(self):
        """ Opens the connection to the peer. """
        raise NotImplementedError()

    async def stop(self):
        """ Closes the connection to the peer. """
        raise NotImplementedError()

    async def command(
            self,
            pipeline_id: str,
    ):
        return NotImplemented

    async def close(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        return NotImplemented

    async def create(
            self,
    ):
        return NotImplemented

    async def send_all(
            self,
    ):
        while True:
            sent = await self.send()
            if not sent:
                return

    async def send(
            self,
            buffer: bool = False,
    ) -> bool:
        return NotImplemented

    async def signal(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        return NotImplemented

    async def connect(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        return NotImplemented

    async def disconnect(
            self,
    ):
        return NotImplemented

    async def reconnect(
            self,
    ):
        return NotImplemented

    async def enumerate(
            self,
            runspace_id: typing.Optional[str] = None,
    ):
        return NotImplemented


class ProcessInfo(ConnectionInfo):

    def __init__(
            self,
            executable: str = 'pwsh',
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        super().__init__()

        self.executable = executable
        self.arguments = arguments or []
        if executable == 'pwsh' and arguments is None:
            self.arguments = ['-NoProfile', '-NoLogo', '-s']

        self._process = Process(self.executable, self.arguments)
        self._listen_task = None
        self._response_events = _MessageEvent()

    def wait_event(
            self,
            pipeline_id: typing.Optional[str] = None,
            message_type: typing.Optional[PSRPMessageType] = None,
    ):
        while True:
            try:
                return self.runspace_pool.next_event(pipeline_id=pipeline_id, message_type=message_type)
            except RunspacePoolWantRead:
                self._response_events.wait('Data', None)

    def start(self):
        self._process.open()
        self._listen_task = threading.Thread(target=self._listen)
        self._listen_task.start()

    def stop(self):
        self._process.close()
        self._listen_task.join()
        self._listen_task = None

    def close(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        self._process.write(_ps_guid_packet('Close', ps_guid=pipeline_id))
        self._response_events.wait('CloseAck', pipeline_id)

    def create(
            self,
    ):
        self.send()

    def command(
            self,
            pipeline_id: str,
    ):
        self._process.write(_ps_guid_packet('Command', ps_guid=pipeline_id))
        self._response_events.wait('CommandAck', pipeline_id)
        self.send()

    def send(
            self,
            buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        self._process.write(_ps_data_packet(payload.data, stream_type=payload.stream_type,
                                            ps_guid=payload.pipeline_id))
        self._response_events.wait('DataAck', payload.pipeline_id)

        return True

    async def signal(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        self._process.write(_ps_guid_packet('Signal', ps_guid=pipeline_id))
        self._response_events.wait('SignalAck', pipeline_id)

    def _listen(self):
        while True:
            data = self._process.read()
            if not data:
                break

            packet = ElementTree.fromstring(data)
            data = base64.b64decode(packet.text) if packet.text else None
            ps_guid = packet.attrib['PSGuid'].upper()
            if ps_guid == _EMPTY_UUID:
                ps_guid = None

            if data:
                msg = PSRPPayload(data, StreamType.default, ps_guid)
                self.runspace_pool.receive_data(msg)

            ps_guid = None if packet.tag == 'Data' else ps_guid
            self._response_events.set(packet.tag, ps_guid)


class AsyncProcessInfo(AsyncConnectionInfo):

    def __init__(
            self,
            executable: str = 'pwsh',
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        super().__init__()

        self.executable = executable
        self.arguments = arguments or []
        if executable == 'pwsh' and arguments is None:
            self.arguments = ['-NoProfile', '-NoLogo', '-s']

        self._process = AsyncProcess(self.executable, self.arguments)
        self._listen_task = None
        self._response_events = _AsyncMessageEvent()

    async def wait_event(
            self,
            pipeline_id: typing.Optional[str] = None,
            message_type: typing.Optional[PSRPMessageType] = None,
    ):
        while True:
            try:
                return self.runspace_pool.next_event(pipeline_id=pipeline_id, message_type=message_type)
            except RunspacePoolWantRead:
                await self._response_events.wait('Data', None)

    async def start(self):
        await self._process.open()
        self._listen_task = asyncio_create_task(self._listen())

    async def stop(self):
        await self._process.close()
        self._listen_task.cancel()
        self._listen_task = None

    async def close(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        await self._process.write(_ps_guid_packet('Close', ps_guid=pipeline_id))
        await self._response_events.wait('CloseAck', pipeline_id)

    async def command(
            self,
            pipeline_id: str,
    ):
        await self._process.write(_ps_guid_packet('Command', ps_guid=pipeline_id))
        await self._response_events.wait('CommandAck', pipeline_id)
        await self.send()

    async def create(
            self,
    ):
        await self.send()

    async def send(
            self,
            buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        await self._process.write(_ps_data_packet(payload.data, stream_type=payload.stream_type,
                                                  ps_guid=payload.pipeline_id))
        await self._response_events.wait('DataAck', payload.pipeline_id)

        return True

    async def signal(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        await self._process.write(_ps_guid_packet('Signal', ps_guid=pipeline_id))
        await self._response_events.wait('SignalAck', pipeline_id)

    async def _listen(self):
        while True:
            data = await self._process.read()
            if not data:
                break

            packet = ElementTree.fromstring(data)
            data = base64.b64decode(packet.text) if packet.text else None
            ps_guid = packet.attrib['PSGuid'].upper()
            if ps_guid == _EMPTY_UUID:
                ps_guid = None

            if data:
                msg = PSRPPayload(data, StreamType.default, ps_guid)
                self.runspace_pool.receive_data(msg)

            ps_guid = None if packet.tag == 'Data' else ps_guid
            await self._response_events.set(packet.tag, ps_guid)


class AsyncWSManInfo(AsyncConnectionInfo):

    def __init__(
            self,
            connection_uri,
            *args,
            **kwargs,
    ):
        super().__init__()
        # Store the args/kwargs so we can create a copy of the class.
        self.__new_args = args
        self.__new_kwargs = kwargs
        self.__new_kwargs['connection_uri'] = connection_uri

        self._connection = AsyncWSManConnection(*args, **kwargs)
        self._winrs = WinRS(WSMan(connection_uri), 'http://schemas.microsoft.com/powershell/Microsoft.PowerShell',
                            input_streams='stdin pr', output_streams='stdout')
        # FIXME: Calculate dynamically.
        self.fragment_size = 32_768

        self._receive_tasks: typing.Dict[typing.Optional[str], typing.Tuple[AsyncWSManConnection, asyncio.Task]] = {}
        self._listen_tasks: typing.List[asyncio.Task] = []
        self._response_events = _AsyncMessageEvent()

    def set_runspace_pool(
            self,
            pool: RunspacePool,
    ):
        super().set_runspace_pool(pool)

        # To support reconnection we want to make sure the WinRS shell id matches our Runspace Id.
        self._winrs.shell_id = pool.runspace_id

    async def wait_event(
            self,
            pipeline_id: typing.Optional[str] = None,
            message_type: typing.Optional[PSRPMessageType] = None,
    ) -> typing.Optional[PSRPEvent]:
        while True:
            try:
                return self.runspace_pool.next_event(pipeline_id=pipeline_id, message_type=message_type)
            except RunspacePoolWantRead:
                # Need to wait for more data to come in, if the connection was closed we return nothing.
                tasks = [
                    asyncio_create_task(self._response_events.wait('Data', pipeline_id)),
                    asyncio_create_task(self._response_events.wait('Disconnect', pipeline_id))
                ]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                [t.cancel() for t in pending]  # Make sure we cancel the pending tasks

                done = next(iter(done))
                if done == tasks[1]:
                    return

    async def start(self):
        await self._connection.open()

    async def stop(self):
        await self._connection.close()
        [t.cancel() for t in self._listen_tasks]
        self._listen_tasks = None

    async def close(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        if pipeline_id is not None:
            # TODO: This doesn't seem to be needed
            await self.signal(pipeline_id, signal_code=SignalCode.terminate)

        else:
            self._winrs.close()
            resp = await self._connection.send(self._winrs.data_to_send())
            self._winrs.receive_data(resp)

            # We don't get a RnuspacePool state change response on our receive listener so manually change the state.
            self.runspace_pool.state = RunspacePoolState.Closed

    async def command(
            self,
            pipeline_id: str,
    ):
        payload = self.next_payload()
        self._winrs.command('', args=[base64.b64encode(payload.data).decode()], command_id=pipeline_id)
        resp = await self._connection.send(self._winrs.data_to_send())
        self._winrs.receive_data(resp)

        await self._create_listener(pipeline_id)

    async def create(
            self,
    ):
        payload = self.next_payload()

        open_content = ElementTree.Element("creationXml", xmlns="http://schemas.microsoft.com/powershell")
        open_content.text = base64.b64encode(payload.data).decode()
        options = OptionSet()
        options.add_option("protocolversion", self.runspace_pool.our_capability.protocolversion,
                           {"MustComply": "true"})
        self._winrs.open(options, open_content)

        resp = await self._connection.send(self._winrs.data_to_send())
        self._winrs.receive_data(resp)

        await self._create_listener()

    async def send(
            self,
            buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        stream = 'stdin' if payload.stream_type == StreamType.default else 'pr'
        self._winrs.send(stream, payload.data, command_id=payload.pipeline_id)
        resp = await self._connection.send(self._winrs.data_to_send())
        self._winrs.receive_data(resp)

        return True

    async def signal(
            self,
            pipeline_id: typing.Optional[str] = None,
            signal_code: SignalCode = SignalCode.ps_ctrl_c,
    ):
        self._winrs.signal(signal_code, pipeline_id)
        resp = await self._connection.send(self._winrs.data_to_send())
        self._winrs.receive_data(resp)

    async def connect(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        rsp = NAMESPACES['rsp']
        connect = ElementTree.Element('{%s}Connect' % rsp)
        if pipeline_id:
            connect.attrib['CommandId'] = pipeline_id
            options = None

        else:
            payload = self.next_payload()

            options = OptionSet()
            options.add_option('protocolversion', self.runspace_pool.our_capability.protocolversion,
                               {'MustComply': 'true'})

            open_content = ElementTree.SubElement(connect, 'connectXml', xmlns='http://schemas.microsoft.com/powershell')
            open_content.text = base64.b64encode(payload.data).decode()

        self._winrs.wsman.connect(self._winrs.resource_uri, connect, option_set=options,
                                  selector_set=self._winrs.selector_set)
        resp = await self._connection.send(self._winrs.data_to_send())
        event = self._winrs.wsman.receive_data(resp)

        if not pipeline_id:
            response_xml = event.body.find('rsp:ConnectResponse/pwsh:connectResponseXml', NAMESPACES).text

            psrp_resp = PSRPPayload(base64.b64decode(response_xml), StreamType.default, None)
            self.runspace_pool.receive_data(psrp_resp)

        await self._create_listener(pipeline_id=pipeline_id)

    async def disconnect(
            self,
            buffer_mode: OutputBufferingMode = OutputBufferingMode.none,
            idle_timeout: typing.Optional[typing.Union[int, float]] = None
    ):
        rsp = NAMESPACES['rsp']

        disconnect = ElementTree.Element('{%s}Disconnect' % rsp)
        if buffer_mode != OutputBufferingMode.none:
            buffer_mode_str = 'Block' if buffer_mode == OutputBufferingMode.block else 'Drop'
            ElementTree.SubElement(disconnect, '{%s}BufferMode' % rsp).text = buffer_mode_str

        if idle_timeout:
            idle_str = f'PT{idle_timeout}S'
            ElementTree.SubElement(disconnect, '{%s}IdleTimeout' % rsp).text = idle_str

        self._winrs.wsman.disconnect(self._winrs.resource_uri, disconnect, selector_set=self._winrs.selector_set)
        resp = await self._connection.send(self._winrs.data_to_send())
        self._winrs.receive_data(resp)

    async def reconnect(
            self,
    ):
        self._winrs.wsman.reconnect(self._winrs.resource_uri, selector_set=self._winrs.selector_set)
        resp = await self._connection.send(self._winrs.data_to_send())
        self._winrs.receive_data(resp)

    async def enumerate(
            self,
            runspace_id: typing.Optional[str] = None,
    ) -> typing.AsyncIterable[typing.Tuple[str, typing.List[str], 'AsyncWSManInfo']]:
        self._winrs.enumerate()
        resp = await self._connection.send(self._winrs.data_to_send())
        shell_enumeration = self._winrs.receive_data(resp)

        for winrs in shell_enumeration.shells:
            winrs.enumerate('http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command', winrs.selector_set)
            resp = await self._connection.send(self._winrs.data_to_send())
            cmd_enumeration = self._winrs.receive_data(resp)

            connection = AsyncWSManInfo(*self.__new_args, **self.__new_kwargs)
            connection._winrs = winrs

            yield winrs.shell_id, cmd_enumeration.commands, connection

    async def _create_listener(
            self,
            pipeline_id: typing.Optional[str] = None,
    ):
        started = asyncio.Event()
        task = asyncio_create_task(self._listen(started, pipeline_id))
        self._listen_tasks.append(task)
        await started.wait()

    async def _listen(
            self,
            started: asyncio.Event,
            pipeline_id: typing.Optional[str] = None,
    ):
        while True:
            self._winrs.receive('stdout', command_id=pipeline_id)

            resp = await self._connection.send(self._winrs.data_to_send())
            # TODO: Will the ReceiveResponse block if not all the fragments have been sent?
            started.set()

            try:
                event: ReceiveResponseEvent = self._winrs.receive_data(resp)

            except OperationTimedOut:
                # Occurs when there has been no output after the OperationTimeout set, just repeat the request
                continue

            except (OperationAborted, ServiceStreamDisconnected) as e:
                # Received when the shell has been closed
                await self._response_events.set('Disconnect', pipeline_id)
                break

            for psrp_data in event.get_streams().get('stdout', []):
                msg = PSRPPayload(psrp_data, StreamType.default, pipeline_id)
                self.runspace_pool.receive_data(msg)

            await self._response_events.set('Data', pipeline_id)

            # If the command is done then we've got nothing left to do here.
            # TODO: do we need to surface the exit_code into the protocol.
            if event.command_state == CommandState.done:
                break


_EMPTY_UUID = '00000000-0000-0000-0000-000000000000'


def _ps_data_packet(
        data: bytes,
        stream_type: StreamType = StreamType.default,
        ps_guid: typing.Optional[str] = None
) -> bytes:
    """Data packet for PSRP fragments

    This creates a data packet that is used to encode PSRP fragments when sending to the server.

    Args:
        data: The PSRP fragments to encode.
        stream_type: The stream type to target, Default or PromptResponse.
        ps_guid: Set to `None` or a 0'd UUID to target the RunspacePool, otherwise this should be the pipeline UUID.

    Returns:
        bytes: The encoded data XML packet.
    """
    ps_guid = ps_guid or _EMPTY_UUID
    stream_name = b'Default' if stream_type == StreamType.default else b'PromptResponse'
    return b"<Data Stream='%s' PSGuid='%s'>%s</Data>\n" % (stream_name, ps_guid.encode(), base64.b64encode(data))


def _ps_guid_packet(
        element: str,
        ps_guid: typing.Optional[str] = None,
) -> bytes:
    """Common PSGuid packet for PSRP message.

    This creates a PSGuid packet that is used to signal events and stages in the PSRP exchange. Unlike the data
    packet this does not contain any PSRP fragments.

    Args:
        element: The element type, can be DataAck, Command, CommandAck, Close, CloseAck, Signal, and SignalAck.
        ps_guid: Set to `None` or a 0'd UUID to target the RunspacePool, otherwise this should be the pipeline UUID.

    Returns:
        bytes: The encoded PSGuid packet.
    """
    ps_guid = ps_guid or _EMPTY_UUID
    return b"<%s PSGuid='%s' />\n" % (element.encode(), ps_guid.encode())
