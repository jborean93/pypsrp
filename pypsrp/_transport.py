# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import abc
import asyncio
import base64
import enum
import typing
import xml.etree.ElementTree as ElementTree

from pypsrp.exceptions import (
    WSManFaultError,
)

from pypsrp.wsman import (
    AsyncWSMan,
    NAMESPACES,
    OptionSet,
)

from pypsrp.out_of_process import (
    PowerShellProcess,
)

from pypsrp.shell import (
    AsyncWinRS,
    SignalCode,
)


EMPTY_UUID = '00000000-0000-0000-0000-000000000000'


class StreamType(enum.Enum):
    Default = enum.auto()
    PromptResponse = enum.auto()


class MessageQueue:
    """ Asyncio queue that allows the caller to wait and put messages based on a unique identifier. """

    def __init__(self):
        self._queue = {}
        self._queue_lock = asyncio.Lock()

    async def get(
            self,
            identifier: typing.Union[str, int],
    ) -> typing.Any:
        return await (await self._get_queue(identifier)).get()

    async def put(
            self,
            identifier: typing.Union[str, int],
            data: typing.Any,
    ):
        message_queue = await self._get_queue(identifier)
        message_queue.put_nowait(data)

    async def _get_queue(
            self,
            identifier: typing.Union[str, int],
    ) -> asyncio.Queue:
        async with self._queue_lock:
            if identifier not in self._queue:
                self._queue[identifier] = asyncio.Queue()

        return self._queue[identifier]


class BaseTransport(metaclass=abc.ABCMeta):
    """Abstract Base Class for PSRP transport.

    The abstract base class that defines the properties and functions that are required for the PSRP client to send
    and receive PSRP messages.

    Args:
        connection: The underlying connection for the transport.
    """

    def __init__(
            self,
            connection: typing.Union[AsyncWSMan, PowerShellProcess],
    ):
        self.connection = connection
        self._managed_connection = not self.is_alive

    async def __aenter__(self):
        # PSRP client creates multiple copies of the transport for each runspace and pipeline. The default behaviour is
        # to share the same listener for each and allowing the transport to override and handle the opening and closing
        # if needed (WSMan).
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    @property
    def managed_connection(self) -> bool:
        """ Whether the connection needs to be opened/closed by the Runspace (True) or by the caller (False). """
        return self._managed_connection

    def copy(self) -> 'BaseTransport':
        """ Create a copy of the transport. """
        return self  # Default is to not have a copy for each runspace/pipeline.

    @property
    @abc.abstractmethod
    def is_alive(self) -> bool:
        """ Whether the connection is still alive or not. """
        pass

    @property
    @abc.abstractmethod
    def max_fragment_size(self) -> int:
        """ The maximum fragment size for each PSRP fragment. """
        pass

    ##########################
    # PSRP operation methods #
    ##########################

    @abc.abstractmethod
    async def close(self):
        """ Close the RunspacePool. """
        pass

    @abc.abstractmethod
    async def command(
            self,
            data: bytes,
            ps_guid: str,
    ) -> str:
        """ Create a PowerShell pipeline. """
        pass

    @abc.abstractmethod
    async def connect(self):
        """ Connect to a disconnected Runspace. """
        raise NotImplementedError("Transport %s does not support Runspace connections" % type(self).__name__)

    @abc.abstractmethod
    async def create(
            self,
            data: bytes,
            protocol_version: str,
    ):
        """ Create the RunspacePool. """
        pass

    @abc.abstractmethod
    async def disconnect(self):
        """ Disconnect from the Runspace. """
        raise NotImplementedError("Transport %s does not support Runspace disconnections" % type(self).__name__)

    @abc.abstractmethod
    async def send(
            self,
            data: bytes,
            stream_type: StreamType = StreamType.Default,
            ps_guid: str = None,
    ):
        """ Send data to the RunspacePool/Pipeline. """
        pass

    @abc.abstractmethod
    async def receive(
            self,
            ps_guid: str = None,
    ) -> typing.Optional[bytes]:
        """ Receive data from the RunspacePool/Pipeline. """
        pass

    @abc.abstractmethod
    async def signal(
            self,
            ps_guid: str
    ):
        """ Send the stop/ctrl+c signal to the Pipeline. """
        pass

    ###############################
    # Connection abstract methods #
    ###############################

    @abc.abstractmethod
    async def start(self):
        """ Starting the underlying connection. """
        pass

    @abc.abstractmethod
    async def stop(self):
        """ Stopping the underlying connection. """
        pass


class OutOfProcTransport(BaseTransport):
    """ Transport implementation for Out of Process connections. """

    def __init__(
            self,
            connection: PowerShellProcess,
    ):
        super().__init__(connection)

        self._response_queue = MessageQueue()
        self._response_task = None

    @property
    def is_alive(self) -> bool:
        return self.connection.running

    @property
    def max_fragment_size(self) -> int:
        # Fragment size is based on the named pipe buffer size of 32KiB.
        # https://github.com/PowerShell/PowerShell/blob/0d5d017f0f1d89a7de58d217fa9f4a37ad62cc94/src/System.Management.Automation/engine/remoting/common/RemoteSessionNamedPipe.cs#L355
        return 32768

    async def close(self):
        await self.connection.write(ps_guid_packet('Close'))
        # TODO: Check this out.
        # await self._response_queue.get('CloseAck:')

        await self.stop()

    async def command(
            self,
            data: bytes,
            ps_guid: str,
    ) -> str:
        await self.connection.write(ps_guid_packet('Command', ps_guid=ps_guid))
        # TODO: Verify what happens with a smaller fragment that doesn't fit all pipeline info
        await self._response_queue.get('CommandAck:%s' % ps_guid)

        await self.connection.write(ps_data_packet(data, ps_guid=ps_guid))
        await self._response_queue.get('DataAck:%s' % ps_guid)

        return ps_guid

    async def connect(self):
        await super().connect()

    async def create(
            self,
            data: bytes,
            protocol_version: str,  # Unused for OutOfProcess connections.
    ):
        await self.start()
        await self.send(data)

        # TODO: Verify if DataAck gets sent on the first Data transmision or not.
        await self._response_queue.get('DataAck:')

    async def disconnect(self):
        await super().disconnect()

    async def send(
            self,
            data: bytes,
            stream_type: StreamType = StreamType.Default,
            ps_guid: str = None,
    ):
        await self.connection.write(ps_data_packet(data, stream_type=stream_type, ps_guid=ps_guid))

    async def receive(
            self,
            ps_guid: str = None,
    ) -> typing.Optional[bytes]:
        return await self._response_queue.get('Data:%s' % (ps_guid or '',))

    async def signal(
            self,
            ps_guid: str
    ):
        await self.connection.write(ps_guid_packet('Signal', ps_guid=ps_guid))
        await self._response_queue.get('SignalAck:%s' % ps_guid)

    async def start(self):
        if self.managed_connection:
            await self.connection.open()

        self._response_task = asyncio.create_task(self._response_listener())

    async def stop(self):
        if self.managed_connection:
            await self.connection.close()

        if self._response_task:
            self._response_task.cancel()
            self._response_task = None

    async def _response_listener(self):
        while True:
            data = await self.connection.read()
            if not data:
                break

            packet = ElementTree.fromstring(data)
            print("Received packet %s" % data)

            data = base64.b64decode(packet.text) if packet.text else None
            ps_guid = packet.attrib['PSGuid'].upper()
            if ps_guid == EMPTY_UUID:
                ps_guid = None

            key = '%s:%s' % (packet.tag, ps_guid or '')
            await self._response_queue.put(key, data)


class WSManTransport(BaseTransport):
    """ Transport implementation for WSMan connections. """

    def __init__(
            self,
            connection: AsyncWSMan,
            configuration_name: str,
            runspace_id: str,
    ):
        super().__init__(connection)

        self._runspace_id = runspace_id
        self._configuration_name = configuration_name

        resource_uri = "http://schemas.microsoft.com/powershell/%s" % configuration_name
        self.shell = AsyncWinRS(connection, resource_uri=resource_uri, id=runspace_id, input_streams='stdin pr',
                                output_streams='stdout')

    async def __aenter__(self):
        # Because .copy() returns a new instance we want the PSRP listener task to actually start and stop the
        # connections using the context manager.
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    @property
    def is_alive(self) -> bool:
        return self.connection.opened

    @property
    def max_fragment_size(self) -> int:
        return self.connection.max_payload_size

    async def close(self):
        await self.shell.close()
        await self.stop()

    def copy(self):
        # WSMan connections need a brand new connection for each PSRP listener task. This creates a new transport with
        # a brand new connection but using the same WinRS shell details.

        # NOTE: .copy() is added dynamically on the WSMan instance
        # noinspection PyUnresolvedReferences
        copied_connection = self.connection.copy()

        new_instance = WSManTransport(copied_connection, self._configuration_name, self._runspace_id)
        # TODO: Find a better way to preserve these 2 values.
        new_instance.shell.id = self.shell.id
        new_instance.shell._selector_set = self.shell._selector_set

        return new_instance

    async def command(
            self,
            data: bytes,
            ps_guid: str,
    ) -> str:
        encoded_data = base64.b64encode(data).decode('utf-8')
        resp = await self.shell.command('', arguments=[encoded_data], command_id=ps_guid)

        # The command returned by WinRS may be different from the PSGuid of the pipeline.
        cmd_id = resp.find("rsp:CommandResponse/rsp:CommandId", NAMESPACES)
        if cmd_id is not None:
            ps_guid = cmd_id.text

        return ps_guid

    async def connect(self):
        pass

    async def create(
            self,
            data: bytes,
            protocol_version: str,
    ):
        await self.start()

        open_content = ElementTree.Element("creationXml", xmlns="http://schemas.microsoft.com/powershell")
        open_content.text = base64.b64encode(data).decode('utf-8')
        options = OptionSet()
        options.add_option("protocolversion", protocol_version, {"MustComply": "true"})

        await self.shell.open(options, open_content)

    async def disconnect(self):
        pass

    async def send(
            self,
            data: bytes,
            stream_type: StreamType = StreamType.Default,
            ps_guid: str = None,
    ):
        pipe_name = 'stdin' if stream_type == StreamType.Default else 'pr'

        await self.shell.send(pipe_name, data, command_id=ps_guid)

    async def receive(
            self,
            ps_guid: str = None,
    ) -> typing.Optional[bytes]:

        try:
            raw_response = await self.shell.receive('stdout', command_id=ps_guid)
        except WSManFaultError as exc:
            # if a command exceeds the OperationTimeout set, we will get
            # a WSManFaultError with the code 2150858793. We ignore this
            # as it just meant no output during that operation.
            if exc.code == 2150858793:
                return

            elif exc.code == 995:  # Shell has been closed
                return

            elif exc.code == 2150858843:  # The shell was not found (deleted)
                return

            raise exc

        responses = b"".join(raw_response[2].get('stdout', []))

        return responses

    async def signal(
            self,
            ps_guid: str
    ):
        await self.shell.signal(SignalCode.PS_CTRL_C, ps_guid)

    async def start(self):
        if self.managed_connection and not self.is_alive:
            await self.connection.open()

    async def stop(self):
        if self.managed_connection and self.is_alive:
            await self.connection.close()


def ps_data_packet(
        data: bytes,
        stream_type: StreamType = StreamType.Default,
        ps_guid: typing.Optional[str] = None
) -> bytes:
    """Data packet for PSRP fragments

    This creates a data packet that is used to encode PSRP fragments when sending to the server.

    Args:
        data: The PSRP fragments to encode.
        stream_type: The stream type to target, Default or PromptResponse.
        ps_guid: Set to `None` or a 0'd UUID to target the runspace, otherwise this should be the pipeline UUID.

    Returns:
        bytes: The encoded data XML packet.
    """
    ps_guid = ps_guid or EMPTY_UUID
    return b"<Data Stream='%s' PSGuid='%s'>%s</Data>\n" % (stream_type.name.encode(), ps_guid.encode(),
                                                           base64.b64encode(data))


def ps_guid_packet(
        element: str,
        ps_guid: typing.Optional[str] = None,
) -> bytes:
    """Common PSGuid packet for PSRP message.

    This creates a PSGuid packet that is used to signal events and stages in the PSRP exchange. Unlike the data
    packet this does not contain any PSRP fragments.

    Args:
        element: The element type, can be DataAck, Command, CommandAck, Close, CloseAck, Signal, and SignalAck.
        ps_guid: Set to `None` or a 0'd UUID to target the runspace, otherwise this should be the pipeline UUID.

    Returns:
        bytes: The encoded PSGuid packet.
    """
    ps_guid = ps_guid or EMPTY_UUID
    return b"<%s PSGuid='%s' />\n" % (element.encode(), ps_guid.encode())


def select_transport(
        connection: typing.Union[AsyncWSMan, PowerShellProcess],
        configuration_name: str,
        runspace_id: str,
) -> BaseTransport:
    """Get the transport class for the connection specified.

    This creates the BaseTransport compatible class based on the underlying connection specified. The BaseTransport
    class is designed to unify the varies connection interfaces to a common one that the PSRP client understands.

    Args:
        connection: The underlying connection to connect with.
        configuration_name: The PSSession configuration name to connect to, only used with WSMan connections.
        runspace_id: The RunspacePool UUID.

    Returns:
        BaseTransport: A class that implements the required methods and properties that the PSRP client can use to
            manage a RunspacePool and Pipeline.
    """
    # TODO: Support connection detail classes and have this manage the connection instead.
    if isinstance(connection, AsyncWSMan):
        return WSManTransport(connection, configuration_name, runspace_id)

    elif isinstance(connection, PowerShellProcess):
        return OutOfProcTransport(connection)

    else:
        raise ValueError("Unsupported connection type %s" % type(connection).__name__)
