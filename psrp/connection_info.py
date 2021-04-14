# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import enum
import queue
import threading
import typing
import xml.etree.ElementTree as ElementTree

from ._compat import (
    asyncio_create_task,
)

from .dotnet.complex_types import (
    RunspacePoolState,
)

from .exceptions import (
    OperationAborted,
    OperationTimedOut,
    ServiceStreamDisconnected,
)

from .io.process import (
    AsyncProcess,
    Process,
)

from .io.ssh import (
    AsyncSSH,
    SSH,
)

from .io.wsman import (
    AsyncWSManConnection,
    WSManConnection,
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


class _ConnectionInfoBase:

    def __new__(cls, *args, **kwargs):
        if cls in [_ConnectionInfoBase, ConnectionInfo, AsyncConnectionInfo, OutOfProcInfo, AsyncOutOfProcInfo]:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'PSRP connection implementations.')

        return super().__new__(cls)

    def __init__(
            self,
    ):
        self._buffer: typing.Dict[str, bytearray] = {}

    def get_fragment_size(
            self,
            pool: RunspacePool,
    ) -> int:
        """Get the max PSRP fragment size.

        Gets the maximum size allowed for PSRP fragments in this Runspace Pool.

        Returns:
            int: The max fragment size.
        """
        return 32_768

    def next_payload(
            self,
            pool: RunspacePool,
            buffer: bool = False,
    ) -> typing.Optional[PSRPPayload]:
        """Get the next payload.

        Get the next payload to exchange if there are any.

        Args:
            pool: The Runspace Pool to get the next payload for.
            buffer: Wait until the buffer as set by `self.fragment_size` has
                been reached before sending the payload.

        Returns:
            Optional[PSRPPayload]: The transport payload to send if there is
                one.
        """
        pool_buffer = self._buffer.setdefault(pool.runspace_id, bytearray())
        fragment_size = self.get_fragment_size(pool)
        psrp_payload = pool.data_to_send(fragment_size - len(pool_buffer))
        if not psrp_payload:
            return

        pool_buffer += psrp_payload.data
        if buffer and len(pool_buffer) < fragment_size:
            return

        # No longer need the buffer for now
        del self._buffer[pool.runspace_id]
        return PSRPPayload(
            pool_buffer,
            psrp_payload.stream_type,
            psrp_payload.pipeline_id,
        )

    ################
    # PSRP Methods #
    ################

    def close(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        """Close the Runspace Pool/Pipeline.

        Closes the Runspace Pool or Pipeline inside the Runspace Pool. This
            should also close the underlying connection if no more resources
            are being used.

        Args:
            pool: The Runspace Pool to close.
            pipeline_id: Closes this pipeline in the Runspace Pool.
        """
        raise NotImplementedError()

    def command(
            self,
            pool: RunspacePool,
            pipeline_id: str,
    ):
        """Create the pipeline.

        Creates a pipeline in the Runspace Pool. This should send the first
        fragment of the
        :class:`CreatePipeline <psrp.dotnet.psrp_messages.CreatePipeline>` PSRP
        message.

        Args:
            pool: The Runspace Pool to create the pipeline in.
            pipeline_id: The Pipeline ID that needs to be created.
        """
        raise NotImplementedError()

    def create(
            self,
            pool: RunspacePool,
    ):
        """Create the Runspace Pool

        Creates the Runspace Pool specified. This should send only one fragment
        that contains at least the
        :class:`SessionCapability <psrp.dotnet.psrp_messages.SessionCapability>`
        PSRP message. The underlying connection should also be done if not
        already done so.

        Args:
            pool: The Runspace Pool to create.
        """
        raise NotImplementedError()

    def send_all(
            self,
            pool: RunspacePool,
    ):
        """Send all PSRP payloads.

        Send all PSRP payloads that are ready to send.

        Args:
            pool: The Runspace Pool to send all payloads to.
        """
        while True:
            sent = self.send(pool)
            if not sent:
                return

    def send(
            self,
            pool: RunspacePool,
            buffer: bool = False,
    ) -> bool:
        """Send PSRP payload.

        Send the next PSRP payload for the Runspace Pool.

        Args:
            pool: The Runspace Pool to send the payload to.
            buffer: When set to `False` will always send the payload regardless
                of the size. When set to `True` will only send the payload if
                it hits the max fragment size.

        Returns:
            bool: Set to `True` if a payload was sent and `False` if there was
                no payloads for the pool to send.
        """
        raise NotImplementedError()

    def signal(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        """Send a signal to the Runspace Pool/Pipeline

        Sends a signal to the Runspace Pool or Pipeline. Currently PSRP only
        uses a signal to a Pipeline to ask the server to stop.

        Args:
            pool: The Runspace Pool that contains the pipeline to signal.
            pipeline_id: The pipeline to send the signal to.
        """
        raise NotImplementedError()

    #####################
    # Optional Features #
    #####################

    def connect(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        """Connect to a Runspace Pool/Pipeline.

        Connects to a Runspace Pool or Pipeline that has been disconnected by
        another client. This is an optional feature that does not have to be
        implemented for the core PSRP scenarios.

        Args:
            pool: The Runspace Pool to connect to.
            pipeline_id: If connecting to a pipeline, this is the pipeline id.
        """
        raise NotImplementedError()

    def disconnect(
            self,
            pool: RunspacePool,
    ):
        """Disconnect a Runspace Pool.

        Disconnects from a Runspace Pool so another client can connect to it.
        This is an optional feature that does not have to be implemented for
        the core PSRP scenarios.

        Args:
            pool: The Runspace Pool to disconnect.
        """
        raise NotImplementedError()

    def reconnect(
            self,
            pool: RunspacePool,
    ):
        """Reconnect a Runspace Pool.

        Reconnect to a Runspace Pool that has been disconnected by the same
        client. This is an optional feature that does not have to be
        implemented for the core PSRP scenarios.

        Args:
            pool: The Runspace Pool to disconnect.
        """
        raise NotImplementedError()

    def enumerate(self) -> typing.Iterable[typing.Tuple[str, typing.List[str]]]:
        """Find Runspace Pools or Pipelines.

        Find all the Runspace Pools or Pipelines on the connection. This is
        used to enumerate any disconnected Runspace Pools or Pipelines for
        `:meth:connect()` and `:meth:reconnect()`. This is an optional feature
        that does not have to be implemented for the core PSRP scenarios.

        Returns:
            Iterable[Tuple[str, List[str]]]: Will yield tuples that contains
                the Runspace Pool ID with a list of all the pipeline IDs for
                that Runspace Pool.
        """
        raise NotImplementedError()


class ConnectionInfo(_ConnectionInfoBase):

    def __init__(
            self,
    ):
        super().__init__()

        self._data_queue: typing.Dict[str, queue.Queue] = {}
        self._queue_lock = threading.Lock()

    def queue_response(
            self,
            runspace_pool_id: str,
            data: typing.Optional[bytes] = None,
    ):
        """Queue received data.

        Queues the data received from the peer into the internal message queue
        for later processing. It is up to the implementing class to retrieve
        the data and queue it.

        Args:
            runspace_pool_id: The Runspace Pool ID the data is associated with.
            data: The data to queue, can be set to `None` to indicate no more
                data is expected.
        """
        data_queue = self._get_pool_queue(runspace_pool_id)
        data_queue.put(data)

    def wait_event(
            self,
            pool: RunspacePool,
    ) -> typing.Optional[PSRPEvent]:
        """Get the next PSRP event.

        Get the next PSRP event generated from the responses of the peer. It is
        up to the implementing class to retrieve the data and queue it so
        events can be generated.

        Args:
            pool: The Runspace Pool to get the next event for.

        Returns:
            Optional[PSRPEvent]: The PSRPEvent or `None` if the Runspace Pool
                has been closed with no more events expected.
        """
        while True:
            event = pool.next_event()
            if event:
                return event

            data_queue = self._get_pool_queue(pool.runspace_id)
            msg = data_queue.get()
            if msg is None:
                return
            pool.receive_data(msg)

    def _get_pool_queue(
            self,
            runspace_pool_id: str,
    ):
        runspace_pool_id = runspace_pool_id.lower()

        with self._queue_lock:
            self._data_queue.setdefault(runspace_pool_id, queue.Queue())

        return self._data_queue[runspace_pool_id]


class AsyncConnectionInfo(_ConnectionInfoBase):

    def __init__(
            self,
    ):
        super().__init__()
        self._data_queue: typing.Dict[str, asyncio.Queue] = {}
        self._queue_lock = asyncio.Lock()

    async def queue_response(
            self,
            runspace_pool_id: str,
            data: typing.Optional[PSRPPayload] = None,
    ):
        data_queue = await self._get_pool_queue(runspace_pool_id)
        await data_queue.put(data)

    async def wait_event(
            self,
            pool: RunspacePool,
    ) -> typing.Optional[PSRPEvent]:
        while True:
            event = pool.next_event()
            if event:
                return event

            data_queue = await self._get_pool_queue(pool.runspace_id)
            msg = await data_queue.get()
            if msg is None:
                return
            pool.receive_data(msg)

    async def _get_pool_queue(
            self,
            runspace_pool_id: str,
    ):
        runspace_pool_id = runspace_pool_id.lower()

        async with self._queue_lock:
            self._data_queue.setdefault(runspace_pool_id, asyncio.Queue())

        return self._data_queue[runspace_pool_id]

    async def close(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        raise NotImplementedError()

    async def command(
            self,
            pool: RunspacePool,
            pipeline_id: str,
    ):
        raise NotImplementedError()

    async def create(
            self,
            pool: RunspacePool,
    ):
        raise NotImplementedError()

    async def send_all(
            self,
            pool: RunspacePool,
    ):
        while True:
            sent = await self.send(pool)
            if not sent:
                return

    async def send(
            self,
            pool: RunspacePool,
            buffer: bool = False,
    ) -> bool:
        raise NotImplementedError()

    async def signal(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        raise NotImplementedError()

    async def connect(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        raise NotImplementedError()

    async def disconnect(
            self,
            pool: RunspacePool,
    ):
        raise NotImplementedError()

    async def reconnect(
            self,
            pool: RunspacePool,
    ):
        raise NotImplementedError()

    async def enumerate(self) -> typing.AsyncIterable[typing.Tuple[str, typing.List[str]]]:
        raise NotImplementedError()


class OutOfProcInfo(ConnectionInfo):

    def __init__(
            self,
    ):
        super().__init__()

        self._runspace_pool = None
        self._listen_task = None
        self._wait_condition = threading.Condition()
        self._wait_table: typing.List[str] = []

    #####################
    # OutOfProc Methods #
    #####################

    def read(self) -> bytes:
        """Get the response data.

        Called by the background thread to read any responses from the peer.
        This should block until data is available.

        Returns:
            bytes: The raw response from the peer.
        """
        raise NotImplementedError()

    def write(
            self,
            data: bytes,
    ):
        """Write data.

        Write a request to send to the peer.

        Args:
            data: The data to write.
        """
        raise NotImplementedError()

    def start(self):
        """Start the connection.

        Starts the connection to the peer so it is ready to read and write to.
        """
        raise NotImplementedError()

    def stop(self):
        """Stop the connection.

        Stops the connection to the peer once the Runspace Pool has been
        closed.
        """
        raise NotImplementedError()

    def close(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        with self._wait_condition:
            self.write(_ps_guid_packet('Close', ps_guid=pipeline_id))
            self._wait_ack('Close', pipeline_id)

        if not pipeline_id:
            self.stop()
            self._listen_task.join()
            self._listen_task = None
            self._runspace_pool = None

    def command(
            self,
            pool: RunspacePool,
            pipeline_id: str,
    ):
        with self._wait_condition:
            self.write(_ps_guid_packet('Command', ps_guid=pipeline_id))
            self._wait_ack('Command', pipeline_id)

        self.send(pool)

    def create(
            self,
            pool: RunspacePool,
    ):
        if self._runspace_pool:
            raise Exception('Cannot open a new pool on the same connection')

        self._runspace_pool = pool
        self.start()
        self._listen_task = threading.Thread(target=self._listen)
        self._listen_task.start()

        self.send(pool)

    def send(
            self,
            pool: RunspacePool,
            buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(pool, buffer=buffer)
        if not payload:
            return False

        with self._wait_condition:
            self.write(_ps_data_packet(payload.data, stream_type=payload.stream_type,
                                       ps_guid=payload.pipeline_id))
            self._wait_ack('Data', payload.pipeline_id)

        return True

    def signal(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        with self._wait_condition:
            self.write(_ps_guid_packet('Signal', ps_guid=pipeline_id))
            self._wait_ack('Signal', pipeline_id)

    def _wait_ack(
            self,
            action: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        key = f'{action}Ack:{pipeline_id or ""}'
        self._wait_table.append(key)
        self._wait_condition.wait_for(lambda: key not in self._wait_table)

    def _listen(self):
        while True:
            data = self.read()
            if not data:
                break

            packet = ElementTree.fromstring(data)
            data = base64.b64decode(packet.text) if packet.text else None
            ps_guid = packet.attrib['PSGuid'].upper()
            if ps_guid == _EMPTY_UUID:
                ps_guid = None

            if data:
                data = PSRPPayload(data, StreamType.default, ps_guid)

            tag = packet.tag
            if tag == 'Data':
                self.queue_response(self._runspace_pool.runspace_id, data)

            else:
                with self._wait_condition:
                    self._wait_table.remove(f'{tag}:{ps_guid or ""}')
                    self._wait_condition.notify_all()

        self.queue_response(self._runspace_pool.runspace_id, None)


class AsyncOutOfProcInfo(AsyncConnectionInfo):

    def __init__(
            self,
    ):
        super().__init__()

        self._runspace_pool = None
        self._listen_task = None
        self._wait_condition = asyncio.Condition()
        self._wait_table: typing.List[str] = []

    #####################
    # OutOfProc Methods #
    #####################

    async def read(self) -> bytes:
        """Get the response data.

        Called by the background thread to read any responses from the peer.
        This should block until data is available.

        Returns:
            bytes: The raw response from the peer.
        """
        raise NotImplementedError()

    async def write(
            self,
            data: bytes,
    ):
        """Write data.

        Write a request to send to the peer.

        Args:
            data: The data to write.
        """
        raise NotImplementedError()

    async def start(self):
        """Start the connection.

        Starts the connection to the peer so it is ready to read and write to.
        """
        raise NotImplementedError()

    async def stop(self):
        """Stop the connection.

        Stops the connection to the peer once the Runspace Pool has been
        closed.
        """
        raise NotImplementedError()

    async def close(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        async with self._wait_condition:
            await self.write(_ps_guid_packet('Close', ps_guid=pipeline_id))
            await self._wait_ack('Close', pipeline_id)

        if not pipeline_id:
            await self.stop()
            await self._listen_task
            self._listen_task = None
            self._runspace_pool = None

    async def command(
            self,
            pool: RunspacePool,
            pipeline_id: str,
    ):
        async with self._wait_condition:
            await self.write(_ps_guid_packet('Command', ps_guid=pipeline_id))
            await self._wait_ack('Command', pipeline_id)

        await self.send(pool)

    async def create(
            self,
            pool: RunspacePool,
    ):
        if self._runspace_pool:
            raise Exception('Cannot open a new pool on the same connection')

        self._runspace_pool = pool
        await self.start()
        self._listen_task = asyncio_create_task(self._listen())

        await self.send(pool)

    async def send(
            self,
            pool: RunspacePool,
            buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(pool, buffer=buffer)
        if not payload:
            return False

        async with self._wait_condition:
            await self.write(_ps_data_packet(payload.data, stream_type=payload.stream_type,
                                             ps_guid=payload.pipeline_id))
            await self._wait_ack('Data', payload.pipeline_id)

        return True

    async def signal(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        async with self._wait_condition:
            await self.write(_ps_guid_packet('Signal', ps_guid=pipeline_id))
            await self._wait_ack('Signal', pipeline_id)

    async def _wait_ack(
            self,
            action: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        key = f'{action}Ack:{pipeline_id or ""}'
        self._wait_table.append(key)
        await self._wait_condition.wait_for(lambda: key not in self._wait_table)

    async def _listen(self):
        while True:
            data = await self.read()
            if not data:
                break

            packet = ElementTree.fromstring(data)
            data = base64.b64decode(packet.text) if packet.text else None
            ps_guid = packet.attrib['PSGuid'].upper()
            if ps_guid == _EMPTY_UUID:
                ps_guid = None

            if data:
                data = PSRPPayload(data, StreamType.default, ps_guid)

            tag = packet.tag
            if tag == 'Data':
                await self.queue_response(self._runspace_pool.runspace_id, data)

            else:
                async with self._wait_condition:
                    self._wait_table.remove(f'{tag}:{ps_guid or ""}')
                    self._wait_condition.notify_all()

        await self.queue_response(self._runspace_pool.runspace_id, None)


class ProcessInfo(OutOfProcInfo):
    """ConnectionInfo for a Process.

    ConnectionInfo implementation for a native process. The data is read from
    the ``stdout`` pipe of the process and the input is read to the ``stdin``
    pipe. This can be used to create a Runspace Pool on a local PowerShell
    instance or any other process that can handle the raw PSRP OutOfProc
    messages.

    Args:
        executable: The executable to run, defaults to `pwsh`.
        arguments: A list of arguments to run, when the executable is `pwsh`
            then this defaults to `-NoProfile -NoLogo -s`.
    """

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

    def read(self) -> bytes:
        return self._process.read()

    def write(
            self,
            data: bytes,
    ):
        self._process.write(data)

    def start(self):
        self._process.open()

    def stop(self):
        self._process.close()


class AsyncProcessInfo(AsyncOutOfProcInfo):
    """Async ConnectionInfo for a Process.

    Async ConnectionInfo implementation for a native process. The data is read
    from the ``stdout`` pipe of the process and the input is read to the
    ``stdin`` pipe. This can be used to create a Runspace Pool on a local
    PowerShell instance or any other process that can handle the raw PSRP
    OutOfProc messages.

    Args:
        executable: The executable to run, defaults to `pwsh`.
        arguments: A list of arguments to run, when the executable is `pwsh`
            then this defaults to `-NoProfile -NoLogo -s`.
    """

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

    async def read(self) -> bytes:
        return await self._process.read()

    async def write(
            self,
            data: bytes,
    ):
        await self._process.write(data)

    async def start(self):
        await self._process.open()

    async def stop(self):
        await self._process.close()


class AsyncSSHInfo(AsyncOutOfProcInfo):

    def __init__(
            self,
            hostname: str,
            port: int = 22,
            username: typing.Optional[str] = None,
            password: typing.Optional[str] = None,
            subsystem: str = 'powershell',
            executable: typing.Optional[str] = None,
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        super().__init__()
        self._ssh = AsyncSSH(
            hostname,
            port=port,
            username=username,
            password=password,
            subsystem=subsystem,
            executable=executable,
            arguments=arguments,
        )

    async def read(self) -> bytes:
        return await self._ssh.read()

    async def write(
            self,
            data: bytes,
    ):
        await self._ssh.write(data)

    async def start(self):
        await self._ssh.open()

    async def stop(self):
        await self._ssh.close()


class WSManInfo(ConnectionInfo):

    def __init__(
            self,
            connection_uri: str,
            configuration_name='Microsoft.PowerShell',
            buffer_mode: OutputBufferingMode = OutputBufferingMode.none,
            idle_timeout: typing.Optional[int] = None,
            *args,
            **kwargs,
    ):
        super().__init__()

        self._connection = WSManConnection(connection_uri=connection_uri, *args, **kwargs)

        self._runspace_table: typing.Dict[str, WinRS] = {}
        self._listener_tasks: typing.Dict[str, asyncio.Task] = {}
        self._connection_uri = connection_uri
        self._buffer_mode = buffer_mode
        self._idle_timeout = idle_timeout
        self._configuration_name = f'http://schemas.microsoft.com/powershell/{configuration_name}'


class AsyncWSManInfo(AsyncConnectionInfo):
    """Async ConnectionInfo for WSMan.

    Async ConnectionInfo implementation for WSMan/WinRM. This is the
    traditional PSRP connection used on Windows before SSH became available.
    It uses a series of SOAP based messages sent over HTTP/HTTPS.

    Args:
        connection_uri: The WSMan URI to connect to.
    """

    def __init__(
            self,
            connection_uri: str,
            configuration_name='Microsoft.PowerShell',
            buffer_mode: OutputBufferingMode = OutputBufferingMode.none,
            idle_timeout: typing.Optional[int] = None,
            *args,
            **kwargs,
    ):
        super().__init__()

        self._connection_args = args
        self._connection_kwargs = kwargs
        self._connection_kwargs['connection_uri'] = connection_uri
        self._connection = AsyncWSManConnection(*self._connection_args, **self._connection_kwargs)

        self._runspace_table: typing.Dict[str, WinRS] = {}
        self._listener_tasks: typing.Dict[str, asyncio.Task] = {}
        self._connection_uri = connection_uri
        self._buffer_mode = buffer_mode
        self._idle_timeout = idle_timeout
        self._configuration_name = f'http://schemas.microsoft.com/powershell/{configuration_name}'

    async def close(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        if pipeline_id is not None:
            await self.signal(pool, pipeline_id, signal_code=SignalCode.terminate)

            pipeline_task = self._listener_tasks.pop(f'{pool.runspace_id}:{pipeline_id}')
            await pipeline_task

        else:
            winrs = self._runspace_table[pool.runspace_id]
            winrs.close()
            resp = await self._connection.send(winrs.data_to_send())
            winrs.receive_data(resp)

            # We don't get a RnuspacePool state change response on our receive listener so manually change the state.
            pool.state = RunspacePoolState.Closed

            # Wait for the listener task(s) to complete and remove the RunspacePool from our internal table.
            listen_tasks = []
            for task_id in list(self._listener_tasks.keys()):
                if task_id.startswith(f'{pool.runspace_id}:'):
                    listen_tasks.append(self._listener_tasks.pop(task_id))

            await asyncio.gather(*listen_tasks)
            del self._runspace_table[pool.runspace_id]

            # No more connections left, close the underlying connection.
            if not self._runspace_table:
                await self._connection.close()

    async def command(
            self,
            pool: RunspacePool,
            pipeline_id: str,
    ):
        winrs = self._runspace_table[pool.runspace_id]

        payload = self.next_payload(pool)
        winrs.command('', args=[base64.b64encode(payload.data).decode()], command_id=pipeline_id)
        resp = await self._connection.send(winrs.data_to_send())
        winrs.receive_data(resp)

        await self._create_listener(pool, pipeline_id)

    async def create(
            self,
            pool: RunspacePool,
    ):
        winrs = WinRS(WSMan(self._connection_uri), self._configuration_name, shell_id=pool.runspace_id,
                      input_streams='stdin pr', output_streams='stdout')
        self._runspace_table[pool.runspace_id] = winrs

        payload = self.next_payload(pool)

        open_content = ElementTree.Element("creationXml", xmlns="http://schemas.microsoft.com/powershell")
        open_content.text = base64.b64encode(payload.data).decode()
        options = OptionSet()
        options.add_option("protocolversion", pool.our_capability.protocolversion, {"MustComply": "true"})
        winrs.open(options, open_content)

        resp = await self._connection.send(winrs.data_to_send())
        winrs.receive_data(resp)

        await self._create_listener(pool)

    async def send(
            self,
            pool: RunspacePool,
            buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(pool, buffer=buffer)
        if not payload:
            return False

        winrs = self._runspace_table[pool.runspace_id]

        stream = 'stdin' if payload.stream_type == StreamType.default else 'pr'
        winrs.send(stream, payload.data, command_id=payload.pipeline_id)
        resp = await self._connection.send(winrs.data_to_send())
        winrs.receive_data(resp)

        return True

    async def signal(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
            signal_code: SignalCode = SignalCode.ps_ctrl_c,
    ):
        winrs = self._runspace_table[pool.runspace_id]

        winrs.signal(signal_code, pipeline_id)
        resp = await self._connection.send(winrs.data_to_send())
        winrs.receive_data(resp)

    async def connect(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        rsp = NAMESPACES['rsp']
        connect = ElementTree.Element('{%s}Connect' % rsp)
        if pipeline_id:
            connect.attrib['CommandId'] = pipeline_id
            options = None

        else:
            payload = self.next_payload(pool)

            options = OptionSet()
            options.add_option('protocolversion', pool.our_capability.protocolversion, {'MustComply': 'true'})

            open_content = ElementTree.SubElement(connect, 'connectXml',
                                                  xmlns='http://schemas.microsoft.com/powershell')
            open_content.text = base64.b64encode(payload.data).decode()

        winrs = self._runspace_table[pool.runspace_id]
        winrs.wsman.connect(winrs.resource_uri, connect, option_set=options, selector_set=winrs.selector_set)
        resp = await self._connection.send(winrs.data_to_send())
        event = winrs.wsman.receive_data(resp)

        if not pipeline_id:
            response_xml = event.body.find('rsp:ConnectResponse/pwsh:connectResponseXml', NAMESPACES).text

            psrp_resp = PSRPPayload(base64.b64decode(response_xml), StreamType.default, None)
            pool.receive_data(psrp_resp)

        await self._create_listener(pool, pipeline_id=pipeline_id)

    async def disconnect(
            self,
            pool: RunspacePool,
            buffer_mode: OutputBufferingMode = OutputBufferingMode.none,
            idle_timeout: typing.Optional[typing.Union[int, float]] = None
    ):
        winrs = self._runspace_table[pool.runspace_id]
        rsp = NAMESPACES['rsp']

        disconnect = ElementTree.Element('{%s}Disconnect' % rsp)
        if buffer_mode != OutputBufferingMode.none:
            buffer_mode_str = 'Block' if buffer_mode == OutputBufferingMode.block else 'Drop'
            ElementTree.SubElement(disconnect, '{%s}BufferMode' % rsp).text = buffer_mode_str

        if idle_timeout:
            idle_str = f'PT{idle_timeout}S'
            ElementTree.SubElement(disconnect, '{%s}IdleTimeout' % rsp).text = idle_str

        winrs.wsman.disconnect(winrs.resource_uri, disconnect, selector_set=winrs.selector_set)
        resp = await self._connection.send(winrs.data_to_send())
        winrs.receive_data(resp)

    async def reconnect(
            self,
            pool: RunspacePool,
    ):
        winrs = self._runspace_table[pool.runspace_id]

        winrs.wsman.reconnect(winrs.resource_uri, selector_set=winrs.selector_set)
        resp = await self._connection.send(winrs.data_to_send())
        winrs.receive_data(resp)

    async def enumerate(self) -> typing.AsyncIterable[typing.Tuple[str, typing.List[str]]]:
        winrs = WinRS(WSMan(self._connection_uri))
        winrs.enumerate()
        resp = await self._connection.send(winrs.data_to_send())
        shell_enumeration = winrs.receive_data(resp)

        for shell in shell_enumeration.shells:
            shell.enumerate('http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command', shell.selector_set)
            resp = await self._connection.send(winrs.data_to_send())
            cmd_enumeration = winrs.receive_data(resp)

            self._runspace_table[shell.shell_id] = shell

            yield shell.shell_id, cmd_enumeration.commands

    async def _create_listener(
            self,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        started = asyncio.Event()
        task = asyncio_create_task(self._listen(started, pool, pipeline_id))
        self._listener_tasks[f'{pool.runspace_id}:{pipeline_id or ""}'] = task
        await started.wait()

    async def _listen(
            self,
            started: asyncio.Event,
            pool: RunspacePool,
            pipeline_id: typing.Optional[str] = None,
    ):
        winrs = self._runspace_table[pool.runspace_id]

        async with AsyncWSManConnection(*self._connection_args, **self._connection_kwargs) as conn:
            while True:
                winrs.receive('stdout', command_id=pipeline_id)

                resp = await conn.send(winrs.data_to_send())
                # TODO: Will the ReceiveResponse block if not all the fragments have been sent?
                started.set()

                try:
                    event: ReceiveResponseEvent = winrs.receive_data(resp)

                except OperationTimedOut:
                    # Occurs when there has been no output after the OperationTimeout set, just repeat the request
                    continue

                except (OperationAborted, ServiceStreamDisconnected) as e:
                    # Received when the shell or pipeline has been closed
                    break

                for psrp_data in event.get_streams().get('stdout', []):
                    msg = PSRPPayload(psrp_data, StreamType.default, pipeline_id)
                    await self.queue_response(pool.runspace_id, msg)

                # If the command is done then we've got nothing left to do here.
                # TODO: do we need to surface the exit_code into the protocol.
                if event.command_state == CommandState.done:
                    break

            if pipeline_id is None:
                await self.queue_response(pool.runspace_id, None)


_EMPTY_UUID = '00000000-0000-0000-0000-000000000000'


def _ps_data_packet(
        data: bytes,
        stream_type: StreamType = StreamType.default,
        ps_guid: typing.Optional[str] = None
) -> bytes:
    """Data packet for PSRP fragments

    This creates a data packet that is used to encode PSRP fragments when
    sending to the server.

    Args:
        data: The PSRP fragments to encode.
        stream_type: The stream type to target, Default or PromptResponse.
        ps_guid: Set to `None` or a 0'd UUID to target the RunspacePool,
            otherwise this should be the pipeline UUID.

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

    This creates a PSGuid packet that is used to signal events and stages in
    the PSRP exchange. Unlike the data packet this does not contain any PSRP
    fragments.

    Args:
        element: The element type, can be DataAck, Command, CommandAck, Close,
            CloseAck, Signal, and SignalAck.
        ps_guid: Set to `None` or a 0'd UUID to target the RunspacePool,
            otherwise this should be the pipeline UUID.

    Returns:
        bytes: The encoded PSGuid packet.
    """
    ps_guid = ps_guid or _EMPTY_UUID
    return b"<%s PSGuid='%s' />\n" % (element.encode(), ps_guid.encode())
