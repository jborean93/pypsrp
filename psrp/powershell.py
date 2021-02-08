# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import queue
import threading
import typing

from ._compat import (
    asyncio_create_task,
    iscoroutinefunction,
)

from .exceptions import (
    PSRPError,
)

from .host import (
    get_host_method,
    PSHost,
)

from .protocol.powershell import (
    ClientGetCommandMetadata,
    ClientPowerShell,
    Command,
    PipelineType,
    PSInvocationState,
    RunspacePool as PSRunspacePool,
)

from .protocol.powershell_events import (
    ApplicationPrivateDataEvent,
    DebugRecordEvent,
    ErrorRecordEvent,
    InformationRecordEvent,
    PipelineHostCallEvent,
    PipelineOutputEvent,
    PipelineStateEvent,
    ProgressRecordEvent,
    PublicKeyRequestEvent,
    VerboseRecordEvent,
    WarningRecordEvent,
)

from .dotnet.complex_types import (
    ApartmentState,
    CommandTypes,
    ErrorCategoryInfo,
    ErrorRecord,
    NETException,
    PSThreadOptions,
    RemoteStreamOptions,
    RunspacePoolState,
)

from .dotnet.complex_types import (
    PSString,
)

from .dotnet.ps_base import (
    PSObject,
)

from .dotnet.psrp_messages import (
    PSRPMessageType,
)

from .connection_info import (
    AsyncConnectionInfo,
    ConnectionInfo,
)

from .exceptions import (
    MissingCipherError,
)


def _not_implemented():
    raise NotImplementedError()


async def _invoke_async(func, *args, **kwargs):
    if iscoroutinefunction(func):
        return await func(*args, **kwargs)

    else:
        return func(*args, **kwargs)


class _EndOfStream(object):
    """ Used to mark the end of a stream. """
    def __new__(cls, *args, **kwargs):
        return cls


class PSDataStream(list):
    _EOF = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._added_idx = queue.Queue()
        self._complete = False

    def __iter__(self):
        return self

    def __next__(self):
        val = self.wait()
        if self._complete:
            raise StopIteration

        return val

    def append(self, value):
        if not self._complete:
            super().append(value)
            self._added_idx.put(len(self) - 1)

    def finalize(self):
        if not self._complete:
            self._added_idx.put_nowait(None)

    def wait(self) -> typing.Optional[PSObject]:
        if self._complete:
            return

        idx = self._added_idx.get()
        if idx is None:
            self._complete = True
            return

        return self[idx]


class AsyncPSDataStream(list):
    """Collection for a PowerShell stream.

    This is a list of PowerShell objects for a PowerShell pipeline stream. This acts like a normal list but includes
    the `:meth:wait()` which can be used to asynchronously wait for any new objects to be added.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._added_idx = asyncio.Queue()
        self._complete = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        val = await self.wait()
        if self._complete:
            raise StopAsyncIteration

        return val

    def append(
            self,
            value: typing.Optional[PSObject],
    ):
        if not self._complete:
            super().append(value)
            self._added_idx.put_nowait(len(self) - 1)

    def finalize(self):
        if not self._complete:
            self._added_idx.put_nowait(None)

    async def wait(self) -> typing.Optional[PSObject]:
        """Wait for a new entry.

        Waits for a new object to be added to the stream and returns that object once it is added.

        Returns:
            typing.Optional[PSObject]: The PSObject added or `None`. If the queue has been finalized then `None` is
                also returned.
        """
        if self._complete:
            return

        idx = await self._added_idx.get()
        if idx is None:
            self._complete = True
            return

        return self[idx]


class RunspacePool:

    def __new__(
            cls,
            connection: ConnectionInfo,
            *args,
            **kwargs
    ):
        new_cls = cls
        if isinstance(connection, AsyncConnectionInfo):
            new_cls = AsyncRunspacePool

        # if new_cls == RunspacePool:
        #     raise TypeError(f'Cannot initialise base class {new_cls.__qualname__}')

        return super().__new__(new_cls)

    def __init__(
            self,
            connection: ConnectionInfo,
            apartment_state: ApartmentState = ApartmentState.Unknown,
            thread_options: PSThreadOptions = PSThreadOptions.Default,
            min_runspaces: int = 1,
            max_runspaces: int = 1,
            host: typing.Optional[PSHost] = None,
            application_arguments: typing.Optional[typing.Dict] = None,
            runspace_pool_id: typing.Optional[str] = None,
    ):
        # We don't pass in host here as getting the host info might be a coroutine. It is set in open().
        self.protocol = PSRunspacePool(
            apartment_state=apartment_state,
            thread_options=thread_options,
            min_runspaces=min_runspaces,
            max_runspaces=max_runspaces,
            application_arguments=application_arguments,
            runspace_pool_id=runspace_pool_id,
        )
        self.connection = connection
        self.connection.set_runspace_pool(self.protocol)
        self.host = host
        self.pipeline_table: typing.Dict[str, AsyncPipeline] = {}  # TODO: Fix up pipeline type

        self._new_client = False  # Used for reconnection as a new client.

    def __enter__(self):
        if self.protocol.state == RunspacePoolState.Disconnected:
            self.connect()

        else:
            self.open()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.protocol.state != RunspacePoolState.Disconnected:
            # TODO: Close each pipeline as well.
            self.connection.close()

            while self.protocol.state not in [RunspacePoolState.Closed, RunspacePoolState.Broken]:
                self.connection.wait_event()

        self.connection.stop()

    def connect(self):
        if self._new_client:
            if self.host:
                self.protocol.host = self.host.get_host_info()

            self.protocol.connect()
            self.connection.connect()

            # We do not receive a RunspacePoolState event to state when it is now opened. Instead we just wait until
            # we've received these 3 messages.
            self.connection.wait_event(message_type=PSRPMessageType.SessionCapability)
            self.connection.wait_event(message_type=PSRPMessageType.RunspacePoolInitData)
            self.connection.wait_event(message_type=PSRPMessageType.ApplicationPrivateData)
            self.protocol.state = RunspacePoolState.Opened
            self._new_client = False

        else:
            self.connection.reconnect()
            self.protocol.state = RunspacePoolState.Opened

    def open(self):
        """Open the Runspace Pool.

        Opens the connection to the peer and subsequently the Runspace Pool.
        """
        self.connection.start()

        if self.host:
            self.protocol.host = self.host.get_host_info()

        self.protocol.open()
        self.connection.create()

        while self.protocol.state != RunspacePoolState.Opened:
            self.connection.wait_event()

    def close(self):
        """Closes the Runspace Pool.

        Closes the Runspace Pool, any outstanding pipelines, and the connection to the peer.
        """
        raise NotImplementedError()

    def exchange_key(self):
        """Exchange session key.

        Exchanges the session key used to serialize secure strings. This should be called automatically by any
        operations that use secure strings but it's kept here as a manual option just in case.
        """
        raise NotImplementedError()

    def reset_runspace_state(self):
        """Resets the Runspace Pool session state.

        Resets the variable table for the Runspace Pool back to the default state. This only works on peers with a
        protocol version of 2.3 or greater (PowerShell v5+).
        """
        raise NotImplementedError()

    def create_disconnected_power_shells(self) -> typing.List['AsyncPipeline']:
        return [p for p in self.pipeline_table.values() if p.pipeline.state == PSInvocationState.Disconnected]


class AsyncRunspacePool(RunspacePool):

    async def __aenter__(self):
        if self.protocol.state == RunspacePoolState.Disconnected:
            await self.connect()

        else:
            await self.open()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def open(self):
        await self.connection.start()

        if self.host:
            self.protocol.host = await _invoke_async(self.host.get_host_info)

        self.protocol.open()
        await self.connection.create()

        while self.protocol.state != RunspacePoolState.Opened:
            await self.connection.wait_event()

    async def close(self):
        if self.protocol.state != RunspacePoolState.Disconnected:
            tasks = [p.close() for p in self.pipeline_table.values()] + [self.connection.close()]
            await asyncio.gather(*tasks)

            while self.protocol.state not in [RunspacePoolState.Closed, RunspacePoolState.Broken]:
                await self.connection.wait_event()

        await self.connection.stop()

    async def connect(self):
        if self._new_client:
            if self.host:
                self.protocol.host = await _invoke_async(self.host.get_host_info())

            self.protocol.connect()
            await self.connection.connect()

            # We do not receive a RunspacePoolState event to state when it is now opened. Instead we just wait until
            # we've received these 3 messages.
            await self.connection.wait_event(message_type=PSRPMessageType.SessionCapability)
            await self.connection.wait_event(message_type=PSRPMessageType.RunspacePoolInitData)
            await self.connection.wait_event(message_type=PSRPMessageType.ApplicationPrivateData)
            self.protocol.state = RunspacePoolState.Opened
            self._new_client = False

        else:
            await self.connection.reconnect()
            self.protocol.state = RunspacePoolState.Opened

    async def disconnect(self):
        self.protocol.state = RunspacePoolState.Disconnecting
        await self.connection.disconnect()
        self.protocol.state = RunspacePoolState.Disconnected

        for pipeline in self.pipeline_table.values():
            pipeline.state = PSInvocationState.Disconnected

    @classmethod
    async def get_runspace_pools(
            cls,
            connection_info,
            host: typing.Optional[PSHost] = None,
    ) -> typing.AsyncIterable['AsyncRunspacePool']:
        await connection_info.start()
        try:
            async for rpid, command_list, connection in connection_info.enumerate():
                runspace_pool = AsyncRunspacePool(connection, host=host, runspace_pool_id=rpid)
                runspace_pool.protocol.state = RunspacePoolState.Disconnected
                runspace_pool._new_client = True

                for cmd_id in command_list:
                    ps = AsyncPowerShell(runspace_pool)
                    ps.pipeline.pipeline_id = cmd_id
                    ps.pipeline.state = PSInvocationState.Disconnected
                    runspace_pool.pipeline_table[cmd_id] = ps

                yield runspace_pool

        finally:
            await connection_info.stop()

    async def exchange_key(self):
        self.protocol.exchange_key()
        await self.connection.send_all()
        await self.connection.wait_event(message_type=PSRPMessageType.EncryptedSessionKey)

    async def reset_runspace_state(self):
        self.protocol.reset_runspace_state()
        await self.connection.send_all()
        await self.connection.wait_event(message_type=PSRPMessageType.RunspaceAvailability)

    async def set_min_runspaces(
            self,
            value: int,
    ):
        self.protocol.min_runspaces = value
        await self.connection.send_all()
        await self.connection.wait_event(message_type=PSRPMessageType.SetMinRunspaces)

    async def set_max_runspaces(
            self,
            value: int,
    ):
        self.protocol.max_runspaces = value
        await self.connection.send_all()
        await self.connection.wait_event(message_type=PSRPMessageType.SetMaxRunspaces)

    async def get_available_runspaces(self) -> int:
        self.protocol.get_available_runspaces()
        await self.connection.send_all()
        event = await self.connection.wait_event(message_type=PSRPMessageType.RunspaceAvailability)

        return event.count


class Pipeline(typing.Generic[PipelineType]):

    def __init__(
            self,
            runspace_pool: RunspacePool,
            pipeline: PipelineType,
    ):
        self.runspace_pool = runspace_pool
        self.pipeline = pipeline
        self.streams = {
            'debug': PSDataStream(),
            'error': PSDataStream(),
            'information': PSDataStream(),
            'progress': PSDataStream(),
            'verbose': PSDataStream(),
            'warning': PSDataStream(),
        }

        self._host_tasks: typing.Dict[int, threading.Thread] = {}
        self._close_lock = threading.Lock()

    def close(self):
        with self._close_lock:
            pipeline = self.runspace_pool.pipeline_table.get(self.pipeline.pipeline_id)
            if not pipeline or pipeline.pipeline.state == PSInvocationState.Disconnected:
                return

            self.runspace_pool.connection.close(self.pipeline.pipeline_id)
            del self.runspace_pool.pipeline_table[self.pipeline.pipeline_id]

    def connect(self) -> typing.Iterable[PSObject]:
        output_stream = PSDataStream()
        task = self.connect_async(output_stream)

        yield from output_stream

        task.wait()

    def connect_async(
            self,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
    ):  # TODO: Fix return type
        self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.protocol.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        task = threading.Thread(target=self._wait_invoke, args=(output_stream, completed))
        task.start()
        return task

    def invoke(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            output_stream: typing.Optional[PSDataStream] = None,
            buffer_input: bool = True,
    ) -> typing.Iterable[typing.Optional[PSObject]]:
        iterate = False
        if output_stream is None:
            iterate = True
            output_stream = PSDataStream()

        output_task = self.invoke_async(
            input_data=input_data,
            output_stream=output_stream,
            buffer_input=buffer_input,
        )

        if iterate:
            yield from output_stream

        output_task.join()

    def invoke_async(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
            buffer_input: bool = True,
    ) -> threading.Thread:
        try:
            self.pipeline.invoke()
        except MissingCipherError:
            self.runspace_pool.exchange_key()
            self.pipeline.invoke()

        self.runspace_pool.connection.command(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.connection.send_all()

        receive_task = threading.Thread(target=self._wait_invoke, args=(output_stream, completed))
        receive_task.start()

        if input_data is not None:
            self._send_input(input_data, buffer_input)

        return receive_task

    def _send_input(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            buffer_input: bool = True,
    ):
        """ Send input data to a running pipeline. """
        for data in input_data:
            try:
                self.pipeline.send(data)

            except MissingCipherError:
                self.runspace_pool.exchange_key()
                self.pipeline.send(data)

            if buffer_input:
                self.runspace_pool.connection.send(buffer=True)
            else:
                self.runspace_pool.connection.send_all()

        self.pipeline.send_end()
        self.runspace_pool.connection.send_all()

    def _wait_invoke(
            self,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
    ) -> typing.List[typing.Optional[PSObject]]:
        """ Background task that collects the pipeline output. """
        return_out = False
        if output_stream is None:
            output_stream = PSDataStream()
            return_out = True

        stream_map = {
            PipelineOutputEvent: output_stream,
            DebugRecordEvent: self.streams['debug'],
            ErrorRecordEvent: self.streams['error'],
            InformationRecordEvent: self.streams['information'],
            ProgressRecordEvent: self.streams['progress'],
            VerboseRecordEvent: self.streams['verbose'],
            WarningRecordEvent: self.streams['warning'],
        }

        disconnected = False
        try:
            while self.pipeline.state == PSInvocationState.Running:
                try:
                    event = self.runspace_pool.connection.wait_event(self.pipeline.pipeline_id)

                except MissingCipherError:
                    # A SecureString was received but no key was exchanged, rerun after getting the key.
                    event = PublicKeyRequestEvent(PSRPMessageType.PublicKeyRequest, PSString(''),
                                                  self.runspace_pool.protocol.runspace_id)

                if event is None:
                    # Runspace was disconnected/closed, just exit our loop and continue on.
                    disconnected = True
                    break

                if isinstance(event, PipelineStateEvent):
                    if event.reason:
                        self.streams['error'].append(event.reason)

                    break  # No more data to process

                elif isinstance(event, PipelineHostCallEvent):
                    # Run in a separate task so we don't block our data listener in case of an exception
                    # self._host_tasks[event.ps_object.ci] = asyncio_create_task(self._host_call(event.ps_object))
                    a = ''  # FIXME

                elif isinstance(event, PublicKeyRequestEvent):
                    self.runspace_pool.exchange_key()

                elif type(event) in stream_map:
                    stream = stream_map[type(event)]
                    stream.append(event.ps_object)

                else:
                    print(f"unknown event {event!s}")

        finally:
            for stream in stream_map.values():
                stream.finalize()

            if not disconnected:
                self.close()

        if completed:
            completed.set()

        # TODO: gather host threads.

        if return_out:
            return list(output_stream)


class AsyncPipeline(typing.Generic[PipelineType]):

    def __init__(
            self,
            runspace_pool: AsyncRunspacePool,
            pipeline: PipelineType,
    ):
        self.runspace_pool = runspace_pool
        self.pipeline = pipeline
        self.streams = {
            'debug': AsyncPSDataStream(),
            'error': AsyncPSDataStream(),
            'information': AsyncPSDataStream(),
            'progress': AsyncPSDataStream(),
            'verbose': AsyncPSDataStream(),
            'warning': AsyncPSDataStream(),
        }

        self._host_tasks: typing.Dict[int, asyncio.Task] = {}
        self._close_lock = asyncio.Lock()

    async def close(self):
        """Closes the pipeline.

        Closes the pipeline resource on the peer. This is done automatically when the pipeline is completed or the
        Runspace Pool is closed but can be called manually if desired.
        """
        # We call this from many places, we want a lock to ensure it's only run once.
        async with self._close_lock:
            pipeline = self.runspace_pool.pipeline_table.get(self.pipeline.pipeline_id)
            if not pipeline or pipeline.pipeline.state == PSInvocationState.Disconnected:
                return

            await self.runspace_pool.connection.close(self.pipeline.pipeline_id)
            del self.runspace_pool.pipeline_table[self.pipeline.pipeline_id]

    async def connect(self) -> typing.AsyncIterable[PSObject]:
        output_stream = AsyncPSDataStream()
        task = await self.connect_async(output_stream)

        async for out in output_stream:
            yield out

        await task

    async def connect_async(
            self,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> asyncio.Task[typing.List[typing.Optional[PSObject]]]:
        await self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.protocol.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        return asyncio_create_task(self._wait_invoke(output_stream, completed))

    async def invoke(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            buffer_input: bool = True,
    ) -> typing.AsyncIterable[typing.Optional[PSObject]]:
        """Invoke the pipeline.

        Invokes the pipeline and yields the output as it is received. This takes the same arguments as
        `:meth:begin_invoke()` but instead of returning once the pipeline is started this will wait until it is
        complete.

        Returns:
            (typing.AsyncIterable[PSObject]): An async iterable that can be iterated to receive the output objects as
                they are received.
        """
        iterate = False
        if output_stream is None:
            iterate = True
            output_stream = AsyncPSDataStream()

        output_task = await self.invoke_async(
            input_data=input_data,
            output_stream=output_stream,
            buffer_input=buffer_input,
        )

        if iterate:
            async for out in output_stream:
                yield out

        await output_task

    async def _send_input(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            buffer_input: bool = True,
    ):
        """ Send input data to a running pipeline. """
        if isinstance(input_data, typing.Iterable):
            async def async_input_gen():
                for data in input_data:
                    yield data

            input_gen = async_input_gen()
        else:
            input_gen = input_data

        async for data in input_gen:
            try:
                self.pipeline.send(data)

            except MissingCipherError:
                await self.runspace_pool.exchange_key()
                self.pipeline.send(data)

            if buffer_input:
                await self.runspace_pool.connection.send(buffer=True)
            else:
                await self.runspace_pool.connection.send_all()

        self.pipeline.send_end()
        await self.runspace_pool.connection.send_all()

    async def _wait_invoke(
            self,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> typing.List[typing.Optional[PSObject]]:
        """ Background task that collects the pipeline output. """
        return_out = False
        if output_stream is None:
            output_stream = AsyncPSDataStream()
            return_out = True

        stream_map = {
            PipelineOutputEvent: output_stream,
            DebugRecordEvent: self.streams['debug'],
            ErrorRecordEvent: self.streams['error'],
            InformationRecordEvent: self.streams['information'],
            ProgressRecordEvent: self.streams['progress'],
            VerboseRecordEvent: self.streams['verbose'],
            WarningRecordEvent: self.streams['warning'],
        }

        disconnected = False
        try:
            while self.pipeline.state == PSInvocationState.Running:
                try:
                    event = await self.runspace_pool.connection.wait_event(self.pipeline.pipeline_id)

                except MissingCipherError:
                    # A SecureString was received but no key was exchanged, rerun after getting the key.
                    event = PublicKeyRequestEvent(PSRPMessageType.PublicKeyRequest, PSString(''),
                                                  self.runspace_pool.protocol.runspace_id)

                if event is None:
                    # Runspace was disconnected/closed, just exit our loop and continue on.
                    disconnected = True
                    break

                if isinstance(event, PipelineStateEvent):
                    if event.reason:
                        self.streams['error'].append(event.reason)

                    break  # No more data to process

                elif isinstance(event, PipelineHostCallEvent):
                    # Run in a separate task so we don't block our data listener in case of an exception
                    self._host_tasks[event.ps_object.ci] = asyncio_create_task(self._host_call(event.ps_object))

                elif isinstance(event, PublicKeyRequestEvent):
                    await self.runspace_pool.exchange_key()

                elif type(event) in stream_map:
                    stream = stream_map[type(event)]
                    stream.append(event.ps_object)

                else:
                    print(f"unknown event {event!s}")

        finally:
            for stream in stream_map.values():
                stream.finalize()

            if not disconnected:
                await self.close()

        if completed:
            completed.set()

        # Need to make sure we await any host response tasks and raise the exception if it failed.
        try:
            await asyncio.gather(*self._host_tasks.values())

        except Exception as e:
            mi = getattr(e, 'mi', 'Unknown')

            if isinstance(e, NotImplementedError):
                msg = f'HostMethodCall {mi!s} not implemented'

            else:
                msg = f'HostMethodClass {mi!s} exception: {e!s}'

            raise PSRPError(msg) from e

        finally:
            self._host_tasks = {}

        if return_out:
            return list(output_stream)

    async def invoke_async(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
            buffer_input: bool = True,
    ) -> asyncio.Task[typing.List[typing.Optional[PSObject]]]:
        """Begin the pipeline.

        Begin the pipeline execution and returns an async iterable that yields the output as they are received.

        Args:
            input_data: A list of objects to send as the input to the pipeline. Can be a normal or async iterable.
            output_stream:
            completed:
            buffer_input: Whether to buffer the input data and only send each object once the buffer is full (`True`)
                or individually as separate PSRP messages (`False`).

        Returns:
            (typing.AsyncIterable[PSObject]): An async iterable that can be iterated to receive the output objects as
                they are received.
        """
        try:
            self.pipeline.invoke()
        except MissingCipherError:
            await self.runspace_pool.exchange_key()
            self.pipeline.invoke()

        await self.runspace_pool.connection.command(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        await self.runspace_pool.connection.send_all()

        receive_task = asyncio_create_task(self._wait_invoke(output_stream, completed))

        if input_data is not None:
            await self._send_input(input_data, buffer_input)

        return receive_task

    async def stop(self):
        """Stops a running pipeline.

        Stops a running pipeline and waits for it to stop.
        """
        task = await self.stop_async()
        await task

    async def stop_async(
            self,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> asyncio.Task:
        await self.runspace_pool.connection.signal(self.pipeline.pipeline_id)
        return asyncio_create_task(self._wait_stop(completed))

    async def _send_input(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            buffer_input: bool = True,
    ):
        """ Send input data to a running pipeline. """
        if isinstance(input_data, typing.Iterable):
            async def async_input_gen():
                for data in input_data:
                    yield data

            input_gen = async_input_gen()
        else:
            input_gen = input_data

        async for data in input_gen:
            try:
                self.pipeline.send(data)

            except MissingCipherError:
                await self.runspace_pool.exchange_key()
                self.pipeline.send(data)

            if buffer_input:
                await self.runspace_pool.connection.send(buffer=True)
            else:
                await self.runspace_pool.connection.send_all()

        self.pipeline.send_end()
        await self.runspace_pool.connection.send_all()

    async def _wait_invoke(
            self,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> typing.List[typing.Optional[PSObject]]:
        """ Background task that collects the pipeline output. """
        return_out = False
        if output_stream is None:
            output_stream = AsyncPSDataStream()
            return_out = True

        stream_map = {
            PipelineOutputEvent: output_stream,
            DebugRecordEvent: self.streams['debug'],
            ErrorRecordEvent: self.streams['error'],
            InformationRecordEvent: self.streams['information'],
            ProgressRecordEvent: self.streams['progress'],
            VerboseRecordEvent: self.streams['verbose'],
            WarningRecordEvent: self.streams['warning'],
        }

        disconnected = False
        try:
            while self.pipeline.state == PSInvocationState.Running:
                try:
                    event = await self.runspace_pool.connection.wait_event(self.pipeline.pipeline_id)

                except MissingCipherError:
                    # A SecureString was received but no key was exchanged, rerun after getting the key.
                    event = PublicKeyRequestEvent(PSRPMessageType.PublicKeyRequest, PSString(''),
                                                  self.runspace_pool.protocol.runspace_id)

                if event is None:
                    # Runspace was disconnected/closed, just exit our loop and continue on.
                    disconnected = True
                    break

                if isinstance(event, PipelineStateEvent):
                    if event.reason:
                        self.streams['error'].append(event.reason)

                    break  # No more data to process

                elif isinstance(event, PipelineHostCallEvent):
                    # Run in a separate task so we don't block our data listener in case of an exception
                    self._host_tasks[event.ps_object.ci] = asyncio_create_task(self._host_call(event.ps_object))

                elif isinstance(event, PublicKeyRequestEvent):
                    await self.runspace_pool.exchange_key()

                elif type(event) in stream_map:
                    stream = stream_map[type(event)]
                    stream.append(event.ps_object)

                else:
                    print(f"unknown event {event!s}")

        finally:
            for stream in stream_map.values():
                stream.finalize()

            if not disconnected:
                await self.close()

        if completed:
            completed.set()

        # Need to make sure we await any host response tasks and raise the exception if it failed.
        try:
            await asyncio.gather(*self._host_tasks.values())

        except Exception as e:
            mi = getattr(e, 'mi', 'Unknown')

            if isinstance(e, NotImplementedError):
                msg = f'HostMethodCall {mi!s} not implemented'

            else:
                msg = f'HostMethodClass {mi!s} exception: {e!s}'

            raise PSRPError(msg) from e

        finally:
            self._host_tasks = {}

        if return_out:
            return list(output_stream)

    async def _wait_stop(
            self,
            completed: typing.Optional[asyncio.Event] = None,
    ):
        while self.pipeline.state not in [PSInvocationState.Stopped, PSInvocationState.Completed]:
            await self.runspace_pool.connection.wait_event(self.pipeline.pipeline_id)

        if completed:
            completed.set()

    async def _host_call(
            self,
            host_call: PSObject,
    ):
        host = getattr(self, 'host', None)
        if host is None:
            host = self.runspace_pool.host

        mi = host_call.mi
        mp = host_call.mp
        method_metadata = get_host_method(host, mi, mp)
        func = method_metadata.invoke

        error_record = None
        try:
            return_value = await _invoke_async(func or _not_implemented)

        except Exception as e:
            setattr(e, 'mi', mi)

            if method_metadata.is_void:
                # TODO: need to stop the pipeline.
                raise

            # Any failure for non-void methods should be propagated back to the peer.
            e_msg = str(e)
            if not e_msg:
                e_msg = f'{type(e).__qualname__} when running {mi}'

            return_value = None
            error_record = ErrorRecord(
                Exception=NETException(e_msg),
                FullyQualifiedErrorId='RemoteHostExecutionException',
                CategoryInfo=ErrorCategoryInfo(
                    Reason='Exception',
                ),
            )

        if not method_metadata.is_void:
            self.runspace_pool.protocol.host_response(host_call.ci, return_value=return_value,
                                                      error_record=error_record)
            await self.runspace_pool.connection.send_all()


class AsyncCommandMetaPipeline(AsyncPipeline[ClientGetCommandMetadata]):

    def __init__(
            self,
            runspace_pool: AsyncRunspacePool,
            name: typing.Union[str, typing.List[str]],
            command_type: CommandTypes = CommandTypes.All,
            namespace: typing.Optional[typing.List[str]] = None,
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        pipeline = ClientGetCommandMetadata(
            runspace_pool=runspace_pool.protocol,
            name=name,
            command_type=command_type,
            namespace=namespace,
            arguments=arguments,
        )
        super().__init__(runspace_pool, pipeline)


class PowerShell(Pipeline[ClientPowerShell]):

    def __new__(
            cls,
            runspace_pool: RunspacePool,
            *args,
            **kwargs,
    ):
        new_cls = cls
        if isinstance(runspace_pool, AsyncRunspacePool):
            new_cls = AsyncPowerShell

        return super().__new__(new_cls)

    def __init__(
            self,
            runspace_pool: AsyncRunspacePool,
            add_to_history: bool = False,
            apartment_state: typing.Optional[ApartmentState] = None,
            history: typing.Optional[str] = None,
            host: typing.Optional[PSHost] = None,
            is_nested: bool = False,
            remote_stream_options: RemoteStreamOptions = RemoteStreamOptions.none,
            redirect_shell_error_to_out: bool = True,
    ):
        pipeline = ClientPowerShell(
            runspace_pool=runspace_pool.protocol,
            add_to_history=add_to_history,
            apartment_state=apartment_state,
            history=history,
            is_nested=is_nested,
            remote_stream_options=remote_stream_options,
            redirect_shell_error_to_out=redirect_shell_error_to_out,
        )
        super().__init__(runspace_pool, pipeline)
        self.host = host

    @property
    def had_errors(self) -> bool:
        return self.pipeline.state == PSInvocationState.Failed

    def add_command(
            self,
            cmdlet: typing.Union[str, Command],
            use_local_scope: typing.Optional[bool] = None,
    ):
        self.pipeline.add_command(cmdlet, use_local_scope)

    def add_script(
            self,
            script: str,
            use_local_scope: typing.Optional[bool] = None,
    ):
        self.pipeline.add_script(script, use_local_scope)
        return self

    def add_statement(self):
        self.pipeline.add_statement()
        return self

    def invoke_async(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
            buffer_input: bool = True,
    ) -> threading.Thread:
        if self.host:
            self.pipeline.host = self.host.get_host_info()

        self.pipeline.no_input = input_data is None

        return super().invoke_async(input_data, output_stream, completed, buffer_input)


class AsyncPowerShell(AsyncPipeline[ClientPowerShell]):

    def __new__(
            cls,
            runspace_pool: RunspacePool,
            *args,
            **kwargs,
    ):
        new_cls = cls
        if isinstance(runspace_pool, AsyncRunspacePool):
            new_cls = AsyncPowerShell

        return super().__new__(new_cls)

    def __init__(
            self,
            runspace_pool: AsyncRunspacePool,
            add_to_history: bool = False,
            apartment_state: typing.Optional[ApartmentState] = None,
            history: typing.Optional[str] = None,
            host: typing.Optional[PSHost] = None,
            is_nested: bool = False,
            remote_stream_options: RemoteStreamOptions = RemoteStreamOptions.none,
            redirect_shell_error_to_out: bool = True,
    ):
        pipeline = ClientPowerShell(
            runspace_pool=runspace_pool.protocol,
            add_to_history=add_to_history,
            apartment_state=apartment_state,
            history=history,
            is_nested=is_nested,
            remote_stream_options=remote_stream_options,
            redirect_shell_error_to_out=redirect_shell_error_to_out,
        )
        super().__init__(runspace_pool, pipeline)
        self.host = host

    @property
    def had_errors(self) -> bool:
        return self.pipeline.state == PSInvocationState.Failed

    def add_command(
            self,
            cmdlet: typing.Union[str, Command],
            use_local_scope: typing.Optional[bool] = None,
    ):
        self.pipeline.add_command(cmdlet, use_local_scope)

    def add_script(
            self,
            script: str,
            use_local_scope: typing.Optional[bool] = None,
    ):
        self.pipeline.add_script(script, use_local_scope)
        return self

    def add_statement(self):
        self.pipeline.add_statement()
        return self

    async def invoke_async(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
            buffer_input: bool = True,
    ) -> asyncio.Task[typing.List[typing.Optional[PSObject]]]:
        if self.host:
            self.pipeline.host = await _invoke_async(self.host.get_host_info)

        self.pipeline.no_input = input_data is None

        return await super().invoke_async(input_data, output_stream, completed, buffer_input)
