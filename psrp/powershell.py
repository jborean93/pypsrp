# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import queue
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

    def append(self, value):
        if value == _EndOfStream:
            self._added_idx.put(None)
            return

        super().append(value)
        self._added_idx.put(len(self) - 1)

    def wait(self) -> typing.Optional[PSObject]:
        if self._complete:
            return self._EOF

        idx = self._added_idx.get()
        if idx is None:
            self._complete = True
            return self._EOF

        return self[idx]


class AsyncPSDataStream(list):
    """Collection for a PowerShell stream.

    This is a list of PowerShell objects for a PowerShell pipeline stream. This acts like a normal list but includes
    the `:meth:wait()` which can be used to asynchronously wait for any new objects to be added.
    """
    _EOF = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._added_idx = asyncio.Queue()
        self._complete = False

    def append(self, value):
        if value == _EndOfStream:
            self._added_idx.put_nowait(None)
            return

        super().append(value)
        self._added_idx.put_nowait(len(self) - 1)

    async def wait(self) -> typing.Optional[PSObject]:
        """Wait for a new entry.

        Waits for a new object to be added to the stream and returns that object once it is added.

        Returns:
            typing.Optional[PSObject]: The PSObject added or `None` if the queue has been finalized.
        """
        if self._complete:
            return self._EOF

        idx = await self._added_idx.get()
        if idx is None:
            self._complete = True
            return self._EOF

        return self[idx]


# Used internally and need to differentiate between None and no more data.
class _OutputDataStream(PSDataStream):
    _EOF = _EndOfStream


class _AsyncOutputStream(AsyncPSDataStream):
    _EOF = _EndOfStream


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

        if new_cls == RunspacePool:
            raise TypeError(f'Cannot initialise base class {new_cls.__qualname__}')

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
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        """Open the Runspace Pool.

        Opens the connection to the peer and subsequently the Runspace Pool.
        """
        raise NotImplementedError()

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
        self._receive_task = None
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
            if pipeline:
                if pipeline.pipeline.state == PSInvocationState.Disconnected:
                    return

                await self.runspace_pool.connection.close(self.pipeline.pipeline_id)
                del self.runspace_pool.pipeline_table[self.pipeline.pipeline_id]

    async def begin_connect(self):
        await self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.protocol.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        output_stream = _AsyncOutputStream()
        self._receive_task = asyncio_create_task(self._wait_invoke(output_stream))

        async def runner():
            while True:
                output = await output_stream.wait()
                if output == _EndOfStream:
                    break

                yield output

            await self._receive_task
            self._receive_task = None

        return runner()

    async def connect(self):
        output_iterator = await self.begin_connect()
        async for output in self.end_invoke(output_iterator):
            yield output

    async def begin_invoke(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            buffer_input: bool = True,
    ) -> typing.AsyncIterable[PSObject]:
        """Begin the pipeline.

        Begin the pipeline execution and returns an async iterable that yields the output as they are received.

        Args:
            input_data: A list of objects to send as the input to the pipeline. Can be a normal or async iterable.
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

        output_stream = _AsyncOutputStream()
        self._receive_task = asyncio_create_task(self._wait_invoke(output_stream))

        if input_data is not None:
            await self._send_input(input_data, buffer_input)

        # Make an AsyncGenerator that the user or end_invoke() can use to yield pipeline output as it comes in.
        async def runner():
            while True:
                output = await output_stream.wait()
                if output == _EndOfStream:
                    break

                yield output

            await self._receive_task
            self._receive_task = None

        return runner()

    async def invoke(
            self,
            *args,
            **kwargs,
    ) -> typing.AsyncIterable[PSObject]:
        """Invoke the pipeline.

        Invokes the pipeline and yields the output as it is received. This takes the same arguments as
        `:meth:begin_invoke()` but instead of returning once the pipeline is started this will wait until it is
        complete.

        Returns:
            (typing.AsyncIterable[PSObject]): An async iterable that can be iterated to receive the output objects as
                they are received.
        """
        output_iterator = await self.begin_invoke(*args, **kwargs)
        async for output in self.end_invoke(output_iterator):
            yield output

    async def end_invoke(
            self,
            output_iterator: typing.AsyncIterable[PSObject],
    ) -> typing.AsyncIterable[PSObject]:
        """End the pipeline invocation.

        Used to wait for a pipeline started by `:meth:begin_invoke()` to complete.

        Args:
            output_iterator: The iterator returned by `:meth:begin_invoke()`.

        Returns:
            (typing.AsyncIterable[PSObject]): An async iterable that can be iterated to receive the output objects as
                they are received.
        """
        async for output in output_iterator:
            yield output

    async def stop(self):
        """Stops a running pipeline.

        Stops a running pipeline and waits for it to stop.
        """
        await self.runspace_pool.connection.signal(self.pipeline.pipeline_id)
        while self.pipeline.state not in [PSInvocationState.Stopped, PSInvocationState.Completed]:
            await self.runspace_pool.connection.wait_event(self.pipeline.pipeline_id)

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
            output_stream: AsyncPSDataStream,
    ):
        """ Background task that collects the pipeline output. """
        stream_map = {
            PipelineOutputEvent: output_stream,
            DebugRecordEvent: self.streams['debug'],
            ErrorRecordEvent: self.streams['error'],
            InformationRecordEvent: self.streams['information'],
            ProgressRecordEvent: self.streams['progress'],
            VerboseRecordEvent: self.streams['verbose'],
            WarningRecordEvent: self.streams['warning'],
        }

        try:
            while self.pipeline.state == PSInvocationState.Running:
                try:
                    event = await self.runspace_pool.connection.wait_event(self.pipeline.pipeline_id)

                except MissingCipherError:
                    # A SecureString was received but no key was exchanged, rerun after getting the key.
                    event = PublicKeyRequestEvent(PSRPMessageType.PublicKeyRequest, PSString(''),
                                                  self.runspace_pool.protocol.runspace_id)

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
                stream.append(_EndOfStream)

            await self.close()

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


class AsyncPowerShell(AsyncPipeline[ClientPowerShell]):

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

    async def begin_invoke(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            buffer_input: bool = True,
    ) -> typing.AsyncIterable[PSObject]:
        if self.host:
            self.pipeline.host = await _invoke_async(self.host.get_host_info)

        self.pipeline.no_input = input_data is None

        return await super().begin_invoke(input_data, buffer_input)
