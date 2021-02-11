# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import functools
import queue
import threading
import typing

from ._compat import (
    asyncio_create_task,
    iscoroutinefunction,
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
    PSRPEvent,
    UserEventEvent,
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


def _async_to_sync(func, *args, **kwargs):
    return asyncio.get_event_loop().run_until_complete(_invoke_async(func, *args, **kwargs))


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


class PipelineTask:

    def __init__(
            self,
            completed: threading.Event,
            output_stream: typing.Optional[PSDataStream] = None,
    ):
        self._completed = completed
        self._output_stream = output_stream

    def wait(self) -> typing.Optional[PSDataStream]:
        self._completed.wait()
        if self._output_stream is not None:
            return self._output_stream


class AsyncPipelineTask:

    def __init__(
            self,
            completed: asyncio.Event,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
    ):
        self._completed = completed
        self._output_stream = output_stream

    async def wait(self) -> typing.Optional[AsyncPSDataStream]:
        await self._completed.wait()
        if self._output_stream is not None:
            return self._output_stream


class _RunspacePoolBase:

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
        self.pool = PSRunspacePool(
            apartment_state=apartment_state,
            thread_options=thread_options,
            min_runspaces=min_runspaces,
            max_runspaces=max_runspaces,
            application_arguments=application_arguments,
            runspace_pool_id=runspace_pool_id,
        )
        self.connection = connection
        self.connection.set_runspace_pool(self.pool)

        self.host = host
        self.pipeline_table: typing.Dict[str, typing.Any] = {}

        self._new_client = False  # Used for reconnection as a new client.
        self._event_task = None
        self._registrations: typing.Dict[PSRPMessageType, typing.List[typing.Callable[[PSRPEvent], typing.Any]]] = {
            mt: [] for mt in [
                PSRPMessageType.ApplicationPrivateData,
                PSRPMessageType.DebugRecord,
                PSRPMessageType.EncryptedSessionKey,
                PSRPMessageType.ErrorRecord,
                PSRPMessageType.InformationRecord,
                PSRPMessageType.ProgressRecord,
                PSRPMessageType.PublicKeyRequest,
                PSRPMessageType.RunspaceAvailability,
                PSRPMessageType.RunspacePoolHostCall,
                PSRPMessageType.RunspacePoolInitData,
                PSRPMessageType.RunspacePoolState,
                PSRPMessageType.SessionCapability,
                PSRPMessageType.UserEvent,
                PSRPMessageType.VerboseRecord,
                PSRPMessageType.WarningRecord,
            ]
        }
        # TODO: add callbacks for things that run automatically in the background

    @property
    def state(
            self,
    ) -> RunspacePoolState:
        return self.pool.state

    def register_user_event(
            self,
            func: typing.Callable[[UserEventEvent], typing.Any],
    ):
        self._registrations[PSRPMessageType.UserEvent].append(func)

    def create_disconnected_power_shells(self) -> typing.List:
        return [p for p in self.pipeline_table.values() if p.pipeline.state == PSInvocationState.Disconnected]


class RunspacePool(_RunspacePoolBase):

    def __enter__(self):
        if self.state == RunspacePoolState.Disconnected:
            self.connect()

        else:
            self.open()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        if self._new_client:
            if self.host:
                self.pool.host = self.host.get_host_info()

            self.pool.connect()
            self.connection.connect()

            self._event_task = threading.Thread(target=self._response_listener)
            self._event_task.start()
            self.connection.wait_event(message_type=PSRPMessageType.SessionCapability)
            self.connection.wait_event(message_type=PSRPMessageType.RunspacePoolInitData)
            self.connection.wait_event(message_type=PSRPMessageType.ApplicationPrivateData)
            self._new_client = False

        else:
            self.connection.reconnect()
            self._event_task = threading.Thread(target=self._response_listener)
            self._event_task.start()

        self.pool.state = RunspacePoolState.Opened

    def open(self):
        """Open the Runspace Pool.

        Opens the connection to the peer and subsequently the Runspace Pool.
        """
        self.connection.start()

        if self.host:
            self.pool.host = self.host.get_host_info()

        self.pool.open()
        self.connection.create()

        self._event_task = threading.Thread(target=self._response_listener)
        self._event_task.start()
        self._wait_response(PSRPMessageType.RunspacePoolState)

    def close(self):
        """Closes the Runspace Pool.

        Closes the Runspace Pool, any outstanding pipelines, and the connection to the peer.
        """
        if self.state != RunspacePoolState.Disconnected:
            [p.close() for p in list(self.pipeline_table.values())]
            self.connection.close()

            while self.state not in [RunspacePoolState.Closed, RunspacePoolState.Broken]:
                self.connection.wait_event()

        self.connection.stop()
        self._event_task.join()

    def disconnect(self):
        self.pool.state = RunspacePoolState.Disconnecting
        self.connection.disconnect()
        self.pool.state = RunspacePoolState.Disconnected

        for pipeline in self.pipeline_table.values():
            pipeline.state = PSInvocationState.Disconnected

    @classmethod
    def get_runspace_pool(
            cls,
            connection_info: ConnectionInfo,
            host: typing.Optional[PSHost] = None,
    ) -> typing.Iterable['RunspacePool']:
        connection_info.start()
        try:
            for rpid, command_list, connection in connection_info.enumerate():
                runspace_pool = _RunspacePoolBase(connection, host=host, runspace_pool_id=rpid)
                runspace_pool.pool.state = RunspacePoolState.Disconnected
                runspace_pool._new_client = True

                for cmd_id in command_list:
                    ps = PowerShell(runspace_pool)
                    ps.pipeline.pipeline_id = cmd_id
                    ps.pipeline.state = PSInvocationState.Disconnected
                    runspace_pool.pipeline_table[cmd_id] = ps

                yield runspace_pool

        finally:
            connection_info.stop()

    def exchange_key(self):
        """Exchange session key.

        Exchanges the session key used to serialize secure strings. This should be called automatically by any
        operations that use secure strings but it's kept here as a manual option just in case.
        """
        self.pool.exchange_key()
        self.connection.send_all()
        self._wait_response(PSRPMessageType.EncryptedSessionKey)

    def reset_runspace_state(self):
        """Resets the Runspace Pool session state.

        Resets the variable table for the Runspace Pool back to the default state. This only works on peers with a
        protocol version of 2.3 or greater (PowerShell v5+).
        """
        self.pool.reset_runspace_state()
        self.connection.send_all()
        self._wait_response(PSRPMessageType.RunspaceAvailability)

    def set_min_runspaces(
            self,
            value: int,
    ):
        self.pool.min_runspaces = value
        self.connection.send_all()
        self._wait_response(PSRPMessageType.SetMinRunspaces)

    def set_max_runspaces(
            self,
            value: int,
    ):
        self.pool.max_runspaces = value
        self.connection.send_all()
        self._wait_response(PSRPMessageType.SetMaxRunspaces)

    def get_available_runspaces(self) -> int:
        self.pool.get_available_runspaces()
        self.connection.send_all()
        event = self._wait_response(PSRPMessageType.RunspaceAvailability)

        return event.count

    def _response_listener(self):
        while True:
            event = self.connection.wait_event()
            if event is None:
                return

            if event.pipeline_id:
                pipeline = self.pipeline_table[event.pipeline_id]
                reg_table = pipeline._registrations

            else:
                reg_table = self._registrations

            if event.MESSAGE_TYPE not in reg_table:
                # TODO: log.warning this
                print(f'Message type not found in registration table: {event!s}')
                continue

            for func in reg_table[event.MESSAGE_TYPE]:
                try:
                    func(event)

                except Exception as e:
                    # TODO: log.warning this
                    print(f'Error running registered callback: {e!s}')

    def _wait_response(
            self,
            message_type: PSRPMessageType,
    ) -> PSRPEvent:
        wait_event = queue.Queue()

        def wait_callback(event):
            wait_event.put(event)

        self._registrations[message_type].append(wait_callback)
        return wait_event.get()


class AsyncRunspacePool(_RunspacePoolBase):

    async def __aenter__(self):
        if self.state == RunspacePoolState.Disconnected:
            await self.connect()

        else:
            await self.open()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def connect(self):
        if self._new_client:
            if self.host:
                self.pool.host = await _invoke_async(self.host.get_host_info)

            self.pool.connect()
            await self.connection.connect()

            self._event_task = asyncio_create_task(self._response_listener())
            await self._wait_response(PSRPMessageType.SessionCapability)
            await self._wait_response(PSRPMessageType.RunspacePoolInitData)
            await self._wait_response(PSRPMessageType.ApplicationPrivateData)
            self._new_client = False

        else:
            await self.connection.reconnect()
            self._event_task = asyncio_create_task(self._response_listener())

        self.pool.state = RunspacePoolState.Opened

    async def open(self):
        await self.connection.start()

        if self.host:
            self.pool.host = await _invoke_async(self.host.get_host_info)

        self.pool.open()
        await self.connection.create()

        self._event_task = asyncio_create_task(self._response_listener())
        await self._wait_response(PSRPMessageType.RunspacePoolState)

    async def close(self):
        if self.state != RunspacePoolState.Disconnected:
            tasks = [p.close() for p in self.pipeline_table.values()] + [self.connection.close()]
            await asyncio.gather(*tasks)

            while self.state not in [RunspacePoolState.Closed, RunspacePoolState.Broken]:
                await self.connection.wait_event()

        await self.connection.stop()
        self._event_task.cancel()

    async def disconnect(self):
        self.pool.state = RunspacePoolState.Disconnecting
        await self.connection.disconnect()
        self.pool.state = RunspacePoolState.Disconnected

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
                runspace_pool = _RunspacePoolBase(connection, host=host, runspace_pool_id=rpid)
                runspace_pool.pool.state = RunspacePoolState.Disconnected
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
        self.pool.exchange_key()
        await self.connection.send_all()
        await self._wait_response(PSRPMessageType.EncryptedSessionKey)

    async def reset_runspace_state(self):
        self.pool.reset_runspace_state()
        await self.connection.send_all()
        await self._wait_response(PSRPMessageType.RunspaceAvailability)

    async def set_min_runspaces(
            self,
            value: int,
    ):
        self.pool.min_runspaces = value
        await self.connection.send_all()
        await self._wait_response(PSRPMessageType.SetMinRunspaces)

    async def set_max_runspaces(
            self,
            value: int,
    ):
        self.pool.max_runspaces = value
        await self.connection.send_all()
        await self._wait_response(PSRPMessageType.SetMaxRunspaces)

    async def get_available_runspaces(self) -> int:
        self.pool.get_available_runspaces()
        await self.connection.send_all()
        event = await self._wait_response(PSRPMessageType.RunspaceAvailability)

        return event.count

    async def _response_listener(self):
        while True:
            event = await self.connection.wait_event()
            if event is None:
                return

            if event.pipeline_id:
                pipeline = self.pipeline_table[event.pipeline_id]
                reg_table = pipeline._registrations

            else:
                reg_table = self._registrations

            if event.MESSAGE_TYPE not in reg_table:
                # TODO: log.warning this
                print(f'Message type not found in registration table: {event!s}')
                continue

            for func in reg_table[event.MESSAGE_TYPE]:
                try:
                    await _invoke_async(func, event)

                except Exception as e:
                    # TODO: log.warning this
                    print(f'Error running registered callback: {e!s}')

    async def _wait_response(
            self,
            message_type: PSRPMessageType,
    ) -> PSRPEvent:
        wait_event = asyncio.Queue()

        def wait_callback(event):
            wait_event.put_nowait(event)

        self._registrations[message_type].append(wait_callback)
        return await wait_event.get()


class _PipelineBase:
    _EVENT_TYPE = threading.Event
    _LOCK_TYPE = threading.Lock
    _STREAM_TYPE = PSDataStream
    _TASK_TYPE = PipelineTask

    def __init__(
            self,
            runspace_pool: _RunspacePoolBase,
            pipeline: PipelineType,
    ):
        self.runspace_pool = runspace_pool
        self.pipeline = pipeline
        self.streams = {
            'debug': self._STREAM_TYPE(),
            'error': self._STREAM_TYPE(),
            'information': self._STREAM_TYPE(),
            'progress': self._STREAM_TYPE(),
            'verbose': self._STREAM_TYPE(),
            'warning': self._STREAM_TYPE(),
        }

        self._host_tasks: typing.Dict[int, typing.Any] = {}
        self._close_lock = self._LOCK_TYPE()

        self._registrations: typing.Dict[PSRPMessageType, typing.List[typing.Callable[[PSRPEvent], typing.Any]]] = {
            mt: [] for mt in [
                PSRPMessageType.DebugRecord,
                PSRPMessageType.ErrorRecord,
                PSRPMessageType.InformationRecord,
                PSRPMessageType.PipelineHostCall,
                PSRPMessageType.PipelineOutput,
                PSRPMessageType.PipelineState,
                PSRPMessageType.ProgressRecord,
                PSRPMessageType.VerboseRecord,
                PSRPMessageType.WarningRecord,
            ]
        }

    @property
    def had_errors(self) -> bool:
        return self.state == PSInvocationState.Failed

    @property
    def state(self) -> PSInvocationState:
        return self.pipeline.state

    def _setup_pipeline_callbacks(
            self,
            output_stream: typing.Optional[typing.Union[AsyncPSDataStream, PSDataStream]] = None,
            completed: typing.Optional[typing.Union[asyncio.Event, threading.Event]] = None,
    ):
        internal_completed = self._EVENT_TYPE()
        if output_stream is None:
            output_stream = self._STREAM_TYPE()
            task = self._TASK_TYPE(internal_completed, output_stream)

        else:
            task = self._TASK_TYPE(internal_completed)

        stream_map = {
            PSRPMessageType.PipelineOutput: output_stream,
            PSRPMessageType.DebugRecord: self.streams['debug'],
            PSRPMessageType.ErrorRecord: self.streams['error'],
            PSRPMessageType.InformationRecord: self.streams['information'],
            PSRPMessageType.ProgressRecord: self.streams['progress'],
            PSRPMessageType.VerboseRecord: self.streams['verbose'],
            PSRPMessageType.WarningRecord: self.streams['warning'],
        }
        for message_type in stream_map.keys():
            def add_stream(event):
                stream_map[event.MESSAGE_TYPE].append(event.ps_object)
            self._registrations[message_type].append(add_stream)

        state_callback = functools.partial(
            self._state_callback,
            streams=stream_map.values(),
            internal_completed=internal_completed,
            user_completed=completed,
        )
        self._registrations[PSRPMessageType.PipelineState].append(state_callback)
        self._registrations[PSRPMessageType.PipelineHostCall].append(self._host_callback)

        return task

    def _state_callback(
            self,
            event: PSRPEvent,
            streams: typing.List[typing.Union[AsyncPSDataStream, PSDataStream]],
            internal_completed: typing.Union[asyncio.Event, threading.Event],
            user_completed: typing.Optional[typing.Union[asyncio.Event, threading.Event]] = None,
    ):
        [s.finalize() for s in streams]

        internal_completed.set()

        if user_completed:
            user_completed.set()

    def _host_callback(
            self,
            event: PSRPEvent,
    ):
        a = ''


class Pipeline(_PipelineBase):

    def close(self):
        with self._close_lock:
            pipeline = self.runspace_pool.pipeline_table.get(self.pipeline.pipeline_id)
            if not pipeline or pipeline.pipeline.state == PSInvocationState.Disconnected:
                return

            self.runspace_pool.connection.close(self.pipeline.pipeline_id)
            del self.runspace_pool.pipeline_table[self.pipeline.pipeline_id]

    def connect(self) -> typing.Iterable[typing.Optional[PSObject]]:
        return self.connect_async().wait()

    def connect_async(
            self,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
    ) -> PipelineTask:
        self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.protocol.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        return self._setup_pipeline_callbacks(output_stream, completed)

    def invoke(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            output_stream: typing.Optional[PSDataStream] = None,
            buffer_input: bool = True,
    ) -> typing.Optional[typing.Iterable[typing.Optional[PSObject]]]:
        return self.invoke_async(
            input_data=input_data,
            output_stream=output_stream,
            buffer_input=buffer_input,
        ).wait()

    def invoke_async(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
            buffer_input: bool = True,
    ) -> PipelineTask:
        try:
            self.pipeline.invoke()
        except MissingCipherError:
            self.runspace_pool.exchange_key()
            self.pipeline.invoke()

        self.runspace_pool.connection.command(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.connection.send_all()

        task = self._setup_pipeline_callbacks(output_stream, completed)

        if input_data is not None:
            self._send_input(input_data, buffer_input)

        return task

    def stop(self):
        """Stops a running pipeline.

        Stops a running pipeline and waits for it to stop.
        """
        self.stop_async().wait()

    def stop_async(
            self,
            completed: typing.Optional[threading.Event] = None,
    ) -> PipelineTask:
        self.runspace_pool.connection.signal(self.pipeline.pipeline_id)

        completed_event = threading.Event()

        def state_callback(event):
            if self.state not in [PSInvocationState.Stopped, PSInvocationState.Completed]:
                return

            if completed:
                completed.set()

            completed_event.set()

        self._registrations[PSRPMessageType.PipelineState].append(state_callback)

        return PipelineTask(completed_event)

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

    def _setup_pipeline_callbacks(
            self,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
    ) -> PipelineTask:
        task = super()._setup_pipeline_callbacks(output_stream, completed)

        def close_on_state(event):
            self.close()
        self._registrations[PSRPMessageType.PipelineState].append(close_on_state)

        return task

    def _host_call(
            self,
            event: PSRPEvent,
    ):
        host_call = event.ps_object
        host = getattr(self, 'host', None) or self.runspace_pool.host

        mi = host_call.mi
        mp = host_call.mp
        method_metadata = get_host_method(host, mi, mp)
        func = method_metadata.invoke

        error_record = None
        try:
            return_value = func() if func else _not_implemented()

        except Exception as e:
            setattr(e, 'mi', mi)

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

            if method_metadata.is_void:
                # TODO: Check this behaviour in real life.
                self.streams['error'].append(error_record)
                self.stop()
                return

        if not method_metadata.is_void:
            self.runspace_pool.protocol.host_response(host_call.ci, return_value=return_value,
                                                      error_record=error_record)
            self.runspace_pool.connection.send_all()


class AsyncPipeline(_PipelineBase):
    _EVENT_TYPE = asyncio.Event
    _LOCK_TYPE = asyncio.Lock
    _STREAM_TYPE = AsyncPSDataStream
    _TASK_TYPE = AsyncPipelineTask

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
        task = await self.connect_async()
        return await task.wait()

    async def connect_async(
            self,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> AsyncPipelineTask:
        await self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.pool.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        return await self._setup_pipeline_callbacks(output_stream, completed)

    async def invoke(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            buffer_input: bool = True,
    ) -> typing.Optional[typing.AsyncIterable[typing.Optional[PSObject]]]:
        """Invoke the pipeline.

        Invokes the pipeline and yields the output as it is received. This takes the same arguments as
        `:meth:begin_invoke()` but instead of returning once the pipeline is started this will wait until it is
        complete.

        Returns:
            (typing.AsyncIterable[PSObject]): An async iterable that can be iterated to receive the output objects as
                they are received.
        """
        output_task = await self.invoke_async(
            input_data=input_data,
            output_stream=output_stream,
            buffer_input=buffer_input,
        )
        return await output_task.wait()

    async def invoke_async(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
            buffer_input: bool = True,
    ) -> AsyncPipelineTask:
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

        task = await self._setup_pipeline_callbacks(output_stream, completed)

        if input_data is not None:
            await self._send_input(input_data, buffer_input)

        return task

    async def stop(self):
        """Stops a running pipeline.

        Stops a running pipeline and waits for it to stop.
        """
        task = await self.stop_async()
        await task.wait()

    async def stop_async(
            self,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> AsyncPipelineTask:
        await self.runspace_pool.connection.signal(self.pipeline.pipeline_id)

        completed_event = asyncio.Event()

        def state_callback(event):
            if self.state not in [PSInvocationState.Stopped, PSInvocationState.Completed]:
                return

            if completed:
                completed.set()

            completed_event.set()

        self._registrations[PSRPMessageType.PipelineState].append(state_callback)

        return AsyncPipelineTask(completed_event)

    async def _setup_pipeline_callbacks(
            self,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
    ) -> AsyncPipelineTask:
        task = super()._setup_pipeline_callbacks(output_stream, completed)

        async def close_on_state(event):
            await self.close()
        self._registrations[PSRPMessageType.PipelineState].append(close_on_state)

        return task

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

    async def _host_callback(
            self,
            event: PSRPEvent,
    ):
        host_call = event.ps_object
        host = getattr(self, 'host', None) or self.runspace_pool.host

        mi = host_call.mi
        mp = host_call.mp
        method_metadata = get_host_method(host, mi, mp)
        func = method_metadata.invoke

        error_record = None
        try:
            return_value = await _invoke_async(func or _not_implemented)

        except Exception as e:
            setattr(e, 'mi', mi)

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

            if method_metadata.is_void:
                # TODO: Check this behaviour in real life.
                self.streams['error'].append(error_record)
                await self.stop()
                return

        if not method_metadata.is_void:
            self.runspace_pool.protocol.host_response(host_call.ci, return_value=return_value,
                                                      error_record=error_record)
            await self.runspace_pool.connection.send_all()


class _CommandMetaPipelineBase(_PipelineBase):

    def __init__(
            self,
            runspace_pool: _RunspacePoolBase,
            name: typing.Union[str, typing.List[str]],
            command_type: CommandTypes = CommandTypes.All,
            namespace: typing.Optional[typing.List[str]] = None,
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        pipeline = ClientGetCommandMetadata(
            runspace_pool=runspace_pool.pool,
            name=name,
            command_type=command_type,
            namespace=namespace,
            arguments=arguments,
        )
        super().__init__(runspace_pool, pipeline)


class AsyncCommandMetaPipeline(_CommandMetaPipelineBase, AsyncPipeline):
    pass


class CommandMetaPipeline(_CommandMetaPipelineBase, Pipeline):
    pass


class _PowerShellBase(_PipelineBase):

    def __init__(
            self,
            runspace_pool: _RunspacePoolBase,
            add_to_history: bool = False,
            apartment_state: typing.Optional[ApartmentState] = None,
            history: typing.Optional[str] = None,
            host: typing.Optional[PSHost] = None,
            is_nested: bool = False,
            remote_stream_options: RemoteStreamOptions = RemoteStreamOptions.none,
            redirect_shell_error_to_out: bool = True,
    ):
        pipeline = ClientPowerShell(
            runspace_pool=runspace_pool.pool,
            add_to_history=add_to_history,
            apartment_state=apartment_state,
            history=history,
            is_nested=is_nested,
            remote_stream_options=remote_stream_options,
            redirect_shell_error_to_out=redirect_shell_error_to_out,
        )
        super().__init__(runspace_pool, pipeline)
        self.host = host

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


class PowerShell(_PowerShellBase, Pipeline):

    def invoke_async(
            self,
            input_data: typing.Optional[typing.Iterable] = None,
            output_stream: typing.Optional[PSDataStream] = None,
            completed: typing.Optional[threading.Event] = None,
            buffer_input: bool = True,
    ) -> PipelineTask:
        if self.host:
            self.pipeline.host = self.host.get_host_info()

        self.pipeline.no_input = input_data is None

        return super().invoke_async(input_data, output_stream, completed, buffer_input)


class AsyncPowerShell(_PowerShellBase, AsyncPipeline):

    async def invoke_async(
            self,
            input_data: typing.Optional[typing.Union[typing.Iterable, typing.AsyncIterable]] = None,
            output_stream: typing.Optional[AsyncPSDataStream] = None,
            completed: typing.Optional[asyncio.Event] = None,
            buffer_input: bool = True,
    ) -> AsyncPipelineTask:
        if self.host:
            self.pipeline.host = await _invoke_async(self.host.get_host_info)

        self.pipeline.no_input = input_data is None

        return await super().invoke_async(input_data, output_stream, completed, buffer_input)
