# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import contextlib
import queue
import threading
import typing

from ._compat import (
    asynccontextmanager,
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
    PipelineHostCallEvent,
    RunspaceAvailabilityEvent,
    RunspacePoolHostCallEvent,
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
        self._ci_table = {}
        self._event_task = None
        self._registrations = {}
        condition_type = asyncio.Condition if isinstance(self, AsyncRunspacePool) else threading.Condition
        for mt in PSRPMessageType:
            self._registrations[mt] = [condition_type()]

    @property
    def max_runspaces(self) -> int:
        return self.pool.max_runspaces

    @property
    def min_runspaces(self) -> int:
        return self.pool.min_runspaces

    @property
    def state(self) -> RunspacePoolState:
        return self.pool.state

    def create_disconnected_power_shells(self) -> typing.List:
        return [p for p in self.pipeline_table.values() if p.pipeline.state == PSInvocationState.Disconnected]

    def _get_event_registrations(
            self,
            event: PSRPEvent,
    ) -> typing.List:
        if isinstance(event, (
                PipelineHostCallEvent,
                RunspaceAvailabilityEvent,
                RunspacePoolHostCallEvent,
        )):
            self._ci_table[int(event.ps_object.ci)] = event

        if event.pipeline_id:
            pipeline = self.pipeline_table[event.pipeline_id]
            reg_table = pipeline._registrations

        else:
            reg_table = self._registrations

        return reg_table[event.MESSAGE_TYPE]


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

            with self._wait_condition(PSRPMessageType.SessionCapability) as sess, \
                    self._wait_condition(PSRPMessageType.RunspacePoolInitData) as init, \
                    self._wait_condition(PSRPMessageType.ApplicationPrivateData) as data:

                self._event_task = threading.Thread(target=self._response_listener)
                self._event_task.start()
                sess.wait()
                init.wait()
                data.wait()
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

        with self._wait_condition(PSRPMessageType.RunspacePoolState) as cond:
            self._event_task = threading.Thread(target=self._response_listener)
            self._event_task.start()
            cond.wait()

    def close(self):
        """Closes the Runspace Pool.

        Closes the Runspace Pool, any outstanding pipelines, and the connection to the peer.
        """
        if self.state != RunspacePoolState.Disconnected:
            [p.close() for p in list(self.pipeline_table.values())]

            with self._wait_condition(PSRPMessageType.RunspacePoolState) as cond:
                self.connection.close()
                cond.wait()

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
                runspace_pool = RunspacePool(connection, host=host, runspace_pool_id=rpid)
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
        self._send_and_wait_for(PSRPMessageType.EncryptedSessionKey)

    def reset_runspace_state(self) -> bool:
        """Resets the Runspace Pool session state.

        Resets the variable table for the Runspace Pool back to the default state. This only works on peers with a
        protocol version of 2.3 or greater (PowerShell v5+).
        """
        ci = self.pool.reset_runspace_state()
        return self._validate_runspace_availability(ci)

    def set_max_runspaces(
            self,
            value: int,
    ) -> bool:
        ci = self.pool.set_max_runspaces(value)
        return self._validate_runspace_availability(ci)

    def set_min_runspaces(
            self,
            value: int,
    ) -> bool:
        ci = self.pool.set_min_runspaces(value)
        return self._validate_runspace_availability(ci)

    def get_available_runspaces(self) -> int:
        ci = self.pool.get_available_runspaces()

        self._send_and_wait_for(
            PSRPMessageType.RunspaceAvailability,
            lambda: ci in self._ci_table,
        )

        return self._ci_table.pop(ci).count

    def _response_listener(self):
        while True:
            event = self.connection.wait_event()
            if event is None:
                return

            registrations = self._get_event_registrations(event)
            for reg in registrations:
                if isinstance(reg, threading.Condition):
                    with reg:
                        reg.notify_all()

                    continue

                try:
                    reg(event)

                except Exception as e:
                    # TODO: log.warning this
                    print(f'Error running registered callback: {e!s}')

    def _send_and_wait_for(
            self,
            message_type: PSRPMessageType,
            predicate: typing.Optional[typing.Callable] = None,
    ):
        with self._wait_condition(message_type) as cond:
            self.connection.send_all()
            cond.wait_for(predicate) if predicate else cond.wait()

    def _validate_runspace_availability(
            self,
            ci: typing.Optional[int]
    ) -> bool:
        if ci is None:
            return True

        self._send_and_wait_for(
            PSRPMessageType.RunspaceAvailability,
            lambda: ci in self._ci_table,
        )

        return self._ci_table.pop(ci).success

    @contextlib.contextmanager
    def _wait_condition(
            self,
            message_type: PSRPMessageType,
    ) -> typing.Iterable[threading.Condition]:
        cond = self._registrations[message_type][0]
        with cond:
            yield cond


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

            async with self._wait_condition(PSRPMessageType.SessionCapability) as sess, \
                    self._wait_condition(PSRPMessageType.RunspacePoolInitData) as init, \
                    self._wait_condition(PSRPMessageType.ApplicationPrivateData) as data:

                self._event_task = asyncio_create_task(self._response_listener())
                await sess.wait()
                await init.wait()
                await data.wait()
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

        async with self._wait_condition(PSRPMessageType.RunspacePoolState) as cond:
            self._event_task = asyncio_create_task(self._response_listener())
            await cond.wait()

    async def close(self):
        if self.state != RunspacePoolState.Disconnected:
            tasks = [p.close() for p in self.pipeline_table.values()] + [self.connection.close()]
            async with self._wait_condition(PSRPMessageType.RunspacePoolState) as cond:
                await asyncio.gather(*tasks)
                await cond.wait_for(lambda: self.state != RunspacePoolState.Opened)

        await self.connection.stop()
        await asyncio.gather(self._event_task)

    async def disconnect(self):
        self.pool.state = RunspacePoolState.Disconnecting
        await self.connection.disconnect()
        self.pool.state = RunspacePoolState.Disconnected

        for pipeline in self.pipeline_table.values():
            pipeline.pipeline.state = PSInvocationState.Disconnected

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
        await self._send_and_wait_for(PSRPMessageType.EncryptedSessionKey)

    async def reset_runspace_state(self) -> bool:
        ci = self.pool.reset_runspace_state()
        return await self._validate_runspace_availability(ci)

    async def set_max_runspaces(
            self,
            value: int,
    ) -> bool:
        ci = self.pool.set_max_runspaces(value)
        return await self._validate_runspace_availability(ci)

    async def set_min_runspaces(
            self,
            value: int,
    ) -> bool:
        ci = self.pool.set_min_runspaces(value)
        return await self._validate_runspace_availability(ci)

    async def get_available_runspaces(self) -> int:
        ci = self.pool.get_available_runspaces()

        await self._send_and_wait_for(
            PSRPMessageType.RunspaceAvailability,
            lambda: ci in self._ci_table,
        )

        return self._ci_table.pop(ci).count

    async def _response_listener(self):
        while True:
            event = await self.connection.wait_event()
            if event is None:
                return

            registrations = self._get_event_registrations(event)
            for reg in registrations:
                if isinstance(reg, asyncio.Condition):
                    async with reg:
                        reg.notify_all()

                    continue

                try:
                    await _invoke_async(reg, event)

                except Exception as e:
                    # TODO: log.warning this
                    print(f'Error running registered callback: {e!s}')

    async def _send_and_wait_for(
            self,
            message_type: PSRPMessageType,
            predicate: typing.Optional[typing.Callable] = None,
    ):
        async with self._wait_condition(message_type) as cond:
            await self.connection.send_all()
            await (cond.wait_for(predicate) if predicate else cond.wait())

    async def _validate_runspace_availability(
            self,
            ci: typing.Optional[int]
    ) -> bool:
        if ci is None:
            return True

        await self._send_and_wait_for(
            PSRPMessageType.RunspaceAvailability,
            lambda: ci in self._ci_table,
        )

        return self._ci_table.pop(ci).success

    @asynccontextmanager
    async def _wait_condition(
            self,
            message_type: PSRPMessageType,
    ) -> typing.AsyncIterable[asyncio.Condition]:
        cond = self._registrations[message_type][0]
        async with cond:
            yield cond


class _PipelineBase:

    def __init__(
            self,
            runspace_pool: _RunspacePoolBase,
            pipeline: PipelineType,
    ):
        self.runspace_pool = runspace_pool
        self.pipeline = pipeline
        self.streams = {}

        self._output_stream = None
        self._completed = None
        self._completed_stop = None
        self._host_tasks: typing.Dict[int, typing.Any] = {}
        self._close_lock = asyncio.Lock() if isinstance(self, AsyncPipeline) else threading.Lock()

        self._registrations = {}
        for mt in PSRPMessageType:
            self._registrations[mt] = []

        self._registrations[PSRPMessageType.PipelineState].append(self._on_state)
        self._registrations[PSRPMessageType.PipelineHostCall].append(self._on_host_call)
        self._registrations[PSRPMessageType.PipelineOutput].append(
            lambda e: self._output_stream.append(e.ps_object))

        stream_type = AsyncPSDataStream if isinstance(self, AsyncPipeline) else PSDataStream
        for name, mt in [
            ('debug', PSRPMessageType.DebugRecord),
            ('error', PSRPMessageType.ErrorRecord),
            ('information', PSRPMessageType.InformationRecord),
            ('progress', PSRPMessageType.ProgressRecord),
            ('verbose', PSRPMessageType.VerboseRecord),
            ('warning', PSRPMessageType.WarningRecord),
        ]:
            stream = stream_type()
            self.streams[name] = stream
            self._registrations[mt].append(lambda e: stream.append(e.ps_object))

    @property
    def had_errors(self) -> bool:
        return self.state == PSInvocationState.Failed

    @property
    def state(self) -> PSInvocationState:
        return self.pipeline.state

    def _new_task(
            self,
            output_stream: typing.Optional[typing.Union[AsyncPSDataStream, PSDataStream]] = None,
            completed: typing.Optional[typing.Union[asyncio.Event, threading.Event]] = None,
            for_stop: bool = False
    ):
        if isinstance(self, AsyncPipeline):
            stream_type = AsyncPSDataStream
            event_type = asyncio.Event
            task_type = AsyncPipelineTask

        else:
            stream_type = PSDataStream
            event_type = threading.Event
            task_type = PipelineTask

        task_output = None
        if not output_stream:
            output_stream = task_output = stream_type()
        self._output_stream = output_stream

        completed = completed or event_type()
        if for_stop:
            self._completed_stop = completed

        else:
            self._completed = completed
            # TODO: Reset streams so we can append and iterate even more data

        return task_type(completed, task_output)

    def _on_state(
            self,
            event: PSRPEvent,
    ):
        raise NotImplementedError()

    def _on_host_call(
            self,
            event: PSRPEvent,
    ):
        raise NotImplementedError()


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
        task = self._new_task(output_stream, completed)

        self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.pool.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        return task

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
        task = self._new_task(output_stream, completed)

        try:
            self.pipeline.invoke()
        except MissingCipherError:
            self.runspace_pool.exchange_key()
            self.pipeline.invoke()

        self.runspace_pool.connection.command(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.connection.send_all()

        if input_data is not None:
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
        task = self._new_task(completed=completed, for_stop=True)
        self.runspace_pool.connection.signal(self.pipeline.pipeline_id)

        return task

    def _on_state(
            self,
            event: PSRPEvent,
    ):
        try:
            self.close()

        finally:
            [s.finalize() for s in self.streams.values()]
            self._output_stream.finalize()
            self._output_stream = None
            self._completed.set()
            self._completed = None

            if self._completed_stop:
                self._completed_stop.set()
                self._completed_stop = None

    def _on_host_call(
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
            self.runspace_pool.pool.host_response(host_call.ci, return_value=return_value,
                                                  error_record=error_record)
            self.runspace_pool.connection.send_all()


class AsyncPipeline(_PipelineBase):

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
        task = self._new_task(output_stream, completed)

        await self.runspace_pool.connection.connect(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        self.runspace_pool.pool.pipeline_table[self.pipeline.pipeline_id] = self.pipeline
        self.pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        return task

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
        task = self._new_task(output_stream, completed)

        try:
            self.pipeline.invoke()
        except MissingCipherError:
            await self.runspace_pool.exchange_key()
            self.pipeline.invoke()

        await self.runspace_pool.connection.command(self.pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self.pipeline.pipeline_id] = self
        await self.runspace_pool.connection.send_all()

        if input_data is not None:
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
        task = self._new_task(completed=completed, for_stop=True)
        await self.runspace_pool.connection.signal(self.pipeline.pipeline_id)

        return task

    async def _on_state(
            self,
            event: PSRPEvent,
    ):
        try:
            await self.close()

        finally:
            [s.finalize() for s in self.streams.values()]
            self._output_stream.finalize()
            self._output_stream = None
            self._completed.set()
            self._completed = None

            if self._completed_stop:
                self._completed_stop.set()
                self._completed_stop = None

    async def _on_host_call(
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
