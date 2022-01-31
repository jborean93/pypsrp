# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import logging
import threading
import typing as t
import uuid

from psrpcore import (
    ApplicationPrivateDataEvent,
    ClientGetCommandMetadata,
    ClientHostResponder,
    ClientPowerShell,
    ClientRunspacePool,
    Command,
    DebugRecordEvent,
    EncryptedSessionKeyEvent,
    ErrorRecordEvent,
    GetRunspaceAvailabilityEvent,
    InformationRecordEvent,
    InvalidPipelineState,
    MissingCipherError,
    PipelineHostCallEvent,
    PipelineOutputEvent,
    PipelineStateEvent,
    ProgressRecordEvent,
    PSRPEvent,
    RunspacePoolHostCallEvent,
    RunspacePoolInitDataEvent,
    RunspacePoolStateEvent,
    SessionCapabilityEvent,
    SetRunspaceAvailabilityEvent,
    UserEventEvent,
    VerboseRecordEvent,
    WarningRecordEvent,
)
from psrpcore.types import (
    ApartmentState,
    CommandTypes,
    DebugRecord,
    ErrorCategoryInfo,
    ErrorRecord,
    InformationRecord,
    NETException,
    ProgressRecord,
    PSInvocationState,
    PSThreadOptions,
    RemoteStreamOptions,
    RunspacePoolState,
    VerboseRecord,
    WarningRecord,
)

from ._compat import SupportsIndex
from ._connection.connection import ConnectionInfo, SyncConnection
from ._exceptions import (
    PipelineFailed,
    PipelineStopped,
    PSRPError,
    RunspaceNotAvailable,
)
from ._host import PSHost, get_host_method

PipelineType = t.TypeVar("PipelineType", bound=t.Union[ClientGetCommandMetadata, ClientPowerShell])
EventType = t.TypeVar("EventType", bound=PSRPEvent)
T = t.TypeVar("T")

log = logging.getLogger(__name__)


def _wrap_invoke(
    callable: t.Callable[..., None],
    *args: t.Any,
    purpose: str = "",
    **kwargs: t.Any,
) -> None:
    try:
        callable(*args, **kwargs)
    except Exception:
        log.exception(f"Failed to invoke callback for {purpose}")


class SyncPSDataCollection(t.Generic[T], t.List[T]):
    """PowerShell Data Collection.

    A data collection for a PowerShell stream. This collection can add an
    event subscriber for when a value is being added, was added, and finally
    marked as complete. It can also be used as an iterator that waits for each
    new entry until the collection is complete. The values for a collection
    depend on the stream that this represents.

    The events are only fired when an element is added by the remote PowerShell
    pipeline. Any normal list additions are treated as normal.
    FIXME: Add doc link to event subscribers.

    Collections are never marked as completed by the PowerShell pipeline so
    this event cannot be relied upon for detecting if a pipeline is finished.
    The `on_completed` event is only fired if the `complete()` function is
    called manually by other code.

    Args:
        blocking_iterator: A keyword argument that when True will cause the
            for loop of this collection to wait until for new entries until the
            collection is marked as complete.

    Attributes:
        blocking_iterator: Whether to block the iterator until a new item is
            added or the collection is marked as completed.
        completed: Whether the collection has been marked as completed.

    Events:
        on_completed: Called when the collection has been marked as completed.
        data_added: Called when the value has been added to the collection from
            the PowerShell pipeline.
        data_adding: Called when the value is about to be added to the
            collection from the PowerShell pipeline.
    """

    def __init__(
        self,
        *args: t.Any,
        blocking_iterator: bool = False,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.blocking_iterator = blocking_iterator
        self.completed = False

        self.on_completed = SyncEventHandler[bool]("PSDataCollection on_completed")
        self.data_added = SyncEventHandler[T]("PSDataCollection data_added")
        self.data_adding = SyncEventHandler[T]("PSDataCollection data_adding")

        self._add_condition = threading.Condition()

    def __iter__(
        self,
    ) -> t.Iterator[T]:
        return self._iter_next()

    def append(
        self,
        value: T,
    ) -> None:
        if self.completed:
            raise ValueError("Objects cannot be added to a closed buffer")
        return super().append(value)

    def complete(self) -> None:
        """Mark the collection as complete and no more entries will be added."""
        self.completed = True
        self.on_completed(True)
        with self._add_condition:
            self._add_condition.notify_all()

    def insert(
        self,
        index: SupportsIndex,
        value: T,
    ) -> None:
        if self.completed:
            raise ValueError("Objects cannot be added to a closed buffer")
        return super().insert(index, value)

    def _append(
        self,
        value: T,
    ) -> None:
        """Used internally to add a new value to the collection and fire the events."""
        # If the collection is marked as complete PowerShell just silently drops
        # the record and doesn't fire any event.
        if self.completed:
            return

        self.data_adding(value)

        with self._add_condition:
            self.append(value)
            self._add_condition.notify_all()

        self.data_added(value)

    def _iter_next(self) -> t.Iterator[T]:
        idx = 0
        while True:
            with self._add_condition:
                if idx < len(self):
                    value = self[idx]
                    idx += 1
                    yield value

                elif self.completed or not self.blocking_iterator:
                    break

                else:
                    self._add_condition.wait()


class MessageResult(t.Generic[EventType]):
    """Result handler for out of band PSRP responses.

    Handler used to wait for a particular result to be received from the peer.
    This will be set when the message type requested has been processed and if
    the callable is also set when the event matches the callable's condition.

    Args:
        event_type: The PSRP message type to wait for and return.
        condition: Optional callable that takes in the event and returns a bool
            that signifies whether the vent is the result to wait for.
    """

    def __init__(
        self,
        event_type: t.Type[EventType],
        condition: t.Optional[t.Callable[[EventType], bool]] = None,
    ) -> None:
        self._condition = condition
        self._event_type = event_type
        self._event = threading.Event()
        self._result: t.Optional[t.Union[ErrorRecord, EventType]] = None

    def wait(self) -> EventType:
        """Waits for message to be set.

        Waits for the message to be set and returns the result.

        Returns:
            EventType: The set event type.
        """
        log.debug("Waiting for %s", self._event_type)
        self._event.wait()
        log.debug("Wait for %s complete", self._event_type)

        if isinstance(self._result, ErrorRecord):
            raise PSRPError(self._result.Exception.Message).with_traceback(self._result.TargetObject)

        # An event is only set when _result is added
        return t.cast(EventType, self._result)

    def set(
        self,
        value: t.Union[ErrorRecord, EventType],
    ) -> bool:
        """Attempts to set the message result.

        Attempts to set the result of the message based on the message type
        and optional condition applied to the object.

        Args:
            value: The event to set or an ErrorRecord on a failure.

        Returns:
            bool: Whether the event matched the message result condition and
            was set.
        """
        if isinstance(value, ErrorRecord) or (
            isinstance(value, self._event_type) and (not self._condition or self._condition(value))
        ):
            log.debug("Setting result for %s", self._event_type)
            self._result = value
            self._event.set()
            return True

        else:
            return False


class SyncEventHandler(t.Generic[T]):
    """Sync Event Handler Subscriber.

    Used to store and run event subscriptions defined by the caller. This is
    used in various places to provide a mechanism that can run caller defined
    code on specific events.

    Example:
        To subscribe to an async event use += on the event attribute itself.

        >>> def user_callback(argument):
        ...     print(f"Callback called with {argument}")
        ...
        >>> runspace.state_changed += user_callback # Add callback
        >>> runspace.state_changed -= user_callback # Remove callback

    Note:
        Events are run in the same thread as the event runner and will block the
        main thread until they are complete.
    """

    def __init__(
        self,
        purpose: str,
    ) -> None:
        self._callbacks: t.List[t.Callable[[T], None]] = []
        self._purpose = purpose

    def __call__(
        self,
        event: T,
    ) -> None:
        for callback in self._callbacks:
            _wrap_invoke(callback, event, purpose=self._purpose)

    def __iadd__(
        self,
        value: t.Callable[[T], None],
    ) -> "SyncEventHandler[T]":
        self._callbacks.append(value)
        return self

    def __isub__(
        self,
        value: t.Callable[[T], None],
    ) -> "SyncEventHandler[T]":
        self._callbacks.remove(value)
        return self


class ThreadTask(t.Generic[T]):
    """Wrapper around a thread that can return a result.

    This is a wrapper around a Python thread that runs the task specified and
    passes along the return value of that task.

    Args:
        task: The callable to run.
        args: The *args to pass to the callable.
        kwargs: The **kwargs to pass to the callable.
    """

    def __init__(
        self,
        task: t.Callable[..., T],
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        self._task = task
        self._thread = threading.Thread(target=self._wrap_task, args=args, kwargs=kwargs)
        self._thread.start()
        self._result: t.Optional[t.Union[T, Exception]] = None

    def _wrap_task(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        try:
            self._result = self._task(*args, **kwargs)
        except Exception as e:
            self._result = e

    def wait(self) -> T:
        """Waits for the task to complete

        Waits for the task of this thread to complete and returns the result of
        that task.

        Returns:
            T: The result from the task of this thread.
        """
        # join() but check for cancel (raise cancelled error)
        self._thread.join()

        if isinstance(self._result, Exception):
            raise self._result

        # A thread is only ended when _result is set
        return t.cast(T, self._result)


@dataclasses.dataclass
class SyncPSDataStreams:
    """Streams generated by PowerShell invocations.

    This contains the streams and the data that is generated by a sync
    PowerShell invocation.

    Attributes:
        debug: The stream containing debug records.
        error: The stream containing error records.
        information: The stream containing information records.
        progress: The stream containing progress records.
        verbose: The stream containing verbose records.
        warning: The stream containing warning records.
    """

    debug: SyncPSDataCollection[DebugRecord] = dataclasses.field(default_factory=SyncPSDataCollection[DebugRecord])
    error: SyncPSDataCollection[ErrorRecord] = dataclasses.field(default_factory=SyncPSDataCollection[ErrorRecord])
    information: SyncPSDataCollection[InformationRecord] = dataclasses.field(
        default_factory=SyncPSDataCollection[InformationRecord]
    )
    progress: SyncPSDataCollection[ProgressRecord] = dataclasses.field(
        default_factory=SyncPSDataCollection[ProgressRecord]
    )
    verbose: SyncPSDataCollection[VerboseRecord] = dataclasses.field(
        default_factory=SyncPSDataCollection[VerboseRecord]
    )
    warning: SyncPSDataCollection[WarningRecord] = dataclasses.field(
        default_factory=SyncPSDataCollection[WarningRecord]
    )

    def clear_streams(self) -> None:
        """Removes all items from all the data streams."""
        self.debug.clear()
        self.error.clear()
        self.information.clear()
        self.progress.clear()
        self.verbose.clear()
        self.warning.clear()


class SyncRunspacePool:
    """Sync Runspace Pool.

    A pool of Runspaces on a remote connection that can be used to invoke
    multiple PowerShell pipelines. This is designed to replicate the .NET
    `RunspacePool Class`_.

    FIXME: Details about events.

    Use the `is_available` attribute when calling :meth:`get_runspace_pools` to
    determine if the Runspace Pool is available for reconnection. If it is not
    available then the pool is still connected to by another client.

    Note:
        The `stream_*` attributes are largely unused by a Runspace Pool as
        stream data is typically targeted to a specific pipeline rather than a
        Runspace.

    Args:
        connection_info: The connection info used for this Runspace Pool.
        apartment_state: Apartment state of the thread used to execute commands
            withih this RunspacePool.
        thread_options: Controls how new threads are created for each command
            invocation.
        min_runspaces: The minimum number of Runspaces that should exist in
            this pool. Should be greater than or equal to 1.
        max_runspaces: The maximum number of Runspaces that can exist in this
            pool. Should be greater than or equal to min_runspaces.
        host: The PSHost associated with this Runspace Pool.
        application_arguments: Application arguments to be sent to the server
            which can be retrieved with `$PSSenderInfo.ApplicationArguments`.
        runspace_pool_id: Used internally for reconnection operations.

    Attributes:
        host: The PSHost associated with this Runspace Pool.
        is_available: Whther the this Runspace pool is available and will
            accept subsequent commands like `connect`, `open`, etc.
        pipeline_table: Mapping of all pipelines associated with this Runspace
            Pool.
        streams: Contains any objects from a stream sent to the Runspace Pool.

    Events:
        state_changed: An event that is called when the Runspace Pool state has
            changed.
        user_event: An event that is called when a user defined event has been
            received by the remote PowerShell pipeline.

    ... _RunspacePool Class:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.runspacepool
    """

    def __init__(
        self,
        connection_info: ConnectionInfo,
        apartment_state: ApartmentState = ApartmentState.Unknown,
        thread_options: PSThreadOptions = PSThreadOptions.Default,
        min_runspaces: int = 1,
        max_runspaces: int = 1,
        host: t.Optional[PSHost] = None,
        application_arguments: t.Optional[t.Dict] = None,
        runspace_pool_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        if min_runspaces < 1 or max_runspaces < min_runspaces:
            raise ValueError(
                "min_runspaces must be greater than 0 and max_runspaces must be greater than min_runspaces."
            )

        self.connection_info = connection_info
        self.host = host
        self.is_available = True
        self.pipeline_table: t.Dict[uuid.UUID, SyncPipeline] = {}
        self.state_changed = SyncEventHandler[RunspacePoolStateEvent]("RunspacePool state_changed")
        self.user_event = SyncEventHandler[UserEventEvent]("RunspacePool user_event")

        # Typically streams are not received on a Runspace but Exchange Online has emitted a warning record here
        # and the error stream is used for failed host call information.
        self.streams = SyncPSDataStreams()

        self._connection: t.Optional[SyncConnection] = None
        self._connection_error: t.Optional[ErrorRecord] = None
        self._new_client = False  # Used for reconnection as a new client.
        self._pool = ClientRunspacePool(
            apartment_state=apartment_state,
            host=host.get_host_info() if host else None,
            thread_options=thread_options,
            min_runspaces=min_runspaces,
            max_runspaces=max_runspaces,
            application_arguments=application_arguments,
            runspace_pool_id=runspace_pool_id,
        )
        self._result_handler: t.List[MessageResult] = []
        self._key_exchange_task: t.Optional[t.Callable[[], bool]] = None

    def __enter__(self) -> "SyncRunspacePool":
        if self.state == RunspacePoolState.Disconnected:
            self.connect()

        else:
            self.open()

        return self

    def __exit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        self.close()

    @property
    def max_runspaces(self) -> int:
        """The maximum number of Runspaces that can exist in the pool."""
        return self._pool.max_runspaces

    @property
    def min_runspaces(self) -> int:
        """The minimum number of Runspaces that exist in the pool."""
        return self._pool.min_runspaces

    @property
    def state(self) -> RunspacePoolState:
        """The current Runspace Pool state."""
        return self._pool.state

    @property
    def application_private_data(self) -> t.Dict[str, t.Any]:
        """Custom data received from the server when the pool was opened."""
        return self._pool.application_private_data

    @property
    def max_payload_size(self) -> int:
        """The maximum payload size that can be sent to without fragmenting."""
        return self._connection.get_fragment_size() - 72 if self._connection else 0

    @classmethod
    def get_runspace_pools(
        cls,
        connection_info: ConnectionInfo,
        host: t.Optional[PSHost] = None,
    ) -> t.Iterator["SyncRunspacePool"]:
        """Queries the server for Runspace Pools.

        Queries the server for all the Runspace Pools that are either open and
        in use or disconnected and ready for a connect operation. Each yielded
        Runspace Pool can be reconnected to if the :attr:`is_available` is
        `True` otherwise the pool is in use by another client.

        The `host` provided will be associated with the Runspace Pool when it
        is connected to.

        Note:
            Disconnection/Reconnection operations are only supported by the
            WSMan connection type.

        Args:
            connection_info: The connection of the server to query.
            host: The PSHost to associate with each yielded Runspace Pool.

        Returns:
            Iterator[AsyncRunspacePool]: Iterates all the Runspace Pools on the
            connection supplied. The :attr:`is_available` attribute can be used
            to filter Runspace Pools that can be connected to.
        """
        for res in connection_info.enumerate_sync():
            runspace_pool = SyncRunspacePool(res.connection_info, host=host, runspace_pool_id=res.rpid)

            if res.state == "Disconnected":
                runspace_pool._pool.state = RunspacePoolState.Disconnected
                runspace_pool._new_client = True

                for pipeline in res.pipelines:
                    ps = SyncPowerShell(runspace_pool, pipeline_id=pipeline.pid)
                    ps._pipeline.state = PSInvocationState.Disconnected
                    runspace_pool.pipeline_table[pipeline.pid] = ps

            else:
                runspace_pool._pool.state = RunspacePoolState.Opened
                runspace_pool.is_available = False

            yield runspace_pool

    def create_disconnected_power_shells(self) -> t.List["SyncPipeline"]:
        """Get all disconnected pipelines in the Runspace Pool.

        Returns a list of all pipelines of this Runspace Pool that are in the
        disconnected state. This only works for Runspace Pools retrieved by
        :meth:`get_runspace_pool` to allow the caller to retrieve a list of
        pipelines that are associated with the Runspace Pool.

        Before the pipeline can be reconnected the Runspace Pool itself must be
        connected.

        Returns:
            t.List[AsyncPipeline]: List of all pipelines of the Runspace Pool
            that are in a disconnected state.
        """
        if not self._new_client:
            raise PSRPError(
                "Can only enumerate disconnected PowerShell pipelines on a Runspace Pool retrieved with "
                "get_runspace_pools()"
            )

        return [p for p in self.pipeline_table.values() if p._pipeline.state == PSInvocationState.Disconnected]

    def connect(self) -> None:
        """Connects to a disconnected Runspace Pool.

        Connected, or reconnects to an existing Runspace Pool. This is used
        instead of :meth:`open` to connect to a Runspace Pool returned by
        :meth:`get_runspace_pools`.

        Note:
            Disconnection/Reconnection operations are only supported by the
            WSMan connection type.
        """
        connection = self._get_connection()
        if self._new_client:
            sess_event = MessageResult(SessionCapabilityEvent)
            self._result_handler.append(sess_event)

            init_event = MessageResult(RunspacePoolInitDataEvent)
            self._result_handler.append(init_event)

            data_event = MessageResult(ApplicationPrivateDataEvent)
            self._result_handler.append(data_event)

            self._pool.connect()
            connection.connect()
            sess_event.wait()
            init_event.wait()
            data_event.wait()

        else:
            connection.reconnect()

        self._pool.state = RunspacePoolState.Opened

    def open(self) -> None:
        """Opens the Runspace Pool.

        Opens the Runspace Pool through the connection specified. A pool must
        be opened before it can be used.
        """
        log.info("Opening Runspace Pool - %s", self._pool.runspace_pool_id)

        connection = self._get_connection()
        self._pool.open()

        sess_event = MessageResult(SessionCapabilityEvent)
        self._result_handler.append(sess_event)

        state_event = MessageResult(RunspacePoolStateEvent)
        self._result_handler.append(state_event)

        connection.create()
        sess_event.wait()

        connection.send_all()
        state_event.wait()

    def close(self) -> None:
        """Closes the Runspace Pool.

        Closes the Runspace Pool freeing any resources on the server.
        """
        if self._connection_error:
            return

        connection = self._get_connection()
        if self.state != RunspacePoolState.Disconnected:
            log.info("Closing Runspace Pool - %s", self._pool.runspace_pool_id)
            state_event = MessageResult(
                RunspacePoolStateEvent,
                lambda e: e.state != RunspacePoolState.Opened,
            )
            self._result_handler.append(state_event)

            connection.close()
            state_event.wait()
            self.pipeline_table = {}

    def disconnect(self) -> None:
        """Disconnects a Runspace Pool.

        Disconnects a Runspace Pool allowing it to be connected to for future
        operations or by another client. A Runspace Pool must be disconnected
        before a new client can connect to it.

        Note:
            Disconnection/Reconnection operations are only supported by the
            WSMan connection type.
        """
        # Allows reconnection on the same RP object.
        self._new_client = False

        connection = self._get_connection()
        self._pool.state = RunspacePoolState.Disconnecting
        connection.disconnect()
        self._pool.state = RunspacePoolState.Disconnected

    def exchange_key(self) -> None:
        """Exchange the Crypto Session Key.

        Exchanges the serialization cryptographic session used used to encrypt
        serialized secure strings. The PowerShell pipeline will call this
        automatically if sending any secure string value as a parameter or as
        input. This will still need to be called if receiving a secure string
        without having first sent one.
        """
        log.info("Starting Runspace Pool Key Exchange - %s", self._pool.runspace_pool_id)

        connection = self._get_connection()
        event = MessageResult(EncryptedSessionKeyEvent)
        self._result_handler.append(event)

        self._pool.exchange_key()
        connection.send_all()
        event.wait()

    def reset_runspace_state(self) -> bool:
        """Resets Runspace Pool State.

        Resets the Runspace Pool state, including the variable table, to the
        default state.

        Note:
            This operation was introduced with the 2.3 protocol version which
            is PowerShell 5.1 or newer.

        Returns:
            bool: Whether the reset was successful.
        """
        connection = self._get_connection()
        ci = self._pool.reset_runspace_state()
        return self._send_set_runspace_availability_ci(connection, ci, "Resetting Runspace Pool State")

    def set_max_runspaces(
        self,
        value: int,
    ) -> bool:
        """Set the maximum runspace pool count.

        Sets the maximum number of runspaces that the pool maintains in
        anticipation of new requests. The maximum runspace count must be
        greater than the minimum runspace count at all times.

        Note:
            A failure to adjust the count will not raise an exception, use the
            return value to validate if this call was successful or not.

        Args:
            value: The maximum number of runspaces in the pool to set.

        Returns:
            bool: Whether the change was succesful or not.
        """
        connection = self._get_connection()
        ci = self._pool.set_max_runspaces(value)
        return self._send_set_runspace_availability_ci(connection, ci, f"Setting maximum pool count to {value}")

    def set_min_runspaces(
        self,
        value: int,
    ) -> bool:
        """Set the minimum runspace pool count.

        Sets the minimum number of runspaces that the pool maintains in
        anticipation of new requests. The minimum runspace count must be
        greater than 0 and never more than the minimum runspace count.

        Note:
            A failure to adjust the count will not raise an exception, use the
            return value to validate if this call was successful or not.

        Args:
            value: The minimum number of runspaces in the pool to set.

        Returns:
            bool: Whether the change was succesful or not.
        """
        connection = self._get_connection()
        ci = self._pool.set_min_runspaces(value)
        return self._send_set_runspace_availability_ci(connection, ci, f"Setting minimum pool count to {value}")

    def get_available_runspaces(self) -> int:
        """Get the number of available runspaces.

        Gets the number of runspaces that are currently available at the time
        of calling this method.

        Returns:
            int: The number of available runspaces in the pool.
        """
        connection = self._get_connection()
        event = MessageResult(GetRunspaceAvailabilityEvent, lambda e: e.ci == ci)
        self._result_handler.append(event)

        ci = self._pool.get_available_runspaces()

        log.info("Getting available Runspace Pool Count - ci %s - %s", ci, self._pool.runspace_pool_id)
        connection.send_all()
        result = event.wait()

        return result.count

    def _get_connection(self) -> SyncConnection:
        if not self.is_available:
            raise RunspaceNotAvailable("This Runspace Pool is connected to another client")

        if self._connection_error:
            raise PSRPError(self._connection_error.Exception.Message).with_traceback(
                self._connection_error.TargetObject
            )

        if not self._connection:
            self._connection = self.connection_info.create_sync(self._pool, self._event_received)

        return self._connection

    def _event_received(
        self,
        event: PSRPEvent,
    ) -> bool:
        if event.pipeline_id:
            pipeline = self.pipeline_table[event.pipeline_id]
            return pipeline._event_received(event)

        log.debug("Processing event for Runspace Pool - %r", event)

        queued_data = False
        if isinstance(event, RunspacePoolStateEvent):
            self.state_changed(event)

            if event.state == RunspacePoolState.Broken:
                self._connection_error = event.reason
                for handler in list(self._result_handler):
                    if handler.set(event.reason):
                        self._result_handler.remove(handler)

                for pipeline in self.pipeline_table.values():
                    pipeline._event_received(event)

        elif isinstance(event, UserEventEvent):
            self.user_event(event)

        elif isinstance(event, RunspacePoolHostCallEvent) and self.host:
            queued_data = self._invoke_host_call(self.host, event, self.streams.error)

        elif isinstance(event, EncryptedSessionKeyEvent) and self._key_exchange_task:
            queued_data = self._key_exchange_task()

        elif isinstance(event, DebugRecordEvent):
            self.streams.debug._append(event.record)

        elif isinstance(event, ErrorRecordEvent):
            self.streams.error._append(event.record)

        elif isinstance(event, InformationRecordEvent):
            self.streams.information._append(event.record)

        elif isinstance(event, ProgressRecordEvent):
            self.streams.progress._append(event.record)

        elif isinstance(event, VerboseRecordEvent):
            self.streams.verbose._append(event.record)

        elif isinstance(event, WarningRecordEvent):
            self.streams.warning._append(event.record)

        for handler in list(self._result_handler):
            if handler.set(event):
                self._result_handler.remove(handler)

        return queued_data

    def _invoke_host_call(
        self,
        host: PSHost,
        event: t.Union[RunspacePoolHostCallEvent, PipelineHostCallEvent],
        error_stream: SyncPSDataCollection[ErrorRecord],
    ) -> bool:
        log.info("Invoking host call - %r", event)
        ci = event.ci
        mi = event.method_identifier
        mp = event.method_parameters

        client_responder = ClientHostResponder(self._pool)
        method_metadata = get_host_method(host, client_responder, ci, mi, mp)
        func = method_metadata.invoke

        error_record = None
        try:
            return_value = func()

        except Exception as e:
            log.exception("Failed to invoke host call - ci %s", ci)
            setattr(e, "mi", mi)

            # Any failure for non-void methods should be propagated back to the peer.
            e_msg = str(e)
            if not e_msg:
                e_msg = f"{type(e).__qualname__} when running {mi!s}"

            return_value = None
            error_record = ErrorRecord(
                Exception=NETException(e_msg),
                FullyQualifiedErrorId="RemoteHostExecutionException",
                CategoryInfo=ErrorCategoryInfo(
                    Reason="Exception",
                ),
            )

            if not method_metadata.format_return:
                # PowerShell continues on even if the exception was on the client host
                error_stream._append(error_record)
                return False

        if method_metadata.format_return:
            if error_record:
                self._pool.host_response(ci, error_record=error_record)
                return True

            responder = method_metadata.format_return

            try:
                responder(return_value)
            except MissingCipherError:
                # This is tricky as the code runs in the listener "thread". Will
                # start the key exchange and as a post action send the host
                # response as the needed data is available.
                self._pool.exchange_key()

                def resend_response() -> bool:
                    responder(return_value)
                    return True

                self._key_exchange_task = resend_response

            return True

        return False

    def _send_set_runspace_availability_ci(
        self,
        connection: SyncConnection,
        ci: t.Optional[int],
        action: str,
    ) -> bool:
        if ci is None:
            return True

        log.info("%s - ci %s - %s", action, ci, self._pool.runspace_pool_id)

        event = MessageResult(SetRunspaceAvailabilityEvent, lambda e: e.ci == ci)
        self._result_handler.append(event)

        connection.send_all()
        result = event.wait()

        return result.success


class SyncPipeline(t.Generic[PipelineType]):
    """Common Pipeline Operations."""

    def __init__(
        self,
        runspace_pool: SyncRunspacePool,
        pipeline: PipelineType,
    ) -> None:
        self.runspace_pool = runspace_pool
        self.state_changed = SyncEventHandler[PipelineStateEvent]("Pipeline state_changed")
        self.streams = SyncPSDataStreams()
        self._stream_output = SyncPSDataCollection[t.Any]()
        self._explicit_output = False

        self._close_lock = threading.Lock()
        self._pipeline: PipelineType = pipeline
        self._pipeline_error: t.Optional[ErrorRecord] = None
        self._result_handler: t.List[MessageResult] = []

    @property
    def had_errors(self) -> bool:
        """Whether the pipeline had errors.

        This checks whether the pipeline had any errors added to the error
        stream.

        Note:
            This is not True if the pipeline failed to run. This only checks
            the error stream.
        """
        return len(self.streams.error) > 0

    @property
    def state(self) -> PSInvocationState:
        """The current pipeline state."""
        return self._pipeline.state

    def close(self) -> None:
        """Closes the pipeline.

        Closes the pipeline resource on the peer. This is done automatically
        when the pipeline is completed or the Runspace Pool is closed but can
        be called manually if desired.
        """
        with self._close_lock:
            pipeline = self.runspace_pool.pipeline_table.get(self._pipeline.pipeline_id)
            if not pipeline or pipeline._pipeline.state == PSInvocationState.Disconnected:
                return

            log.info("Closing pipeline - %s", self._pipeline.pipeline_id)
            connection = self.runspace_pool._get_connection()
            connection.close(self._pipeline.pipeline_id)
            del self.runspace_pool.pipeline_table[self._pipeline.pipeline_id]

    def connect(self) -> t.List[t.Any]:
        """Connect to the pipeline.

        Connects to the pipeline that is in a disconnected state. Once
        connected it will wait until the running pipeline is complete and
        output the values from the pipeline since it was connected.

        Returns:
            t.List[t.Any]: The output from the connected pipeline.
        """
        task = self.connect_async()
        return task.wait()

    def connect_async(
        self,
        output_stream: t.Optional[SyncPSDataCollection[t.Any]] = None,
        completed: t.Optional[t.Callable[[], None]] = None,
    ) -> ThreadTask[t.List[t.Any]]:
        """Connect to the pipeline as a background task.

        Connects to the pipelines that is in a disconnected state and continue
        to wait until it is complete as a background task. When running the
        output will be added to the defined output_stream or returned as a list
        if not explicit output stream was defined.

        The `completed` keyword argument is an optional callable that is
        called when the pipeline has completed. This can be used to mark a
        stream as completed if enumerating a blocking collection or to do any
        other work.

        Note:
            The completed callback is run as part of the final steps of the
            task. It cannot be used to await on invoke_async returned task or
            start a new pipeline as that will cause a deadlock.

        Args:
            output_stream: Add any output data to this stream rather than
                returning the output as a list.
            completed: A callable that is called once the task has completed
                running.

        Returns:
            ThreadTask[t.List[t.Any]]: Returns a thread task that can be
            waited on to get the final output. If output_stream is specified
            the return value of this task is an empty list.
        """
        if output_stream is not None:
            self._explicit_output = True
            self._stream_output = output_stream
        else:
            self._stream_output = SyncPSDataCollection[t.Any]()

        task_ready = threading.Event()
        task = ThreadTask(self._pipelines_task, task_ready, completed=completed)
        task_ready.wait()

        connection = self.runspace_pool._get_connection()
        connection.connect(self._pipeline.pipeline_id)
        self.runspace_pool.pipeline_table[self._pipeline.pipeline_id] = self
        self.runspace_pool._pool.pipeline_table[self._pipeline.pipeline_id] = self._pipeline
        self._pipeline.state = PSInvocationState.Running
        # TODO: Seems like we can't create a nested pipeline from a disconnected one.

        return task

    def invoke(
        self,
        input_data: t.Optional[t.Iterable] = None,
        output_stream: t.Optional[SyncPSDataCollection[t.Any]] = None,
        buffer_input: bool = True,
    ) -> t.List[t.Any]:
        """Invoke the pipeline.

        Invokes the pipeline on the associated Runspace Pool. If no
        output_stream is defined then the output is returned as a list,
        otherwise the output is added to the stream specified and this module
        returns an empty list.

        The function will wait until the pipeline has completed running, use
        :meth:`invoke_async` to run a pipeline in the background.

        The input_data can either be a normal iterable, including and iterator.

        Example:
            Send input as a normal iterable

            >>> ps.invoke([1, 2])

            Send input as an sync iterator

            >>> def sync_iter():
            ...     yield 1
            ...     yield 2
            ...
            >>> ps.invoke(sync_iter())

        Args:
            input_data: Any data to send as input to the first command in the
                pipeline.
            output_stream: Add any output data to this stream rather than
                returning the output as a list.
            buffer_input: Buffer the input data so it only sends the input once
                it fills the buffer rather than send each input as it's own
                individual message.

        Returns:
            t.List[t.Any]: The output of the pipeline, will be an empty list
            if output_stream is set.
        """
        output_task = self.invoke_async(
            input_data=input_data,
            output_stream=output_stream,
            buffer_input=buffer_input,
        )
        return output_task.wait()

    def invoke_async(
        self,
        input_data: t.Optional[t.Iterable] = None,
        output_stream: t.Optional[SyncPSDataCollection[t.Any]] = None,
        completed: t.Optional[t.Callable[[], None]] = None,
        buffer_input: bool = True,
    ) -> ThreadTask[t.List[t.Any]]:
        """Invoke the pipeline as a background task.

        Invokes the pipeline on the associated Runspace Pool and continues to
        run it in a background task. The function will wait until the pipeline
        details have been sent to the peer and all the input has been sent.
        Once that is done a task is returned that can be awaited on for it to
        complete.

        The keyword arguments are the same as :meth:`invoke` except for the
        addition of `completed` which is a callable that is called when the
        pipeline has completed. This can be used to mark a stream as completed
        if enumerating a blocking collection or to do any other work.

        Note:
            The completed callback is run as part of the final steps of the
            task. It cannot be used to await on invoke_async returned task or
            start a new pipeline as that will cause a deadlock.

        Args:
            input_data: Any data to send as input to the first command in the
                pipeline.
            output_stream: Add any output data to this stream rather than
                returning the output as a list.
            completed: A callable that is called once the task has completed
                running.
            buffer_input: Buffer the input data so it only sends the input once
                it fills the buffer rather than send each input as it's own
                individual message.

        Returns:
            ThreadTask[t.List[t.Any]]: Returns a thread task that can be waited
            on to get the final output. If output_stream is specified the
            return value of this task is an empty list.
        """
        log.info("Starting pipeline - %s", self._pipeline.pipeline_id)
        if output_stream is not None:
            self._explicit_output = True
            self._stream_output = output_stream
        else:
            self._stream_output = SyncPSDataCollection[t.Any]()

        task_ready = threading.Event()
        task = ThreadTask(self._pipelines_task, task_ready, completed=completed)
        task_ready.wait()

        try:
            self._pipeline.start()
        except MissingCipherError:
            self.runspace_pool.exchange_key()
            self._pipeline.start()

        self.runspace_pool.pipeline_table[self._pipeline.pipeline_id] = self
        connection = self.runspace_pool._get_connection()
        connection.command(self._pipeline.pipeline_id)
        connection.send_all()

        if input_data is not None:
            log.debug("Sending pipeline input - %s", self._pipeline.pipeline_id)

            for data in input_data:
                try:
                    self._pipeline.send(data)

                except MissingCipherError:
                    self.runspace_pool.exchange_key()
                    self._pipeline.send(data)

                except InvalidPipelineState as e:
                    if e.current_state == PSInvocationState.Failed:
                        err = str(self._pipeline_error) if self._pipeline_error else "Unknown failure."
                        raise PipelineFailed(
                            f"Pipeline failed while sending input: {err}",
                            error_record=self._pipeline_error,
                        ) from e

                    else:
                        raise PipelineFailed(f"Pipeline ended while sending input: {e}") from e

                if buffer_input:
                    connection.send(buffer=True)
                else:
                    connection.send_all()

            log.debug("Sending pipeline input eof - %s", self._pipeline.pipeline_id)
            self._pipeline.send_eof()
            connection.send_all()

        return task

    def stop(self) -> None:
        """Stops a running pipeline.

        Sends a signal to stop the running pipeline and wait for it to stop.
        The connect/invoke task await will raise a :class:`PipelineStopped`
        exception to indicate it was stopped.

        Use :meth:`stop_async` to send the stop signal but not wait for the
        signal to be processed and the pipeline to be stopped.

        Note:
            A pipeline may not response to a stop signal if it is running a
            non-PowerShell command, like a .NET function or native command. This
            will block until the pipeline has a chance to respond to the signal
            and stop it's operations.
        """
        task = self.stop_async()
        task.wait()

    def stop_async(
        self,
        completed: t.Optional[t.Callable[[], None]] = None,
    ) -> ThreadTask[None]:
        """Stops the pipeline as a background task.

        Will create a task that sends the background stop signal and wait for
        it to complete all in a background task. This returned task can be
        awaited to wait until the stop was processed and acknoledged by the
        server otherwise it will continue to run in the background.

        Use :meth:`stop` to send the stop signal and wait until it is complete.

        Note:
            Disconnecting from the Runspace Pool this pipeline is attached with
            will not cancel the background task.

        Args:
            completed: A callable that is called once the task has completed
                running and the signal was acknowledged by the server.

        Returns:
            ThreadTask: Returns a thread task that can be waited on to wait
            until the stop was processed and acknowledged by the server.
        """
        log.info("Stopping pipeline - %s", self._pipeline.pipeline_id)
        connection = self.runspace_pool._get_connection()

        def inner_stop() -> None:
            if self.state != PSInvocationState.Running:
                return

            connection.signal(self._pipeline.pipeline_id)

            if completed:
                _wrap_invoke(completed, purpose="stop_async")

        # The signal call blocks until an Ack but stop_async should just send
        # the signal and return a task that waits for the ack.
        task = ThreadTask(inner_stop)
        return task

    def _event_received(
        self,
        event: PSRPEvent,
    ) -> bool:
        log.debug("Processing event for Pipeline - %r", event)

        host = getattr(self, "host", None) or self.runspace_pool.host
        queued_data = False

        if isinstance(event, RunspacePoolStateEvent) and event.reason is not None:
            for handler in list(self._result_handler):
                handler.set(event.reason)
                self._result_handler.remove(handler)

        elif isinstance(event, PipelineStateEvent):
            if event.state == PSInvocationState.Failed:
                self._pipeline_error = event.reason

            self.state_changed(event)

        elif isinstance(event, PipelineHostCallEvent) and host:
            queued_data = self.runspace_pool._invoke_host_call(host, event, self.streams.error)

        elif isinstance(event, PipelineOutputEvent):
            self._stream_output._append(event.data)

        elif isinstance(event, DebugRecordEvent):
            self.streams.debug._append(event.record)

        elif isinstance(event, ErrorRecordEvent):
            self.streams.error._append(event.record)

        elif isinstance(event, InformationRecordEvent):
            self.streams.information._append(event.record)

        elif isinstance(event, ProgressRecordEvent):
            self.streams.progress._append(event.record)

        elif isinstance(event, VerboseRecordEvent):
            self.streams.verbose._append(event.record)

        elif isinstance(event, WarningRecordEvent):
            self.streams.warning._append(event.record)

        for handler in list(self._result_handler):
            if handler.set(event):
                self._result_handler.remove(handler)

        return queued_data

    def _pipelines_task(
        self,
        ready: threading.Event,
        completed: t.Optional[t.Callable[[], None]] = None,
    ) -> t.List[t.Any]:
        event = MessageResult(PipelineStateEvent, lambda e: e.state != PSInvocationState.Running)
        self._result_handler.append(event)
        ready.set()

        state = event.wait()
        log.debug("Pipeline has ended - %r - %s", state, self._pipeline.pipeline_id)

        if completed:
            _wrap_invoke(completed, purpose="pipeline task completion")

        self.close()

        # For some weird reason the state may not be present on a failed or
        # stopped pipeline. Just replicate the error msg as best as it can.
        if state.state == PSInvocationState.Failed:
            err = str(state.reason) if state.reason else "Unknown failure."
            raise PipelineFailed(err, error_record=state.reason)

        elif state.state == PSInvocationState.Stopped:
            err = str(state.reason) if state.reason else "The pipeline has been stopped."
            raise PipelineStopped(err, error_record=state.reason)

        return [] if self._explicit_output else list(self._stream_output)


class SyncCommandMetaPipeline(SyncPipeline[ClientGetCommandMetadata]):
    """Get Command Metadata Pipeline.

    A Pipeline that can retrieve command metadata in a Runspace Pool. This is
    essentially a dedicated pipeline for the `Get-Command` cmdlet used in
    PowerShell. The `Get-Command` cmdlet can still be used with
    :class:`AsyncPowerShell`, this is just another mechanism to do the same
    thing. The `Export-PSSession` uses this type of Pipeline when being called
    through PowerShell.

    FIXME: Add doc link to event subscribers.

    Args:
        runspace_pool: The RunspacePool the pipeline is associated with.
        name: The names of the commands to search for. This accepts both a
            string or list of strings and includes support for PowerShell's
            wildcard matching using `*`, `?`, and `[]`.
        command_type: The command types to search for.
        namespace: The namespaces, modules to search in.
        arguments: Arguments to apply to each command in order to get the
            metadata of provider specific dynamic parameters.
        pipeline_id: Used internally for reconnection operations.

    Events:
        state_changed: An event that is called when the Pipeline state has
            changed.
    """

    def __init__(
        self,
        runspace_pool: SyncRunspacePool,
        name: t.Union[str, t.List[str]],
        command_type: CommandTypes = CommandTypes.All,
        namespace: t.Optional[t.List[str]] = None,
        arguments: t.Optional[t.List[str]] = None,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        pipeline = ClientGetCommandMetadata(
            runspace_pool=runspace_pool._pool,
            name=name,
            command_type=command_type,
            namespace=namespace,
            arguments=arguments,
            pipeline_id=pipeline_id,
        )
        super().__init__(runspace_pool, pipeline)


class SyncPowerShell(SyncPipeline[ClientPowerShell]):
    """PowerShell Pipeline.

    A Pipeline that executes PowerShell commands or scripts on a Runspace Pool.
    This is the main pipeline type used in PowerShell Remoting and is designed
    to replicate the .NET `PowerShell`_ class.

    FIXME: Add doc link to event subscribers.

    The pipeline contains a stream attribute for each PowerShell stream and the
    output is either returned by the invoke() methods or added to the explicit
    output pipeline passed into those methods.

    A pipeline can be invoked multiple times and stream records are appended to
    their respective streams. When a stream has been manually marked as complete
    the records are dropped.

    Args:
        runspace_pool: The RunspacePool the pipeline is associated with.
        apartment_state: ApartmentState of the thread in which the command is
            executed.
        history: If defined, this adds the string to the history of the Runspace
            Pool the command is running in.
        host: The PSHost to run the command with, if undefined it will use the
            host of the Runspace Pool the command is running in.
        is_nested: Whether this pipeline is nested to run inside another
            pipeline.
        remote_stream_options: Options for the error, warning, verbose, and
            debug streams.
        redirect_shell_error_to_out: Redirects the global error output pipe to
            the commands error output pipe.
        pipeline_id: Used internally for reconnection operations.

    Attributes:
        runspace_pool: The RunspacePool the pipeline is associated with.
        streams: The stream data for the pipeline.

    Events:
        state_changed: An event that is called when the Pipeline state has
            changed.

    .. _PowerShell:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.powershell
    """

    def __init__(
        self,
        runspace_pool: SyncRunspacePool,
        apartment_state: t.Optional[ApartmentState] = None,
        history: t.Optional[str] = None,
        host: t.Optional[PSHost] = None,
        is_nested: bool = False,
        remote_stream_options: RemoteStreamOptions = RemoteStreamOptions.none,
        redirect_shell_error_to_out: bool = True,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        pipeline = ClientPowerShell(
            runspace_pool=runspace_pool._pool,
            add_to_history=history is not None,
            apartment_state=apartment_state,
            history=history,
            host=host.get_host_info() if host else None,
            is_nested=is_nested,
            remote_stream_options=remote_stream_options,
            redirect_shell_error_to_out=redirect_shell_error_to_out,
            pipeline_id=pipeline_id,
        )
        super().__init__(runspace_pool, pipeline)
        self.host = host

    def add_argument(
        self,
        value: t.Any,
    ) -> "SyncPowerShell":
        """Add argument to the current command.

        Adds a positional argument value to the current command in the
        pipeline's command collection.

        Args:
            value: The value to use as the positional argument.

        Returns:
            AsyncPowerShell: The current PowerShell pipeline instance.
        """
        self._pipeline.add_argument(value)
        return self

    def add_command(
        self,
        cmdlet: t.Union[str, Command],
        use_local_scope: t.Optional[bool] = None,
    ) -> "SyncPowerShell":
        """Add command to the pipeline.

        Adds a new command to the current statement. Multiple commands in a
        statement are piped together.

        Example:
            To replicate ``Get-Item -Path /tmp | Select-Object`` with this API.

            >>> ps.add_command("Get-Item").add_parameter("Path", "/tmp")
            >>> ps.add_command("Select-Object")

        Use :meth:`add_statement` to separate commands that are run on separate
        lines/statements.

        Args:
            cmdlet: The command to run as a str or the :class:psrpcore.Command`
                object.
            use_local_scope: Mark the command as running in the local scope of
                the pipeline.

        Returns:
            AsyncPowerShell: The current PowerShell pipeline instance.
        """
        self._pipeline.add_command(cmdlet, use_local_scope)
        return self

    def add_parameter(
        self,
        name: str,
        value: t.Any,
    ) -> "SyncPowerShell":
        """Add parameter to the command.

        Adds a parameter and value to the current command in the pipeline's
        command collection.

        Note:
            For switch parameter, use True or False as the value.

        Args:
            name: The name of the parameter.
            value: The value of the parameter to add.

        Returns:
            AsyncPowerShell: The current PowerShell pipeline instance.
        """
        self._pipeline.add_parameter(name, value)
        return self

    def add_parameters(
        self,
        **parameters: t.Any,
    ) -> "SyncPowerShell":
        """Add multiple parameters to the command.

        Adds multiple parameters to the current command in the pipeline's
        command collection.

        Args:
            parameters: Each keyword is treated as the parameter name with its
                value.

        Returns:
            AsyncPowerShell: The current PowerShell pipeline instance.
        """
        self._pipeline.add_parameters(**parameters)
        return self

    def add_script(
        self,
        script: str,
        use_local_scope: t.Optional[bool] = None,
    ) -> "SyncPowerShell":
        """Add a script to the pipeline.

        Adds a free form script to the current statement. Like
        :meth:`add_command` this script is added on a statement and multiple
        scripts/commands in the same statement are piped together. Use
        :meth:`add_statement` to separate commands and scripts from each other.

        Args:
            script: The script to run.
            use_local_scope: Mark the script as running in the local scope of
                the pipeline.

        Returns:
            AsyncPowerShell: The current PowerShell pipeline instance.
        """
        self._pipeline.add_script(script, use_local_scope)
        return self

    def add_statement(self) -> "SyncPowerShell":
        """Add a new statement to the pipeline.

        Adds a new satement to separate commands and scripts from each other.
        This is akin to using a semicolon or newline in a script.

        Returns:
            AsyncPowerShell: The current PowerShell pipeline instance.
        """
        self._pipeline.add_statement()
        return self

    def invoke_async(
        self,
        input_data: t.Optional[t.Iterable] = None,
        output_stream: t.Optional[SyncPSDataCollection[t.Any]] = None,
        completed: t.Optional[t.Callable[[], None]] = None,
        buffer_input: bool = True,
    ) -> ThreadTask[t.List[t.Any]]:
        self._pipeline.metadata.no_input = input_data is None

        return super().invoke_async(input_data, output_stream, completed, buffer_input)
