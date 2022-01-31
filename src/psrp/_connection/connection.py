# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import enum
import logging
import typing as t
import uuid

from psrpcore import ClientRunspacePool, PSRPEvent, PSRPPayload

log = logging.getLogger(__name__)

T = t.TypeVar("T", bound=t.Callable)
AsyncEventCallable = t.Callable[[PSRPEvent], t.Awaitable[bool]]
SyncEventCallable = t.Callable[[PSRPEvent], bool]


class ConnectionInfo:
    """Base class for all connection info implementations.

    This is the base class for all connection info implementation that document
    the methods that must be implemented for the code to create a new
    connection class. Currently :meth:`create_sync` will be called when
    creating a synchronous Runspace Pool and :meth:`create_async` will be
    called when creating an asyncio based Runspace Pool.
    """

    def create_sync(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
    ) -> "SyncConnection":
        """Create new synchronous connection.

        Creates a new synchronous connection for the Runspace Pool to use. The
        connection should be initialised and ready to send the first PSRP
        fragment.

        Args:
            pool: The Runspace Pool state manager for the connection.
            callback: The callback method used by the connection to call when
                a new PSRP event is available.
        """
        raise NotImplementedError("Sync connection not implemented on this connection type")  # pragma: no cover

    async def create_async(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> "AsyncConnection":
        """Create new asynchronous connection.

        Creates a new asynchronous connection for the Runspace Pool to use. The
        connection should be initialised and ready to send the first PSRP
        fragment.

        Args:
            pool: The Runspace Pool state manager for the connection.
            callback: The callback coroutine used by the connection to call
                when a new PSRP event is available.
        """
        raise NotImplementedError("Async connection not implemented on this connection type")  # pragma: no cover

    def enumerate_sync(self) -> t.Iterator["EnumerationRunspaceResult"]:
        """Find Runspace Pools or Pipelines.

        Find all the Runspace Pools or Pipelines on the connection. This is
        used to enumerate any disconnected Runspace Pools or Pipelines when
        requested by the caller.

        Note:
            This is an optonal feature and is currently only implemented for
            the WSMan connection.

        Returns:
            Iterator[EnumerationRunspaceResult]: Will yield information about
            all the Runspace pools on the target and their pipelines.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover

    async def enumerate_async(self) -> t.AsyncIterator["EnumerationRunspaceResult"]:
        """Find Runspace Pools or Pipelines.

        Find all the Runspace Pools or Pipelines on the connection. This is
        used to enumerate any disconnected Runspace Pools or Pipelines when
        requested by the caller.

        Note:
            This is an optonal feature and is currently only implemented for
            the WSMan connection.

        Returns:
            AsyncIterator[EnumerationRunspaceResult]: Will yield information
            about all the Runspace pools on the target and their pipelines.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover
        yield  # type: ignore[unreachable]  # The yield is needed for mypy to see this as an Iterator  # pragma: no cover


class EnumerationRunspaceResult(t.NamedTuple):
    """Information about a Runspace Pool enumeration.

    This is used by the `enumerate` method to return information about the
    Runspace Pools that are available on the target connection.

    Attributes:
        connection_info: The connection info used to create a new connection
            for the Runspace Pool.
        rpid: The Runspace Pool ID this entry represents.
        state: The state of the Runspace Pool.
        pipelines: List of pipelines associated with the Runspace Pool.
    """

    connection_info: ConnectionInfo
    rpid: uuid.UUID
    state: str
    pipelines: t.List["EnumerationPipelineResult"]


class EnumerationPipelineResult(t.NamedTuple):
    """Information about a Pipeline enumeration.

    This is used by the `enumerate` method to return information about the
    Pipelines of a Runspace Pool that are available on the target connection.

    Attributes:
        pid: The Pipeline ID this entry represents.
        state: The state of the Pipeline.
    """

    pid: uuid.UUID
    state: str


class OutputBufferingMode(enum.Enum):
    """Output Buffer Mode for disconnecting Runspaces.

    This is used to control what a disconnected PSRP session does when the
    output generated has exceeded the buffer capacity.

    Attributes:
        NONE: No output buffer mode is selected, the mode is inherited from the
            session configuration.
        BLOCK: When the output buffer is full, execution is suspended until the
            buffer is clear.
        DROP: When the output buffer is full, execution continues replacing
            older buffered output.
    """

    NONE = enum.auto()
    BLOCK = enum.auto()
    DROP = enum.auto()


class _ConnectionBase:
    def __new__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> "_ConnectionBase":
        if cls in [_ConnectionBase, SyncConnection, AsyncConnection]:
            raise TypeError(
                f"Type {cls.__name__} cannot be instantiated; it can be used only as a base class for "
                f"PSRP connection implementations."
            )

        return super().__new__(cls)

    def __init__(
        self,
        pool: ClientRunspacePool,
    ) -> None:
        self.__buffer = bytearray()
        self.__pool = pool

    def get_fragment_size(self) -> int:
        """Get the max PSRP fragment size.

        Gets the maximum size allowed for PSRP fragments for this connection.

        Returns:
            int: The max fragment size.
        """
        return 32_768  # Used as a default for all OutOfProc transports.

    def get_runspace_pool(self) -> ClientRunspacePool:
        """Get the Runspace Pool state manager.

        Gets the Runspace Pool state manager for the connection info to use.

        Returns:
            ClientRunspacePool: The Runspace Pool state manager.
        """
        return self.__pool

    def next_payload(
        self,
        buffer: bool = False,
    ) -> t.Optional[PSRPPayload]:
        """Get the next payload.

        Get the next payload to exchange if there are any.

        Args:
            buffer: Wait until the buffer as set by :meth:`get_fragment_size`
                has been reached before sending the payload.

        Returns:
            Optional[PSRPPayload]: The PSRP payload to send if there is one.
        """
        data_buffer = self.__buffer
        fragment_size = self.get_fragment_size()
        psrp_payload = self.__pool.data_to_send(fragment_size - len(data_buffer))
        if not psrp_payload:
            return None

        data_buffer += psrp_payload.data
        if buffer and len(data_buffer) < fragment_size:
            return None

        # No longer need the buffer for now
        self.__buffer = bytearray()
        return PSRPPayload(
            data_buffer,
            psrp_payload.stream_type,
            psrp_payload.pipeline_id,
        )


class SyncConnection(_ConnectionBase):
    """Base class used for synchronous connection info implementations."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
    ) -> None:
        super().__init__(pool)
        self.__event_callback = callback

    def process_response(
        self,
        data: t.Union[PSRPEvent, PSRPPayload],
    ) -> bool:
        """Process an incoming PSRP payload.

        Processes any incoming PSRP payload received from the peer and invokes
        the pool callback function for any PSRP events inside that payload.
        Typically a PSRPPayload is the expected data type but a PSRPEvent can
        also be passed in for manual messages the connection wishes to send to
        the pool.

        Args:
            data: The PSRPPayload or PSRPEvent to process.

        Returns:
            bool: A response has been queued on the internal pool that needs to
            be sent to the peer.
        """
        pool = self.get_runspace_pool()
        if isinstance(data, PSRPEvent):
            log.debug("Calling Pool callback for %s - %r", pool.runspace_pool_id, data)
            return self.__event_callback(data)

        else:
            if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
                log.debug("Processing PSRP data %s", base64.b64encode(data.data).decode())
            pool.receive_data(data)

        data_queued = False
        while True:
            event = pool.next_event()
            if not event:
                break

            log.debug("Calling Pool callback for %s - %r", pool.runspace_pool_id, event)
            res = self.__event_callback(event)
            if res:
                data_queued = True

        return data_queued

    ################
    # PSRP Methods #
    ################

    def close(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        """Close the Runspace Pool/Pipeline.

        Closes the Runspace Pool or Pipeline inside the Runspace Pool. This
        should also close the underlying connection if no more resources are
        being used. This method must also ensure that any running pipelines are
        closed and that state has been processed by the client. It is expected
        that closing a pipeline or runspace will result in a PSRP state event
        for the respective type to indicate it has been closed/stopped.

        Args:
            pipeline_id: Closes this pipeline in the Runspace Pool.
        """
        raise NotImplementedError()  # pragma: no cover

    def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        """Create the pipeline.

        Creates a pipeline in the Runspace Pool. This should send the first
        fragment of the `CreatePipeline` PSRP message.

        Args:
            pipeline_id: The Pipeline ID that needs to be created.
        """
        raise NotImplementedError()  # pragma: no cover

    def create(self) -> None:
        """Create the Runspace Pool

        Creates the Runspace Pool specified. This should send only one fragment
        that contains at least the `SessionCapability` PSRP message. If more
        fragments can fit inside the payload they should also be sent.
        """
        raise NotImplementedError()  # pragma: no cover

    def send_all(self) -> None:
        """Send all PSRP payloads.

        Send all PSRP payloads that are ready to send.
        """
        while True:
            sent = self.send()
            if not sent:
                return

    def send(
        self,
        buffer: bool = False,
    ) -> bool:
        """Send PSRP payload.

        Send the next PSRP payload for the Runspace Pool.

        Args:
            buffer: When set to `False` will always send the payload regardless
                of the size. When set to `True` will only send the payload if
                it hits the max fragment size.

        Returns:
            bool: Set to `True` if a payload was sent and `False` if there was
            no payloads for the pool to send.
        """
        raise NotImplementedError()  # pragma: no cover

    def signal(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        """Send a signal to the Runspace Pool/Pipeline

        Sends a signal to the Pipeline. Currently PSRP only uses a signal to a
        Pipeline to request the pipeline to stop. It is expected that this will
        result in a `PipelineStateEvent` for the pipeline targeted.

        Args:
            pipeline_id: The pipeline to send the signal to.
        """
        raise NotImplementedError()  # pragma: no cover

    #####################
    # Optional Features #
    #####################

    def connect(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        """Connect to a Runspace Pool/Pipeline.

        Connects to a Runspace Pool or Pipeline that has been disconnected by
        another client. This is an optional feature that does not have to be
        implemented for the core PSRP scenarios.

        Args:
            pipeline_id: If connecting to a pipeline, this is the pipeline id.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover

    def disconnect(self) -> None:
        """Disconnect a Runspace Pool.

        Disconnects from a Runspace Pool so another client can connect to it.
        This is an optional feature that does not have to be implemented for
        the core PSRP scenarios.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover

    def reconnect(self) -> None:
        """Reconnect a Runspace Pool.

        Reconnect to a Runspace Pool that has been disconnected by the same
        client. This is an optional feature that does not have to be
        implemented for the core PSRP scenarios.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover


class AsyncConnection(_ConnectionBase):
    """Base class used for asyncio connection info implementations."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> None:
        super().__init__(pool)
        self.__event_callback = callback

    async def process_response(
        self,
        data: t.Union[PSRPEvent, PSRPPayload],
    ) -> bool:
        """Process an incoming PSRP payload.

        Processes any incoming PSRP payload received from the peer and invokes
        the pool callback coroutine for any PSRP events inside that payload.
        Typically a PSRPPayload is the expected data type but a PSRPEvent can
        also be passed in for manual messages the connection wishes to send to
        the pool.

        Args:
            data: The PSRPPayload or PSRPEvent to process.

        Returns:
            bool: A response has been queued on the internal pool that needs to
            be sent to the peer.
        """
        pool = self.get_runspace_pool()

        if isinstance(data, PSRPEvent):
            log.debug("Calling Pool callback for %s - %r", pool.runspace_pool_id, data)
            return await self.__event_callback(data)

        else:
            if log.isEnabledFor(logging.DEBUG):  # pragma: no cover
                log.debug("Processing PSRP data %s", base64.b64encode(data.data).decode())
            pool.receive_data(data)

        data_queued = False
        while True:
            event = pool.next_event()
            if not event:
                break

            log.debug("Calling Pool callback for %s - %r", pool.runspace_pool_id, event)
            res = await self.__event_callback(event)
            if res:
                data_queued = True

        return data_queued

    ################
    # PSRP Methods #
    ################

    async def close(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        """Close the Runspace Pool/Pipeline.

        Closes the Runspace Pool or Pipeline inside the Runspace Pool. This
        should also close the underlying connection if no more resources are
        being used. This method must also ensure that any running pipelines are
        closed and that state has been processed by the client. It is expected
        that closing a pipeline or runspace will result in a PSRP state event
        for the respective type to indicate it has been closed/stopped.

        Args:
            pipeline_id: Closes this pipeline in the Runspace Pool.
        """
        raise NotImplementedError()  # pragma: no cover

    async def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        """Create the pipeline.

        Creates a pipeline in the Runspace Pool. This should send the first
        fragment of the `CreatePipeline` PSRP message.

        Args:
            pipeline_id: The Pipeline ID that needs to be created.
        """
        raise NotImplementedError()  # pragma: no cover

    async def create(self) -> None:
        """Create the Runspace Pool

        Creates the Runspace Pool specified. This should send only one fragment
        that contains at least the `SessionCapability` PSRP message. If more
        fragments can fit inside the payload they should also be sent.
        """
        raise NotImplementedError()  # pragma: no cover

    async def send_all(self) -> None:
        """Send all PSRP payloads.

        Send all PSRP payloads that are ready to send.
        """
        while True:
            sent = await self.send()
            if not sent:
                return

    async def send(
        self,
        buffer: bool = False,
    ) -> bool:
        """Send PSRP payload.

        Send the next PSRP payload for the Runspace Pool.

        Args:
            buffer: When set to `False` will always send the payload regardless
                of the size. When set to `True` will only send the payload if
                it hits the max fragment size.

        Returns:
            bool: Set to `True` if a payload was sent and `False` if there was
            no payloads for the pool to send.
        """
        raise NotImplementedError()  # pragma: no cover

    async def signal(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        """Send a signal to the Runspace Pool/Pipeline

        Sends a signal to the Pipeline. Currently PSRP only uses a signal to a
        Pipeline to request the pipeline to stop. It is expected that this will
        result in a `PipelineStateEvent` for the pipeline targeted.

        Args:
            pipeline_id: The pipeline to send the signal to.
        """
        raise NotImplementedError()  # pragma: no cover

    #####################
    # Optional Features #
    #####################

    async def connect(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        """Connect to a Runspace Pool/Pipeline.

        Connects to a Runspace Pool or Pipeline that has been disconnected by
        another client. This is an optional feature that does not have to be
        implemented for the core PSRP scenarios.

        Args:
            pipeline_id: If connecting to a pipeline, this is the pipeline id.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover

    async def disconnect(self) -> None:
        """Disconnect a Runspace Pool.

        Disconnects from a Runspace Pool so another client can connect to it.
        This is an optional feature that does not have to be implemented for
        the core PSRP scenarios.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover

    async def reconnect(self) -> None:
        """Reconnect a Runspace Pool.

        Reconnect to a Runspace Pool that has been disconnected by the same
        client. This is an optional feature that does not have to be
        implemented for the core PSRP scenarios.
        """
        raise NotImplementedError("Disconnection operation not implemented on this connection type")  # pragma: no cover
