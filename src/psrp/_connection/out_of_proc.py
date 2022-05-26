# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import logging
import threading
import typing as t
import uuid
import xml.etree.ElementTree as ElementTree

from psrpcore import ClientRunspacePool, PSRPEvent, PSRPPayload, StreamType
from psrpcore.types import (
    ErrorCategoryInfo,
    ErrorRecord,
    NETException,
    PSRPMessageType,
    RunspacePoolState,
    RunspacePoolStateMsg,
)

from psrp._compat import asyncio_create_task
from psrp._connection.connection import (
    AsyncConnection,
    AsyncEventCallable,
    SyncConnection,
    SyncEventCallable,
)
from psrp._exceptions import PSRPError

log = logging.getLogger(__name__)

_EMPTY_UUID = uuid.UUID(int=0)


class SyncOutOfProcConnection(SyncConnection):
    def __new__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> "SyncOutOfProcConnection":
        if cls == SyncOutOfProcConnection:
            raise TypeError(
                f"Type {cls.__name__} cannot be instantiated; it can be used only as a base class for "
                f"PSRP out of process connection implementations."
            )

        return super().__new__(cls)  # type: ignore[return-value] # This returns OutOfProcConnection

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
    ) -> None:
        super().__init__(pool, callback)

        self.__active_pipelines: t.List[uuid.UUID] = []
        self.__listen_task: t.Optional[threading.Thread] = None
        self.__wait_condition = threading.Condition()
        self.__wait_table: t.List[t.Tuple[str, t.Optional[uuid.UUID]]] = []
        self.__write_lock = threading.Lock()
        self.__close_lock = threading.Lock()

    #####################
    # OutOfProc Methods #
    #####################

    def read(self) -> t.Optional[bytes]:
        """Get the response data.

        Called by the background thread to read any responses from the peer.
        This should block until data is available. The OutOfProc listener
        will continue to call this method and process each payload returned.

        Note:
            The OutOfProc listener will only attempt to process a payload once
            a newline has been found in the return value. While not every value
            returned needs to contain a newline it is expected for the server
            to delimit each bounary using the newline which should be returned
            as is.

        Returns:
            bytes: The raw response from the peer.
        """
        raise NotImplementedError()  # pragma: no cover

    def write(
        self,
        data: bytes,
    ) -> None:
        """Write data.

        Write a request to send to the peer. This is called when a PSRP
        message needs to be sent to the server. The data is in the form of an
        OutOfProc transport message which is a simple XML encoded value. The
        implementation may wish to pass this through as is to the server or
        modify/encapsulate it as needed by the transport.

        Args:
            data: The data to write.
        """
        raise NotImplementedError()  # pragma: no cover

    def stop(self) -> None:
        """Stop the connection.

        Called when the connection to the Runspace Pool has been closed. The
        OutOfProc implementation can use this to clean up any resources it has
        opened.
        """
        pass  # pragma: no cover

    def close(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        if pipeline_id:
            close = False
            with self.__close_lock:
                if pipeline_id in self.__active_pipelines:
                    self.__active_pipelines.remove(pipeline_id)
                    close = True

            if close:
                self._close(pipeline_id)

        else:
            # An OutOfProc server will block until all pipelines are closed.
            # The server should send the PipelineState that will finalise the
            # asyncio Tasks waiting for the pipeline to complete.
            for pid in list(self.__active_pipelines):
                self.close(pid)

            self._close(None)
            self.stop()

            if self.__listen_task:
                self.__listen_task.join()
                self.__listen_task = None

    def _close(
        self,
        pipeline_id: t.Optional[uuid.UUID],
    ) -> None:
        with self.__wait_condition:
            with self.__write_lock:
                self.write(ps_guid_packet("Close", ps_guid=pipeline_id))
            self._wait_ack("Close", pipeline_id)

    def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        with self.__wait_condition:
            with self.__write_lock:
                self.write(ps_guid_packet("Command", ps_guid=pipeline_id))
            self._wait_ack("Command", pipeline_id)

        self.send()
        self.__active_pipelines.append(pipeline_id)

    def create(self) -> None:
        self.__listen_task = threading.Thread(target=self._listen)
        self.__listen_task.start()

        self.send()

    def send(
        self,
        buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        with self.__wait_condition:
            self._send(payload)
            self._wait_ack("Data", payload.pipeline_id)

        return True

    def _send(
        self,
        payload: PSRPPayload,
    ) -> None:
        with self.__write_lock:
            self.write(ps_data_packet(payload.data, stream_type=payload.stream_type, ps_guid=payload.pipeline_id))

    def signal(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        with self.__wait_condition:
            with self.__write_lock:
                self.write(ps_guid_packet("Signal", ps_guid=pipeline_id))
            self._wait_ack("Signal", pipeline_id)

    def _wait_ack(
        self,
        action: str,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        key = (f"{action}Ack", pipeline_id)
        self.__wait_table.append(key)
        self.__wait_condition.wait_for(lambda: key not in self.__wait_table)

    def _listen(self) -> None:
        buffer = bytearray()

        try:
            while True:
                try:
                    end_idx = buffer.index(b"\n")
                except ValueError:
                    # Don't have enough data - wait for more to arrive.
                    read_data = self.read()
                    if not read_data:
                        break

                    buffer += read_data
                    continue

                data = bytes(buffer[:end_idx])
                buffer = buffer[end_idx + 1 :]

                try:
                    packet = ElementTree.fromstring(data)
                except ElementTree.ParseError as e:
                    # Use what's remaining in the buffer as part of the error message
                    msg = data + b"\n" + bytes(buffer)
                    raise PSRPError(f"Failed to parse response: {msg.decode()}") from e

                data = base64.b64decode(packet.text) if packet.text else b""
                ps_guid: t.Optional[uuid.UUID] = uuid.UUID(packet.attrib["PSGuid"])
                if ps_guid == _EMPTY_UUID:
                    ps_guid = None

                payload_data: t.Optional[PSRPPayload] = None
                if data:
                    payload_data = PSRPPayload(data, StreamType.default, ps_guid)

                    payload: t.Optional[PSRPPayload] = None
                    data_available = self.process_response(payload_data)
                    if data_available:
                        payload = self.next_payload()

                    if payload:
                        self.__wait_table.append(("DataAck", payload.pipeline_id))
                        self._send(payload)

                if packet.tag != "Data":
                    with self.__wait_condition:
                        self.__wait_table.remove((packet.tag, ps_guid))
                        self.__wait_condition.notify_all()

        except Exception as e:
            log.exception("OutOfProc listener encountered unhandled exception")
            self._break_runspace(e)

        finally:
            with self.__wait_condition:
                self.__wait_table = []
                self.__wait_condition.notify_all()

    def _break_runspace(
        self,
        exception: t.Optional[Exception] = None,
    ) -> None:
        pool = self.get_runspace_pool()

        pool.state = RunspacePoolState.Broken
        error_record: t.Optional[ErrorRecord] = None
        if exception:
            error_record = ErrorRecord(
                Exception=NETException(Message=str(exception)),
                CategoryInfo=ErrorCategoryInfo(),
                TargetObject=exception.__traceback__,
            )

        broken_event = PSRPEvent.create(
            PSRPMessageType.RunspacePoolState,
            RunspacePoolStateMsg(
                RunspaceState=pool.state,
                ExceptionAsErrorRecord=error_record,
            ),
            runspace_pool_id=pool.runspace_pool_id,
        )
        self.process_response(broken_event)


class AsyncOutOfProcConnection(AsyncConnection):
    def __new__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> "AsyncOutOfProcConnection":
        if cls == AsyncOutOfProcConnection:
            raise TypeError(
                f"Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for "
                f"PSRP out of process connection implementations."
            )

        return super().__new__(cls)  # type: ignore[return-value] # This returns AsyncOutOfProcInfo

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> None:
        super().__init__(pool, callback)

        self.__active_pipelines: t.List[uuid.UUID] = []
        self.__listen_task: t.Optional[asyncio.Task] = None
        self.__wait_condition = asyncio.Condition()
        self.__wait_table: t.List[t.Tuple[str, t.Optional[uuid.UUID]]] = []
        self.__write_lock = asyncio.Lock()
        self.__close_lock = asyncio.Lock()

    #####################
    # OutOfProc Methods #
    #####################

    async def read(self) -> t.Optional[bytes]:
        """Get the response data.

        Called by the background thread to read any responses from the peer.
        This should block until data is available. The OutOfProc listener
        will continue to call this method and process each payload returned.

        Note:
            The OutOfProc listener will only attempt to process a payload once
            a newline has been found in the return value. While not every value
            returned needs to contain a newline it is expected for the server
            to delimit each bounary using the newline which should be returned
            as is.

        Returns:
            bytes: The raw response from the peer.
        """
        raise NotImplementedError()  # pragma: no cover

    async def write(
        self,
        data: bytes,
    ) -> None:
        """Write data.

        Write a request to send to the peer. This is called when a PSRP
        message needs to be sent to the server. The data is in the form of an
        OutOfProc transport message which is a simple XML encoded value. The
        implementation may wish to pass this through as is to the server or
        modify/encapsulate it as needed by the transport.

        Args:
            data: The data to write.
        """
        raise NotImplementedError()  # pragma: no cover

    async def stop(self) -> None:
        """Stop the connection.

        Called when the connection to the Runspace Pool has been closed. The
        OutOfProc implementation can use this to clean up any resources it has
        opened.
        """
        pass  # pragma: no cover

    async def close(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        if pipeline_id:
            close = False
            async with self.__close_lock:
                if pipeline_id in self.__active_pipelines:
                    self.__active_pipelines.remove(pipeline_id)
                    close = True

            if close:
                await self._close(pipeline_id)

        else:
            # An OutOfProc server will block until all pipelines are closed.
            # The server should send the PipelineState that will finalise the
            # asyncio Tasks waiting for the pipeline to complete.
            await asyncio.gather(*[self.close(pid) for pid in self.__active_pipelines])
            await self._close(None)

            await self.stop()

            if self.__listen_task:
                await self.__listen_task
                self.__listen_task = None

    async def _close(
        self,
        pipeline_id: t.Optional[uuid.UUID],
    ) -> None:
        async with self.__wait_condition:
            async with self.__write_lock:
                await self.write(ps_guid_packet("Close", ps_guid=pipeline_id))
            await self._wait_ack("Close", pipeline_id)

    async def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        async with self.__wait_condition:
            async with self.__write_lock:
                await self.write(ps_guid_packet("Command", ps_guid=pipeline_id))
            await self._wait_ack("Command", pipeline_id)

        await self.send()
        self.__active_pipelines.append(pipeline_id)

    async def create(
        self,
    ) -> None:
        self.__listen_task = asyncio_create_task(self._listen())

        await self.send()

    async def send(
        self,
        buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        async with self.__wait_condition:
            await self._send(payload)
            await self._wait_ack("Data", payload.pipeline_id)

        return True

    async def _send(
        self,
        payload: PSRPPayload,
    ) -> None:
        await self.write(ps_data_packet(payload.data, stream_type=payload.stream_type, ps_guid=payload.pipeline_id))

    async def signal(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        async with self.__wait_condition:
            async with self.__write_lock:
                await self.write(ps_guid_packet("Signal", ps_guid=pipeline_id))
            await self._wait_ack("Signal", pipeline_id)

    async def _wait_ack(
        self,
        action: str,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        key = (f"{action}Ack", pipeline_id)
        self.__wait_table.append(key)
        await self.__wait_condition.wait_for(lambda: key not in self.__wait_table)

        if self.__listen_task and self.__listen_task.done():
            self.__listen_task.result()

    async def _listen(self) -> None:
        buffer = bytearray()

        try:
            while True:
                try:
                    end_idx = buffer.index(b"\n")
                except ValueError:
                    # Don't have enough data - wait for more to arrive.
                    read_data = await self.read()
                    if not read_data:
                        break

                    buffer += read_data
                    continue

                data = bytes(buffer[:end_idx])
                buffer = buffer[end_idx + 1 :]

                try:
                    packet = ElementTree.fromstring(data)
                except ElementTree.ParseError as e:
                    # Use what's remaining in the buffer as part of the error message
                    msg = data + b"\n" + bytes(buffer)
                    raise PSRPError(f"Failed to parse response: {msg.decode()}") from e

                data = base64.b64decode(packet.text) if packet.text else b""
                ps_guid: t.Optional[uuid.UUID] = uuid.UUID(packet.attrib["PSGuid"])
                if ps_guid == _EMPTY_UUID:
                    ps_guid = None

                payload_data: t.Optional[PSRPPayload] = None
                if data:
                    payload_data = PSRPPayload(data, StreamType.default, ps_guid)

                    payload: t.Optional[PSRPPayload] = None
                    data_available = await self.process_response(payload_data)
                    if data_available:
                        payload = self.next_payload()

                    if payload:
                        self.__wait_table.append(("DataAck", payload.pipeline_id))
                        await self._send(payload)

                if packet.tag != "Data":
                    async with self.__wait_condition:
                        self.__wait_table.remove((packet.tag, ps_guid))
                        self.__wait_condition.notify_all()

        except Exception as e:
            log.exception("OutOfProc listener encountered unhandled exception")
            await self._break_runspace(e)

        finally:
            async with self.__wait_condition:
                self.__wait_table = []
                self.__wait_condition.notify_all()

    async def _break_runspace(
        self,
        exception: t.Optional[Exception] = None,
    ) -> None:
        pool = self.get_runspace_pool()

        pool.state = RunspacePoolState.Broken
        error_record: t.Optional[ErrorRecord] = None
        if exception:
            error_record = ErrorRecord(
                Exception=NETException(Message=str(exception)),
                CategoryInfo=ErrorCategoryInfo(),
                TargetObject=exception.__traceback__,
            )

        broken_event = PSRPEvent.create(
            PSRPMessageType.RunspacePoolState,
            RunspacePoolStateMsg(
                RunspaceState=pool.state,
                ExceptionAsErrorRecord=error_record,
            ),
            runspace_pool_id=pool.runspace_pool_id,
        )
        await self.process_response(broken_event)


def ps_data_packet(
    data: bytes,
    stream_type: StreamType = StreamType.default,
    ps_guid: t.Optional[uuid.UUID] = None,
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
    stream_name = b"Default" if stream_type == StreamType.default else b"PromptResponse"
    return b"<Data Stream='%s' PSGuid='%s'>%s</Data>\n" % (stream_name, str(ps_guid).encode(), base64.b64encode(data))


def ps_guid_packet(
    element: str,
    ps_guid: t.Optional[uuid.UUID] = None,
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
    return b"<%s PSGuid='%s' />\n" % (element.encode(), str(ps_guid).encode())
