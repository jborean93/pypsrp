# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import h11
import logging
import socket
import ssl
import typing

from httpcore import (
    AsyncByteStream,
    AsyncHTTPTransport,
    CloseError,
    ConnectError,
    ConnectTimeout,
    LocalProtocolError,
    ReadError,
    ReadTimeout,
    RemoteProtocolError,
    WriteError,
    WriteTimeout,
)

from ._bytestreams import (
    AsyncIteratorByteStream,
    PlainByteStream,
)

from ._utils import (
    ConnectionState,
    exponential_backoff,
    H11Event,
    Headers,
    is_socket_readable,
    map_exceptions,
    TimeoutDict,
    URL,
)

logger = logging.getLogger(__name__)


async def backport_start_tls(
    transport: asyncio.BaseTransport,
    protocol: asyncio.BaseProtocol,
    ssl_context: ssl.SSLContext,
    *,
    server_side: bool = False,
    server_hostname: str = None,
    ssl_handshake_timeout: float = None,
) -> asyncio.Transport:  # pragma: nocover (Since it's not used on all Python versions.)
    """
    Python 3.6 asyncio doesn't have a start_tls() method on the loop
    so we use this function in place of the loop's start_tls() method.
    Adapted from this comment:
    https://github.com/urllib3/urllib3/issues/1323#issuecomment-362494839
    """
    import asyncio.sslproto

    loop = asyncio.get_event_loop()
    waiter = loop.create_future()
    ssl_protocol = asyncio.sslproto.SSLProtocol(
        loop,
        protocol,
        ssl_context,
        waiter,
        server_side=False,
        server_hostname=server_hostname,
        call_connection_made=False,
    )

    transport.set_protocol(ssl_protocol)
    loop.call_soon(ssl_protocol.connection_made, transport)
    loop.call_soon(transport.resume_reading)  # type: ignore

    await waiter
    return ssl_protocol._app_transport


class SocketStream:
    """ Based on httpcore._backends.async.SocketStream"""
    def __init__(
            self,
            stream_reader: asyncio.StreamReader,
            stream_writer: asyncio.StreamWriter
    ):
        self.stream_reader = stream_reader
        self.stream_writer = stream_writer
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()

        self._inner = None

    async def read(
            self,
            n: int,
            timeout: TimeoutDict,
    ) -> bytes:
        exc_map = {asyncio.TimeoutError: ReadTimeout, OSError: ReadError}
        async with self.read_lock:
            with map_exceptions(exc_map):
                try:
                    return await asyncio.wait_for(
                        self.stream_reader.read(n), timeout.get("read")
                    )
                except AttributeError as exc:  # pragma: nocover
                    if "resume_reading" in str(exc):
                        # Python's asyncio has a bug that can occur when a
                        # connection has been closed, while it is paused.
                        # See: https://github.com/encode/httpx/issues/1213
                        #
                        # Returning an empty byte-string to indicate connection
                        # close will eventually raise an httpcore.RemoteProtocolError
                        # to the user when this goes through our HTTP parsing layer.
                        return b""
                    raise

    async def write(
            self,
            data: bytes,
            timeout: TimeoutDict,
    ) -> None:
        if not data:
            return

        exc_map = {asyncio.TimeoutError: WriteTimeout, OSError: WriteError}
        async with self.write_lock:
            with map_exceptions(exc_map):
                self.stream_writer.write(data)
                return await asyncio.wait_for(
                    self.stream_writer.drain(), timeout.get("write")
                )

    async def aclose(self) -> None:
        # SSL connections should issue the close and then abort, rather than
        # waiting for the remote end of the connection to signal the EOF.
        #
        # See:
        #
        # * https://bugs.python.org/issue39758
        # * https://github.com/python-trio/trio/blob/
        #             31e2ae866ad549f1927d45ce073d4f0ea9f12419/trio/_ssl.py#L779-L829
        #
        # And related issues caused if we simply omit the 'wait_closed' call,
        # without first using `.abort()`
        #
        # * https://github.com/encode/httpx/issues/825
        # * https://github.com/encode/httpx/issues/914
        is_ssl = self.stream_writer.get_extra_info("ssl_object") is not None

        async with self.write_lock:
            with map_exceptions({OSError: CloseError}):
                self.stream_writer.close()
                if is_ssl:
                    # Give the connection a chance to write any data in the buffer,
                    # and then forcibly tear down the SSL connection.
                    await asyncio.sleep(0)
                    self.stream_writer.transport.abort()  # type: ignore
                if hasattr(self.stream_writer, "wait_closed"):
                    # Python 3.7+ only.
                    await self.stream_writer.wait_closed()  # type: ignore

    async def start_tls(
            self,
            hostname: bytes,
            ssl_context: ssl.SSLContext,
            timeout: TimeoutDict,
    ) -> "SocketStream":
        loop = asyncio.get_event_loop()

        stream_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(stream_reader)
        transport = self.stream_writer.transport

        # The asyncio start_tls method has a hardcoded check for this attribute
        # failing with TypeError if this attribute isn't True. The SSL
        # transport used is compatible with Start TLS so setting this here
        # bypasses that problem.
        # https://github.com/python/cpython/blob/d9151cb45371836d39b6d53afb50c5bcd353c661/Lib/asyncio/base_events.py#L1210-L1212
        # https://github.com/encode/httpcore/issues/254
        setattr(transport, '_start_tls_compatible', True)

        loop_start_tls = getattr(loop, "start_tls", backport_start_tls)

        exc_map = {asyncio.TimeoutError: ConnectTimeout, OSError: ConnectError}

        with map_exceptions(exc_map):
            transport = await asyncio.wait_for(
                loop_start_tls(
                    transport,
                    protocol,
                    ssl_context,
                    server_hostname=hostname.decode('utf-8'),
                ),
                timeout=timeout.get('connect'),
            )

        # Initialize the protocol, so it is made aware of being tied to
        # a TLS connection.
        # See: https://github.com/encode/httpx/issues/859
        protocol.connection_made(transport)

        stream_writer = asyncio.StreamWriter(
            transport=transport, protocol=protocol, reader=stream_reader, loop=loop
        )

        ssl_stream = SocketStream(stream_reader, stream_writer)
        # When we return a new SocketStream with new StreamReader/StreamWriter instances
        # we need to keep references to the old StreamReader/StreamWriter so that they
        # are not garbage collected and closed while we're still using them.
        ssl_stream._inner = self
        return ssl_stream

    def is_readable(self) -> bool:
        transport = self.stream_reader._transport  # type: ignore
        sock: typing.Optional[socket.socket] = transport.get_extra_info("socket")
        # If socket was detached from the transport, most likely connection was reset.
        # Hence make it readable to notify users to poll the socket.
        # We'd expect the read operation to return `b""` indicating the socket closure.
        return sock is None or is_socket_readable(sock.fileno())

    @classmethod
    async def open_socket(
            cls,
            hostname: typing.Optional[str] = None,
            port: typing.Optional[int] = None,
            ssl_context: typing.Optional[ssl.SSLContext] = None,
            connection_timeout: typing.Optional[float] = None,
            retries: int = 0,
            sock: typing.Optional[socket.socket] = None,
            server_hostname: typing.Optional[str] = None,
    ) -> 'SocketStream':
        delays = exponential_backoff(factor=0.5)

        while True:
            try:
                exc_map = {asyncio.TimeoutError: ConnectTimeout, OSError: ConnectError}
                with map_exceptions(exc_map):
                    sr, sw = await asyncio.wait_for(
                        asyncio.open_connection(
                            host=hostname, port=port, ssl=ssl_context,
                            sock=sock, server_hostname=server_hostname),
                        connection_timeout,
                    )
                    return cls(
                        stream_reader=sr, stream_writer=sw,
                    )

            except (ConnectError, ConnectTimeout):
                if retries <= 0:
                    raise

                retries -= 1
                delay = next(delays)
                await asyncio.sleep(delay)


class AsyncHTTPConnection(AsyncHTTPTransport):
    """ Based on httpcore._async.http11.AsyncHTTP11Connection and AsyncHTTPConnection. """
    READ_NUM_BYTES = 64 * 1024

    def __init__(
            self,
            sock: SocketStream,
    ):
        self.socket = sock
        self.request_lock = asyncio.Lock()

        self.h11_state = h11.Connection(our_role=h11.CLIENT)
        self.state = ConnectionState.PENDING
        self.expires_at: typing.Optional[float] = None

    async def aclose(self) -> None:
        async with self.request_lock:
            if self.state != ConnectionState.CLOSED:
                self.state = ConnectionState.CLOSED

                if self.h11_state.our_state is h11.MUST_CLOSE:
                    event = h11.ConnectionClosed()
                    self.h11_state.send(event)

    async def arequest(
            self,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: dict = None,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, dict]:
        headers = [] if headers is None else headers
        stream = PlainByteStream(b"") if stream is None else stream
        ext = {} if ext is None else ext
        timeout = typing.cast(TimeoutDict, ext.get("timeout", {}))

        self.state = ConnectionState.ACTIVE

        await self._send_request(method, url, headers, timeout)
        await self._send_request_body(stream, timeout)
        (
            http_version,
            status_code,
            reason_phrase,
            headers,
        ) = await self._receive_response(timeout)
        response_stream = AsyncIteratorByteStream(
            aiterator=self._receive_response_data(timeout),
            aclose_func=self._response_closed,
        )
        ext = {
            "http_version": http_version.decode("ascii", errors="ignore"),
            "reason": reason_phrase.decode("ascii", errors="ignore"),
        }
        return status_code, headers, response_stream, ext

    async def _send_request(
            self,
            method: bytes,
            url: URL,
            headers: Headers,
            timeout: TimeoutDict,
    ) -> None:
        """
        Send the request line and headers.
        """
        with map_exceptions({h11.LocalProtocolError: LocalProtocolError}):
            event = h11.Request(method=method, target=url[3], headers=headers)
        await self._send_event(event, timeout)

    async def _send_request_body(
        self, stream: AsyncByteStream, timeout: TimeoutDict
    ) -> None:
        """
        Send the request body.
        """
        # Send the request body.
        async for chunk in stream:
            event = h11.Data(data=chunk)
            await self._send_event(event, timeout)

        # Finalize sending the request.
        event = h11.EndOfMessage()
        await self._send_event(event, timeout)

    async def _send_event(self, event: H11Event, timeout: TimeoutDict) -> None:
        """
        Send a single `h11` event to the network, waiting for the data to
        drain before returning.
        """
        bytes_to_send = self.h11_state.send(event)
        await self.socket.write(bytes_to_send, timeout)

    async def _receive_response(
            self,
            timeout: TimeoutDict,
    ) -> typing.Tuple[bytes, int, bytes, typing.List[typing.Tuple[bytes, bytes]]]:
        """
        Read the response status and headers from the network.
        """
        while True:
            event = await self._receive_event(timeout)
            if isinstance(event, h11.Response):
                break

        http_version = b"HTTP/" + event.http_version

        if hasattr(event.headers, "raw_items"):
            # h11 version 0.11+ supports a `raw_items` interface to get the
            # raw header casing, rather than the enforced lowercase headers.
            headers = event.headers.raw_items()
        else:
            headers = event.headers

        return http_version, event.status_code, event.reason, headers

    async def _receive_response_data(
        self, timeout: TimeoutDict
    ) -> typing.AsyncIterator[bytes]:
        """
        Read the response data from the network.
        """
        while True:
            event = await self._receive_event(timeout)
            if isinstance(event, h11.Data):
                yield bytes(event.data)
            elif isinstance(event, (h11.EndOfMessage, h11.PAUSED)):
                break

    async def _receive_event(
            self,
            timeout: TimeoutDict,
    ) -> H11Event:
        """
        Read a single `h11` event, reading more data from the network if needed.
        """
        while True:
            with map_exceptions({h11.RemoteProtocolError: RemoteProtocolError}):
                event = self.h11_state.next_event()

            if event is h11.NEED_DATA:
                data = await self.socket.read(self.READ_NUM_BYTES, timeout)
                self.h11_state.receive_data(data)
            else:
                assert event is not h11.NEED_DATA
                break
        return event

    async def _response_closed(self) -> None:
        if (
            self.h11_state.our_state is h11.DONE
            and self.h11_state.their_state is h11.DONE
        ):
            self.h11_state.start_next_cycle()
            self.state = ConnectionState.IDLE
        else:
            await self.aclose()

    def is_socket_readable(self) -> bool:
        return self.socket is not None and self.socket.is_readable()
