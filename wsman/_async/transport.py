# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""
httpx async transports for WSMan.

The HTTP connection based classes are very close implementations of httpcore
https://github.com/encode/httpcore. Unfortunately WSMan requires some low level
functionality that is not publicly exposed by httpx at this moment.

See:

* https://github.com/encode/httpcore/issues/272 - making HTTPConnection public
* https://github.com/encode/httpcore/issues/273 - adhoc socket connect
"""

import asyncio
import h11
import httpcore
import logging
import re
import spnego
import ssl

from typing import (
    Dict,
    Optional,
    Tuple,
    Union,
)


WWW_AUTH_PATTERN = re.compile(r'(CredSSP|Kerberos|Negotiate|NTLM)\s*([^,]*),?', re.I)

H11Event = Union[
    h11.Request,
    h11.Response,
    h11.InformationalResponse,
    h11.Data,
    h11.EndOfMessage,
    h11.ConnectionClosed,
]

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
    def __init__(
            self,
            stream_reader: asyncio.StreamReader,
            stream_writer: asyncio.StreamWriter
    ):
        self.stream_reader = stream_reader
        self.stream_writer = stream_writer
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()

    def get_http_version(self) -> str:
        ssl_object = self.stream_writer.get_extra_info("ssl_object")

        if ssl_object is None:
            return "HTTP/1.1"

        ident = ssl_object.selected_alpn_protocol()
        return "HTTP/2" if ident == "h2" else "HTTP/1.1"

    async def start_tls(
            self, hostname: bytes,
            ssl_context: ssl.SSLContext,
            timeout: Dict
    ) -> "SocketStream":
        loop = asyncio.get_event_loop()

        stream_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(stream_reader)
        transport = self.stream_writer.transport

        loop_start_tls = getattr(loop, "start_tls", backport_start_tls)

        exc_map = {asyncio.TimeoutError: ConnectTimeout, OSError: ConnectError}

        with map_exceptions(exc_map):
            transport = await asyncio.wait_for(
                loop_start_tls(
                    transport,
                    protocol,
                    ssl_context,
                    server_hostname=hostname.decode("ascii"),
                ),
                timeout=timeout.get("connect"),
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
        ssl_stream._inner = self  # type: ignore
        return ssl_stream

    async def read(
            self,
            n: int,
            timeout: Dict
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

    async def write(self, data: bytes, timeout: TimeoutDict) -> None:
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

    def is_readable(self) -> bool:
        transport = self.stream_reader._transport  # type: ignore
        sock: Optional[socket.socket] = transport.get_extra_info("socket")
        # If socket was detached from the transport, most likely connection was reset.
        # Hence make it readable to notify users to poll the socket.
        # We'd expect the read operation to return `b""` indicating the socket closure.
        return sock is None or _utils.is_socket_readable(sock.fileno())


class Lock(AsyncLock):
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def release(self) -> None:
        self._lock.release()

    async def acquire(self) -> None:
        await self._lock.acquire()


class Semaphore(AsyncSemaphore):
    def __init__(self, max_value: int, exc_class: type) -> None:
        self.max_value = max_value
        self.exc_class = exc_class

    @property
    def semaphore(self) -> asyncio.BoundedSemaphore:
        if not hasattr(self, "_semaphore"):
            self._semaphore = asyncio.BoundedSemaphore(value=self.max_value)
        return self._semaphore

    async def acquire(self, timeout: float = None) -> None:
        try:
            await asyncio.wait_for(self.semaphore.acquire(), timeout)
        except asyncio.TimeoutError:
            raise self.exc_class()

    async def release(self) -> None:
        self.semaphore.release()


class AsyncioBackend:

    async def open_tcp_stream(
        self,
        hostname: bytes,
        port: int,
        ssl_context: Optional[ssl.SSLContext],
        timeout: Dict,
        *,
        local_address: Optional[str],
    ) -> SocketStream:
        host = hostname.decode("ascii")
        connect_timeout = timeout.get("connect")
        local_addr = None if local_address is None else (local_address, 0)

        exc_map = {asyncio.TimeoutError: ConnectTimeout, OSError: ConnectError}
        with map_exceptions(exc_map):
            stream_reader, stream_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=ssl_context, local_addr=local_addr
                ),
                connect_timeout,
            )
            return SocketStream(
                stream_reader=stream_reader, stream_writer=stream_writer
            )

    def create_lock(self) -> AsyncLock:
        return Lock()

    def create_semaphore(self, max_value: int, exc_class: type) -> AsyncSemaphore:
        return Semaphore(max_value, exc_class=exc_class)

    async def time(self) -> float:
        loop = asyncio.get_event_loop()
        return loop.time()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class AsyncHTTP11Connection(httpcore.AsyncHTTPTransport):
    READ_NUM_BYTES = 64 * 1024

    def __init__(
            self,
            socket: AsyncSocketStream,
            ssl_context: SSLContext = None
    ):
        self.socket = socket
        self.ssl_context = SSLContext() if ssl_context is None else ssl_context

        self.h11_state = h11.Connection(our_role=h11.CLIENT)

        self.state = ConnectionState.ACTIVE

    def __repr__(self) -> str:
        return f"<AsyncHTTP11Connection state={self.state}>"

    def info(self) -> str:
        return f"HTTP/1.1, {self.state.name}"

    def get_state(self) -> ConnectionState:
        return self.state

    def mark_as_ready(self) -> None:
        if self.state == ConnectionState.IDLE:
            self.state = ConnectionState.READY

    async def arequest(
        self,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: AsyncByteStream = None,
        ext: dict = None,
    ) -> Tuple[int, Headers, AsyncByteStream, dict]:
        headers = [] if headers is None else headers
        stream = PlainByteStream(b"") if stream is None else stream
        ext = {} if ext is None else ext
        timeout = cast(TimeoutDict, ext.get("timeout", {}))

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
        return (status_code, headers, response_stream, ext)

    async def start_tls(
        self, hostname: bytes, timeout: TimeoutDict = None
    ) -> AsyncSocketStream:
        timeout = {} if timeout is None else timeout
        self.socket = await self.socket.start_tls(hostname, self.ssl_context, timeout)
        return self.socket

    async def _send_request(
        self, method: bytes, url: URL, headers: Headers, timeout: TimeoutDict
    ) -> None:
        """
        Send the request line and headers.
        """
        logger.trace("send_request method=%r url=%r headers=%s", method, url, headers)
        _scheme, _host, _port, target = url
        with map_exceptions({h11.LocalProtocolError: LocalProtocolError}):
            event = h11.Request(method=method, target=target, headers=headers)
        await self._send_event(event, timeout)

    async def _send_request_body(
        self, stream: AsyncByteStream, timeout: TimeoutDict
    ) -> None:
        """
        Send the request body.
        """
        # Send the request body.
        async for chunk in stream:
            logger.trace("send_data=Data(<%d bytes>)", len(chunk))
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
        self, timeout: TimeoutDict
    ) -> Tuple[bytes, int, bytes, List[Tuple[bytes, bytes]]]:
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
    ) -> AsyncIterator[bytes]:
        """
        Read the response data from the network.
        """
        while True:
            event = await self._receive_event(timeout)
            if isinstance(event, h11.Data):
                logger.trace("receive_event=Data(<%d bytes>)", len(event.data))
                yield bytes(event.data)
            elif isinstance(event, (h11.EndOfMessage, h11.PAUSED)):
                logger.trace("receive_event=%r", event)
                break

    async def _receive_event(self, timeout: TimeoutDict) -> H11Event:
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
        logger.trace(
            "response_closed our_state=%r their_state=%r",
            self.h11_state.our_state,
            self.h11_state.their_state,
        )
        if (
            self.h11_state.our_state is h11.DONE
            and self.h11_state.their_state is h11.DONE
        ):
            self.h11_state.start_next_cycle()
            self.state = ConnectionState.IDLE
        else:
            await self.aclose()

    async def aclose(self) -> None:
        if self.state != ConnectionState.CLOSED:
            self.state = ConnectionState.CLOSED

            if self.h11_state.our_state is h11.MUST_CLOSE:
                event = h11.ConnectionClosed()
                self.h11_state.send(event)

            await self.socket.aclose()

    def is_socket_readable(self) -> bool:
        return self.socket.is_readable()


class AsyncHTTPConnection:
    def __init__(
        self,
        origin: Origin,
        http2: bool = False,
        uds: str = None,
        ssl_context: SSLContext = None,
        socket: AsyncSocketStream = None,
        local_address: str = None,
        retries: int = 0,
        backend: AsyncBackend = None,
    ):
        self.origin = origin
        self.http2 = http2
        self.uds = uds
        self.ssl_context = SSLContext() if ssl_context is None else ssl_context
        self.socket = socket
        self.local_address = local_address
        self.retries = retries

        if self.http2:
            self.ssl_context.set_alpn_protocols(["http/1.1", "h2"])

        self.connection: Optional[AsyncBaseHTTPConnection] = None
        self.is_http11 = False
        self.is_http2 = False
        self.connect_failed = False
        self.expires_at: Optional[float] = None
        self.backend = AutoBackend() if backend is None else backend

    def __repr__(self) -> str:
        http_version = "UNKNOWN"
        if self.is_http11:
            http_version = "HTTP/1.1"
        elif self.is_http2:
            http_version = "HTTP/2"
        return f"<AsyncHTTPConnection http_version={http_version} state={self.state}>"

    def info(self) -> str:
        if self.connection is None:
            return "Not connected"
        elif self.state == ConnectionState.PENDING:
            return "Connecting"
        return self.connection.info()

    @property
    def request_lock(self) -> AsyncLock:
        # We do this lazily, to make sure backend autodetection always
        # runs within an async context.
        if not hasattr(self, "_request_lock"):
            self._request_lock = self.backend.create_lock()
        return self._request_lock

    async def arequest(
        self,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: AsyncByteStream = None,
        ext: dict = None,
    ) -> Tuple[int, Headers, AsyncByteStream, dict]:
        assert url_to_origin(url) == self.origin
        ext = {} if ext is None else ext
        timeout = cast(TimeoutDict, ext.get("timeout", {}))

        async with self.request_lock:
            if self.state == ConnectionState.PENDING:
                if not self.socket:
                    logger.trace(
                        "open_socket origin=%r timeout=%r", self.origin, timeout
                    )
                    self.socket = await self._open_socket(timeout)
                self._create_connection(self.socket)
            elif self.state in (ConnectionState.READY, ConnectionState.IDLE):
                pass
            elif self.state == ConnectionState.ACTIVE and self.is_http2:
                pass
            else:
                raise NewConnectionRequired()

        assert self.connection is not None
        logger.trace(
            "connection.arequest method=%r url=%r headers=%r", method, url, headers
        )
        return await self.connection.arequest(method, url, headers, stream, ext)

    async def _open_socket(self, timeout: TimeoutDict = None) -> AsyncSocketStream:
        scheme, hostname, port = self.origin
        timeout = {} if timeout is None else timeout
        ssl_context = self.ssl_context if scheme == b"https" else None

        retries_left = self.retries
        delays = exponential_backoff(factor=RETRIES_BACKOFF_FACTOR)

        while True:
            try:
                return await self.backend.open_tcp_stream(
                    hostname,
                    port,
                    ssl_context,
                    timeout,
                    local_address=self.local_address,
                )
            except (ConnectError, ConnectTimeout):
                if retries_left <= 0:
                    self.connect_failed = True
                    raise
                retries_left -= 1
                delay = next(delays)
                await self.backend.sleep(delay)
            except Exception:  # noqa: PIE786
                self.connect_failed = True
                raise

    def _create_connection(self, socket: AsyncSocketStream) -> None:
        http_version = socket.get_http_version()
        logger.trace(
            "create_connection socket=%r http_version=%r", socket, http_version
        )
        if http_version == "HTTP/2":
            from .http2 import AsyncHTTP2Connection

            self.is_http2 = True
            self.connection = AsyncHTTP2Connection(
                socket=socket, backend=self.backend, ssl_context=self.ssl_context
            )
        else:
            self.is_http11 = True
            self.connection = AsyncHTTP11Connection(
                socket=socket, ssl_context=self.ssl_context
            )

    @property
    def state(self) -> ConnectionState:
        if self.connect_failed:
            return ConnectionState.CLOSED
        elif self.connection is None:
            return ConnectionState.PENDING
        return self.connection.get_state()

    def is_socket_readable(self) -> bool:
        return self.connection is not None and self.connection.is_socket_readable()

    def mark_as_ready(self) -> None:
        if self.connection is not None:
            self.connection.mark_as_ready()

    async def start_tls(self, hostname: bytes, timeout: TimeoutDict = None) -> None:
        if self.connection is not None:
            logger.trace("start_tls hostname=%r timeout=%r", hostname, timeout)
            self.socket = await self.connection.start_tls(hostname, timeout)
            logger.trace("start_tls complete hostname=%r timeout=%r", hostname, timeout)

    async def aclose(self) -> None:
        async with self.request_lock:
            if self.connection is not None:
                await self.connection.aclose()


class AsyncWSManTransport(httpcore.AsyncHTTPTransport):

    def __init__(
            self,
            ssl_context: ssl.SSLContext,
            keepalive_expiry: float,
            encrypt: bool = True,
            username: Optional[str] = None,
            password: Optional[str] = None,
            protocol: str = 'negotiate',
            service: str = 'HTTP',
            hostname_override: Optional[str] = None,
            disable_cbt: bool = False,
            delegate: bool = False,
            credssp_allow_tlsv1: bool = False,
            credssp_require_kerberos: bool = False,
    ):
        # Connection options
        self._connection = None
        self._ssl_context = ssl_context
        self._keepalive_expiry = keepalive_expiry

        # Authentication options
        self.protocol = protocol.lower()
        if self.protocol not in ['kerberos', 'negotiate', 'ntlm', 'credssp']:
            raise ValueError(f"{type(self).__name__} only supports credssp, negotiate, kerberos, or ntlm "
                             f"authentication")

        self._username = username
        self._password = password
        self._service = service
        self._hostname_override = hostname_override
        self._disable_cbt = disable_cbt
        self._context = None
        self._context_req = spnego.ContextReq.default
        self._spnego_options = spnego.NegotiateOptions.none
        self._encrypt = encrypt

        if encrypt:
            self._spnego_options |= spnego.NegotiateOptions.wrapping_winrm

        if self.protocol == 'credssp':
            if credssp_allow_tlsv1:
                self._spnego_options |= spnego.NegotiateOptions.credssp_allow_tlsv1

            if credssp_require_kerberos:
                self._spnego_options |= spnego.NegotiateOptions.negotiate_kerberos

        elif delegate:
            self._context_req |= spnego.ContextReq.delegate

    async def arequest(
        self,
        method: bytes,
        url: httpx.URL,
        headers: httpx.Headers = None,
        stream: httpcore.AsyncByteStream = None,
        ext: typing.Dict = None,
    ) -> typing.Tuple[int, httpx.Headers, httpcore.AsyncByteStream, typing.Dict]:
        ext = ext or {}
        connection = await self._get_connection()

        if not connection:
            self._context = None
            self._connection = connection = await self._create_connection(url, ext)

        if not self._context:
            # Set up the authentication context. If we are encrypting data we
            # cannot send anything at the moment.
            response = await self._authenticate(
                connection, method, url, headers,
                None if self._encrypt else stream, ext
            )

            if not self._encrypt:
                return response

        new_headers = httpx.Headers(headers)
        new_stream = stream
        if self._encrypt:
            dec_data = b''
            async for data in stream:
                dec_data += data
            enc_data, content_type = _encrypt_wsman(dec_data, new_headers['Content-Type'], self._encryption_type,
                                                    self._context)
            new_headers['Content-Type'] = content_type
            new_headers['Content-Length'] = str(len(enc_data))
            new_stream = httpcore.PlainByteStream(enc_data)

        status_code, headers, stream, ext = await self._connection.arequest(
            method, url, headers=headers, stream=new_stream, ext=ext
        )
        connection.expires_at = await connection.backend.time() + self._keepalive_expiry

        new_stream = stream
        content_type = httpx.Headers(headers).get('content-type', '')
        if content_type.startswith('multipart/encrypted;') or content_type.startswith('multipart/x-multi-encrypted;'):
            enc_data = b''
            async for data in stream:
                enc_data += data
            await stream.aclose()
            dec_data = _decrypt_wsman(enc_data, content_type, self._context)
            new_stream = httpcore.PlainByteStream(dec_data)

        return status_code, headers, new_stream, ext

    async def _authenticate(
            self,
            connection: AsyncHTTPConnection,
            method: bytes,
            url: httpx.URL,
            headers: httpx.Headers = None,
            stream: httpcore.AsyncByteStream = None,
            ext: typing.Dict = None,
    ):
        # Get the TLS object for CBT if required - will be None when connecting over HTTP
        cbt = None
        ssl_object = connection.socket.stream_writer.get_extra_info('ssl_object')
        if ssl_object and self.send_cbt and self.protocol != 'credssp':
            cert = ssl_object.getpeercert(True)
            cert_hash = get_tls_server_end_point_hash(cert)
            cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-server-end-point:" + cert_hash)

        auth_hostname = self.hostname_override or url[1].decode('utf-8')
        self._context = await _async_wrap(
            spnego.client, self.username, self.password, hostname=auth_hostname,
            service=self.service, channel_bindings=cbt, context_req=self._context_req,
            protocol=self.protocol, options=self._spnego_options
        )

        # Send a blank request for the first authentication packet
        # TODO: Send actual if not encrypting data
        new_headers = httpx.Headers(headers.copy())
        if not stream:
            new_headers['Content-Length'] = '0'
        auth_header = 'Negotiate'

        out_token = await _async_wrap(self._context.step)
        while not self._context.complete or out_token is not None:
            new_headers['Authorization'] = "%s %s" % (auth_header, base64.b64encode(out_token).decode())

            # send the request with the auth token and get the response
            response = await connection.arequest(method, url, headers=new_headers.raw, stream=stream, ext=ext)
            await response[2].aclose()
            connection.expires_at = await connection.backend.time() + self._keepalive_expiry

            auth_header = httpx.Headers(response[1]).get('www-authenticate', '')
            in_token = self._regex.search(auth_header)
            if in_token:
                in_token = base64.b64decode(in_token.group(2))

            # If there was no token received from the host then we just break the auth cycle.
            if not in_token:
                break

            out_token = await _async_wrap(self._context.step, in_token)

        return response

    async def aclose(self) -> None:
        await self._connection.aclose()
        self._connection = None

    async def _create_connection(
            self,
            url: httpx.URL,
            ext: typing.Dict,
    ):
        connection = AsyncHTTPConnection(
            origin=url[:3],
            ssl_context=self._ssl_context,
        )
        socket = await connection._open_socket(timeout=ext.get('timeout', {}))
        connection.socket = socket
        connection.expires_at = await connection.backend.time() + self._keepalive_expiry

        return connection

    async def _get_connection(self):
        connection = self._connection

        if not connection:
            return

        must_close = False

        if connection.state == ConnectionState.IDLE:
            now = await connection.backend.time()
            if connection.is_socket_readable() or now >= connection.expires_at:
                must_close = True

        else:
            must_close = True

        if must_close:
            await connection.aclose()
            self._connection = None

        return self._connection

    @property
    def _encryption_type(self) -> str:
        """ Returns the WSMan encryption Content-Type for the authentication protocol used. """
        if self.protocol == 'kerberos':
            protocol = 'Kerberos'

        elif self.protocol == 'credssp':
            protocol = 'CredSSP'

        else:
            protocol = 'SPNEGO'

        return f'application/HTTP-{protocol}-session-encrypted'
