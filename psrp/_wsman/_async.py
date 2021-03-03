# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import functools
import h11
import httpx
import logging
import re
import socket
import spnego
import spnego.channel_bindings
import ssl
import typing

from httpcore import (
    AsyncByteStream,
    AsyncConnectionPool,
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

from ._encryption import (
    decrypt_wsman,
    encrypt_wsman,
)

from ._utils import (
    ConnectionState,
    exponential_backoff,
    get_tls_server_end_point_hash,
    H11Event,
    Headers,
    is_socket_readable,
    map_exceptions,
    Origin,
    TimeoutDict,
    URL,
)

logger = logging.getLogger(__name__)


WWW_AUTH_PATTERN = re.compile(r'(CredSSP|Kerberos|Negotiate|NTLM)\s*([^,]*),?', re.I)


def _async_wrap(func, *args, **kwargs):
    """ Runs a sync function in the background. """
    loop = asyncio.get_running_loop()
    task = loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

    return task


def _time() -> float:
    return asyncio.get_event_loop().time()


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
            hostname: str,
            port: int,
            ssl_context: typing.Optional[ssl.SSLContext],
            connection_timeout: typing.Optional[float] = None,
            retries: int = 0,
    ):
        delays = exponential_backoff(factor=0.5)

        while True:
            try:
                exc_map = {asyncio.TimeoutError: ConnectTimeout, OSError: ConnectError}
                with map_exceptions(exc_map):
                    sr, sw = await asyncio.wait_for(
                        asyncio.open_connection(
                            host=hostname, port=port, ssl=ssl_context),
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


class AsyncWSManTransport(AsyncHTTPTransport):

    _REQUEST_HEADER = 'authorization'
    _RESPONSE_HEADER = 'www-authenticate'

    def __init__(
            self,
            ssl_context: ssl.SSLContext = None,
            keepalive_expiry: float = 60.0,
            encrypt: bool = True,
            credential: typing.Any = None,
            protocol: str = 'negotiate',
            service: str = 'HTTP',
            hostname_override: typing.Optional[str] = None,
            disable_cbt: bool = False,
            delegate: bool = False,
            credssp_allow_tlsv1: bool = False,
            credssp_require_kerberos: bool = False,
            proxy_url: typing.Optional[str] = None,
            proxy_credential: typing.Any = None,
            proxy_auth: typing.Optional[str] = 'none',
            proxy_service: typing.Optional[str] = 'HTTP',
            proxy_hostname: typing.Optional[str] = None,
    ):
        # none is only really valid for proxies, WinRM will most definitely enforce one of them.
        # certificate auth shouldn't be a value in protocol or proxy_auth it's only in this list for the error message.
        valid_protocols = ['basic', 'certificate', 'kerberos', 'negotiate', 'ntlm', 'credssp', 'none']

        # Connection options
        self._connection = None
        self._socket = None
        self._ssl_context = ssl_context
        self._keepalive_expiry = keepalive_expiry

        # Proxy options
        self._proxy_url = httpx.URL(proxy_url) if proxy_url else None
        self._proxy_credential = proxy_credential
        self._proxy_auth = proxy_auth or 'none'
        self._proxy_service = proxy_service
        self._proxy_hostname = proxy_hostname

        if self._proxy_auth not in valid_protocols:
            raise ValueError(f"{type(self).__name__} proxy_auth only supports {', '.join(valid_protocols)}")

        # Authentication options
        self.protocol = protocol.lower()
        if self.protocol not in valid_protocols:
            raise ValueError(f"{type(self).__name__} only supports {', '.join(valid_protocols)}")

        self._credential = credential
        self._service = service
        self._hostname_override = hostname_override
        self._disable_cbt = disable_cbt
        self._delegate = delegate
        self._credssp_allow_tlsv1 = credssp_allow_tlsv1
        self._credssp_require_kerberos = credssp_require_kerberos
        self._context = None
        self._encrypt = encrypt

        self._auth_func = None
        if self.protocol == 'basic':
            if encrypt:
                raise ValueError(f"{type(self).__name__} with protocol {self.protocol} does not support encryption")
            self._auth_func = self._authenticate_basic

        elif self.protocol in ['credssp', 'kerberos', 'negotiate', 'ntlm']:
            self._auth_func = self._authenticate_negotiate

    async def arequest(
        self,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: AsyncByteStream = None,
        ext: typing.Dict = None,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        ext = ext or {}
        connection = await self._get_connection()

        if not connection:
            self._context = None  # In case of a keep-alive expiry we want to remove any existing auth context.
            self._connection = connection = await self._create_connection(url, ext)

        if not self._context and self._auth_func:
            # Set up the authentication context. If we are encrypting data we cannot send anything at the moment.
            response = await self._auth_func(
                connection, method, url, headers,
                None if self._encrypt else stream, ext
            )

            # If we didn't encrypt then the response from the authentication phase contains our actual response.
            if not self._encrypt or response[0] != 200:
                return response

        headers, stream = await self._wrap_stream(headers, stream)
        status_code, headers, stream, ext = await self._connection.arequest(
            method, url, headers=headers.raw, stream=stream, ext=ext
        )
        headers, stream = await self._unwrap_stream(headers, stream)

        return status_code, headers.raw, stream, ext

    async def aclose(self) -> None:
        if self._connection:
            await self._connection.aclose()
            self._connection = None

        if self._socket:
            await self._socket.aclose()
            self._socket = None

    async def _authenticate_basic(
            self,
            connection: AsyncHTTPConnection,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        headers, stream = await self._wrap_stream(headers, stream)

        credential = f'{self._credential[0] or ""}:{self._credential[1] or ""}'.encode('utf-8')
        headers[self._REQUEST_HEADER] = f'Basic {base64.b64encode(credential).decode()}'

        status_code, headers, stream, ext = await connection.arequest(method, url, headers=headers.raw,
                                                                      stream=stream, ext=ext)
        headers, stream = await self._unwrap_stream(headers, stream)

        return status_code, headers.raw, stream, ext

    async def _authenticate_negotiate(
            self,
            connection: AsyncHTTPConnection,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        headers, stream = await self._wrap_stream(headers, stream)
        auth_header = {
            'negotiate': 'Negotiate',
            'ntlm': 'Negotiate',
            'kerberos': 'Kerberos',
            'credssp': 'CredSSP',
        }[self.protocol]

        # Get the TLS object for CBT if required - will be None when connecting over HTTP
        cbt = None
        ssl_object = connection.socket.stream_writer.get_extra_info('ssl_object')
        if ssl_object and not self._disable_cbt and self.protocol != 'credssp':
            cert = ssl_object.getpeercert(True)
            cert_hash = get_tls_server_end_point_hash(cert)
            cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-server-end-point:" + cert_hash)

        context_req = spnego.ContextReq.default
        spnego_options = spnego.NegotiateOptions.none

        if self._encrypt:
            spnego_options |= spnego.NegotiateOptions.wrapping_winrm

        if self.protocol == 'credssp':
            if self._credssp_allow_tlsv1:
                spnego_options |= spnego.NegotiateOptions.credssp_allow_tlsv1

            if self._credssp_require_kerberos:
                spnego_options |= spnego.NegotiateOptions.negotiate_kerberos

        elif self._delegate:
            context_req |= spnego.ContextReq.delegate

        username, password = self._credential
        auth_hostname = self._hostname_override or url[1].decode('utf-8')
        self._context = await _async_wrap(
            spnego.client, username, password, hostname=auth_hostname,
            service=self._service, channel_bindings=cbt, context_req=context_req,
            protocol=self.protocol, options=spnego_options
        )

        status_code = 500
        send_headers = headers
        out_token = await _async_wrap(self._context.step)
        while not self._context.complete or out_token is not None:
            send_headers[self._REQUEST_HEADER] = f'{auth_header} {base64.b64encode(out_token).decode()}'
            status_code, headers, stream, ext = await connection.arequest(method, url, headers=send_headers.raw,
                                                                          stream=stream, ext=ext)
            headers, stream = await self._unwrap_stream(headers, stream)

            auth_header = headers.get(self._RESPONSE_HEADER, '')
            in_token = WWW_AUTH_PATTERN.search(auth_header)
            if in_token:
                in_token = base64.b64decode(in_token.group(2))

            # If there was no token received from the host then we just break the auth cycle.
            if not in_token:
                break

            out_token = await _async_wrap(self._context.step, in_token)

        return status_code, headers.raw, stream, ext

    async def _create_connection(
            self,
            url: URL,
            ext: typing.Dict,
    ):
        timeout = ext.get('timeout', {})
        proxy_url = self._proxy_url.raw if self._proxy_url else None
        scheme, host, port = (proxy_url or url)[:3]
        ssl_context = self._ssl_context if scheme == b'https' else None

        self._socket = await SocketStream.open_socket(
            host.decode('utf-8'), port, ssl_context, timeout.get('connect'),
        )
        connection = AsyncHTTPConnection(self._socket)

        if not proxy_url:
            return connection

        try:
            target_scheme, target_host, target_port = url[:3]

            if target_scheme == b'http':
                # Add auth options
                return AsyncHTTPProxy(proxy_url, connection)

            # CONNECT
            target = b'%b:%d' % (target_host, target_port)
            connect_url = proxy_url[:3] + (target,)
            connect_headers = [(b'Host', target), (b'Accept', b'*/*')]

            proxy_status_code, _, proxy_stream, _ = await connection.arequest(
                b'CONNECT', connect_url, headers=connect_headers, ext=ext,
            )
            async for _ in proxy_stream:
                pass

            if proxy_status_code < 200 or proxy_status_code > 299:
                raise Exception(f'Proxy failed {proxy_status_code}')

            # do start_tls on the connection
            tls_sock = await self._socket.start_tls(target_host, self._ssl_context, timeout)
            connection = AsyncHTTPConnection(tls_sock)
            self._socket = tls_sock

        except Exception:
            await self._socket.aclose()
            self._socket = None
            raise

        return connection

    async def _get_connection(self):
        connection = self._connection

        if not connection:
            return

        must_close = False

        if connection.state == ConnectionState.IDLE:
            now = _time()
            if connection.is_socket_readable() or now >= connection.expires_at:
                must_close = True

        else:
            must_close = True

        if must_close:
            await connection.aclose()
            self._connection = None

            await self._socket.aclose()
            self._socket = None

        return self._connection

    async def _wrap_stream(
            self,
            headers: Headers,
            stream: typing.Optional[AsyncByteStream] = None,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        temp_headers = httpx.Headers(headers)

        if self._encrypt and stream:
            dec_data = bytearray()
            async for data in stream:
                dec_data += data

            protocol = {
                'kerberos': 'Kerberos',
                'credssp': 'CredSSP',
            }.get(self.protocol, 'SPNEGO')
            enc_data, content_type = encrypt_wsman(dec_data, temp_headers['Content-Type'],
                                                   f'application/HTTP-{protocol}-session-encrypted', self._context)
            temp_headers['Content-Type'] = content_type
            temp_headers['Content-Length'] = str(len(enc_data))

            stream = PlainByteStream(enc_data)

        elif not stream:
            temp_headers['Content-Length'] = '0'

        return temp_headers, stream

    async def _unwrap_stream(
            self,
            headers: Headers,
            stream: AsyncByteStream,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        # We make sure we always read the incoming stream so the connection is set to IDLE when closing the response.
        # This allows subsequent requests to reuse the connection.
        data = bytearray()
        async for chunk in stream:
            data += chunk
        await stream.aclose()
        self._connection.expires_at = _time() + self._keepalive_expiry

        temp_headers = httpx.Headers(headers)

        content_type = temp_headers.get('Content-Type', '')
        if content_type.startswith('multipart/encrypted;') or \
                content_type.startswith('multipart/x-multi-encrypted;'):

            data, content_type = decrypt_wsman(data, content_type, self._context)
            temp_headers['Content-Length'] = str(len(data))
            temp_headers['Content-Type'] = content_type

        return temp_headers, PlainByteStream(bytes(data))


class AsyncHTTPProxy(AsyncWSManTransport):

    _REQUEST_HEADER = 'proxy-authorization'
    _RESPONSE_HEADER = 'proxy-authenticate'

    def __init__(
            self,
            proxy_url: URL,
            connection: AsyncHTTPConnection,

            ssl_context: ssl.SSLContext = None,
            credential: typing.Any = None,
            protocol: str = 'none',
            service: str = 'HTTP',
            hostname_override: typing.Optional[str] = None,
            disable_cbt: bool = False,
    ):
        super().__init__(
            ssl_context=ssl_context,
            encrypt=False,
            credential=credential,
            protocol=protocol,
            service=service,
            hostname_override=hostname_override,
            disable_cbt=disable_cbt,
        )

        self.proxy_url = proxy_url
        self.connection = connection

    @property
    def expires_at(self) -> float:
        return self.connection.expires_at

    @expires_at.setter
    def expires_at(self, value: float):
        self.connection.expires_at = value

    @property
    def socket(self) -> SocketStream:
        return self.connection.socket

    @property
    def state(self) -> ConnectionState:
        return self.connection.state

    async def aclose(self) -> None:
        if self.connection:
            await self.connection.aclose()
            self.connection = None

    async def arequest(
            self,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        ext = ext or {}

        # Issue a forwarded proxy request...

        # GET https://www.example.org/path HTTP/1.1
        # [proxy headers]
        # [headers]
        scheme, host, port, path = url
        if port is None:
            target = b'%s://%b%b' % (scheme, host, path)
        else:
            target = b"%b://%b:%d%b" % (scheme, host, port, path)

        url = self.proxy_url[:3] + (target,)
        return await self.connection.arequest(
            method, url, headers=headers, stream=stream, ext=ext
        )

    def is_socket_readable(self):
        return self.connection.is_socket_readable()
