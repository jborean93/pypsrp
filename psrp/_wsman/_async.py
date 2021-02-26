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

    def __init__(
            self,
            ssl_context: ssl.SSLContext,
            keepalive_expiry: float,
            encrypt: bool = True,
            username: typing.Optional[str] = None,
            password: typing.Optional[str] = None,
            protocol: str = 'negotiate',
            service: str = 'HTTP',
            hostname_override: typing.Optional[str] = None,
            disable_cbt: bool = False,
            delegate: bool = False,
            credssp_allow_tlsv1: bool = False,
            credssp_require_kerberos: bool = False,
    ):
        # Connection options
        self._connection = None
        self._socket = None
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

    @property
    def _time(self) -> float:
        return asyncio.get_event_loop().time()

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

        if not self._context:
            # Set up the authentication context. If we are encrypting data we cannot send anything at the moment.
            response = await self._authenticate(
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

    async def _authenticate(
            self,
            connection: AsyncHTTPConnection,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
    ):
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

        auth_hostname = self._hostname_override or url[1].decode('utf-8')
        self._context = await _async_wrap(
            spnego.client, self._username, self._password, hostname=auth_hostname,
            service=self._service, channel_bindings=cbt, context_req=self._context_req,
            protocol=self.protocol, options=self._spnego_options
        )

        status_code = 500
        send_headers = headers
        out_token = await _async_wrap(self._context.step)
        while not self._context.complete or out_token is not None:
            send_headers['Authorization'] = f'{auth_header} {base64.b64encode(out_token).decode()}'
            status_code, headers, stream, ext = await connection.arequest(method, url, headers=send_headers.raw,
                                                                          stream=stream, ext=ext)
            headers, stream = await self._unwrap_stream(headers, stream)

            auth_header = headers.get('www-authenticate', '')
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
        scheme, hostname, port = url[:3]
        ssl_context = self._ssl_context if scheme == b'https' else None
        timeout = ext.get('timeout', {})

        self._socket = await SocketStream.open_socket(
            hostname.decode('utf-8'), port, ssl_context,
            timeout.get('connect'),
        )

        connection = AsyncHTTPConnection(self._socket)
        connection.expires_at = self._time + self._keepalive_expiry

        return connection

    async def _get_connection(self):
        connection = self._connection

        if not connection:
            return

        must_close = False

        if connection.state == ConnectionState.IDLE:
            now = self._time
            if connection.is_socket_readable() or now >= connection.expires_at:
                must_close = True

        else:
            must_close = True

        if must_close:
            await connection.aclose()
            self._connection = None

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
        self._connection.expires_at = self._time + self._keepalive_expiry

        temp_headers = httpx.Headers(headers)

        content_type = temp_headers.get('Content-Type', '')
        if content_type.startswith('multipart/encrypted;') or \
                content_type.startswith('multipart/x-multi-encrypted;'):

            data, content_type = decrypt_wsman(data, content_type, self._context)
            temp_headers['Content-Length'] = str(len(data))
            temp_headers['Content-Type'] = content_type

        return temp_headers, PlainByteStream(bytes(data))
