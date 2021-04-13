# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import http
import httpx
import logging
import ssl
import typing

from httpcore import (
    AsyncByteStream,
    AsyncHTTPTransport,
)

from ._auth import (
    AsyncAuth,
    AsyncNoAuth,
)

from ._connection import (
    AsyncHTTPConnection,
    SocketStream,
)

from ._utils import (
    ConnectionState,
    Headers,
    URL,
)

HAS_SOCKS = True
try:
    from python_socks.async_.asyncio import Proxy
except ImportError:
    HAS_SOCKS = False


logger = logging.getLogger(__name__)


def _time() -> float:
    return asyncio.get_event_loop().time()


class AsyncWSManTransport(AsyncHTTPTransport):

    def __init__(
            self,
            auth: typing.Optional[AsyncAuth] = None,
            ssl_context: ssl.SSLContext = None,
            keepalive_expiry: float = 60.0,
            proxy_url: typing.Optional[str] = None,
            proxy_auth: typing.Optional[AsyncAuth] = None,
    ):
        # Connection options
        self._connection = None
        self._socket = None
        self._auth = auth or AsyncNoAuth()
        self._ssl_context = ssl_context
        self._keepalive_expiry = keepalive_expiry

        # Proxy options
        self._proxy_url = httpx.URL(proxy_url) if proxy_url else None
        self._proxy_auth = proxy_auth or AsyncNoAuth()

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
            self._auth.reset()
            self._connection = connection = await self._create_connection(url, ext)

        return await self._auth.arequest(
            connection, method, url, headers=headers, stream=stream, ext=ext)

    async def aclose(self) -> None:
        if self._connection:
            await self._connection.aclose()
            self._connection = None

        if self._socket:
            await self._socket.aclose()
            self._socket = None

    async def _create_connection(
            self,
            url: URL,
            ext: typing.Dict,
    ):
        timeout = ext.get('timeout', {})
        proxy_url = self._proxy_url.raw if self._proxy_url else None
        scheme, host, port = (proxy_url or url)[:3]
        ssl_context = None if scheme == b'http' else self._ssl_context

        sock_kwargs = {
            'connection_timeout': timeout.get('connect'),
        }

        if scheme in [b'socks5', b'socks5h']:
            if not HAS_SOCKS:
                raise ImportError("Need pypsrp[socks] to be installed")

            # python-socks doesn't natively understand socks5h, we adjust the
            # prefix and set rdns based on whether socks5h is set or not.
            proxy_url = str(self._proxy_url)
            rdns = False
            if scheme == b'socks5h':
                rdns = True
                proxy_url = proxy_url.replace('socks5h://', 'socks5://', 1)

            target_scheme, target_host, target_port = url[:3]
            proxy = Proxy.from_url(proxy_url, rdns=rdns)
            proxy_url = None

            sock_kwargs['sock'] = await proxy.connect(
                dest_host=target_host.decode('utf-8'),
                dest_port=target_port,
                timeout=sock_kwargs['connection_timeout'])

            if target_scheme == b'https':
                sock_kwargs.update({
                    'server_hostname': target_host.decode('utf-8'),
                    'ssl_context': self._ssl_context,
                })

        else:
            sock_kwargs.update({
                'hostname': host.decode('utf-8'),
                'port': port,
                'ssl_context': ssl_context,
            })

        self._socket = await SocketStream.open_socket(**sock_kwargs)
        connection = AsyncHTTPConnection(self._socket)
        if not proxy_url:
            return connection

        try:
            target_scheme, target_host, target_port = url[:3]

            if target_scheme == b'http':
                return AsyncProxyConnection(
                    proxy_url, connection,
                    auth=self._proxy_auth
                )

            # CONNECT
            target = b'%b:%d' % (target_host, target_port)
            connect_url = proxy_url[:3] + (target,)
            connect_headers = [(b'Host', target), (b'Accept', b'*/*')]

            proxy_status_code, proxy_headers, proxy_stream, _ = await self._proxy_auth.arequest(
                connection, b'CONNECT', connect_url, headers=connect_headers, ext=ext,
                auths_header='Proxy-Authenticate', authz_header='Proxy-Authorization'
            )

            if proxy_status_code < 200 or proxy_status_code > 299:
                try:
                    reason = http.HTTPStatus(proxy_status_code).phrase
                except ValueError:
                    reason = ''
                raise Exception(f'Proxy failed {proxy_status_code} {reason}')

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
            if connection.is_socket_readable():  # or now >= connection.expires_at:
                must_close = True

        else:
            must_close = True

        if must_close:
            await connection.aclose()
            self._connection = None

            await self._socket.aclose()
            self._socket = None

        return self._connection


class AsyncProxyConnection(AsyncHTTPTransport):

    def __init__(
            self,
            proxy_url: URL,
            connection: AsyncHTTPConnection,
            auth: AsyncAuth = None,
    ):
        self.proxy_url = proxy_url
        self._connection = connection
        self._auth = auth or AsyncNoAuth()

    @property
    def state(self):
        return self._connection.state

    @property
    def expires_at(self):
        return self._connection.expires_at

    @expires_at.setter
    def expires_at(self, value):
        self._connection.expires_at = value

    def is_socket_readable(self):
        return self._connection.is_socket_readable()

    async def arequest(
            self,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        ext = ext or {}

        scheme, host, port, path = url
        if port is None:
            target = b'%s://%b%b' % (scheme, host, path)
        else:
            target = b"%b://%b:%d%b" % (scheme, host, port, path)

        url = self.proxy_url[:3] + (target,)
        return await self._auth.arequest(
            self._connection, method, url, headers=headers, stream=stream,
            ext=ext, auths_header='Proxy-Authenticate',
            authz_header='Proxy-Authorization',
        )

    async def aclose(self) -> None:
        await self._connection.aclose()
