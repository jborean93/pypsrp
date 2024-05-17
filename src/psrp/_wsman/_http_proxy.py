# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import ssl

import httpcore

from ._auth import AuthProvider
from ._exceptions import WSManHTTPError
from ._http import AsyncHTTPConnection, SyncHTTPConnection, check_response_status
from ._proxy import Proxy

_PROXY_AUTH_HEADERS = (b"Proxy-Authenticate", b"Proxy-Authorization")


def _create_connect_request(
    target: httpcore.Origin,
    proxy: httpcore.Origin,
) -> httpcore.Request:
    url_target = b"%b:%d" % (target.host, target.port)
    connect_url = httpcore.URL(
        scheme=proxy.scheme,
        host=proxy.host,
        port=proxy.port,
        target=url_target,
    )
    connect_headers = [
        (b"Host", url_target),
        (b"Accept", b"*/*"),
    ]
    return httpcore.Request(
        method=b"CONNECT",
        url=connect_url,
        headers=connect_headers,
        extensions={},
    )


class AsyncHTTPProxy(AsyncHTTPConnection):
    def __init__(
        self,
        *,
        url: str,
        stream: httpcore.AsyncNetworkStream,
        auth_provider: AuthProvider | None = None,
        tunnel: bool = False,
    ) -> None:
        super().__init__(
            url=url,
            connect_timeout=0,
            auth_provider=auth_provider,
            ssl_context=None,
            auth_headers=_PROXY_AUTH_HEADERS,
        )

        self._connection = httpcore.AsyncHTTP11Connection(
            origin=self._parsed_url.origin,
            stream=stream,
        )
        self._tunnel = tunnel

    async def handle_async_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        if not self._tunnel:
            origin = self._parsed_url.origin
            url = httpcore.URL(
                scheme=origin.scheme,
                host=origin.host,
                port=origin.port,
                target=bytes(request.url),
            )
            request = httpcore.Request(
                method=request.method,
                url=url,
                headers=request.headers,
                content=request.stream,
                extensions=request.extensions,
            )

        return await super().handle_async_request(request)


class SyncHTTPProxy(SyncHTTPConnection):
    def __init__(
        self,
        *,
        url: str,
        stream: httpcore.NetworkStream,
        auth_provider: AuthProvider | None = None,
        tunnel: bool = False,
    ) -> None:
        super().__init__(
            url=url,
            connect_timeout=0,
            auth_provider=auth_provider,
            ssl_context=None,
            auth_headers=_PROXY_AUTH_HEADERS,
        )

        self._connection = httpcore.HTTP11Connection(
            origin=self._parsed_url.origin,
            stream=stream,
        )
        self._tunnel = tunnel

    def handle_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        if not self._tunnel:
            origin = self._parsed_url.origin
            url = httpcore.URL(
                scheme=origin.scheme,
                host=origin.host,
                port=origin.port,
                target=bytes(request.url),
            )
            request = httpcore.Request(
                method=request.method,
                url=url,
                headers=request.headers,
                content=request.stream,
                extensions=request.extensions,
            )

        return super().handle_request(request)


class HTTPProxy(Proxy):
    """HTTP Proxy.

    This is a HTTP proxy implementation. This implementation can be used for
    both HTTP and HTTPS proxy servers and supports the same authentication
    methods allowed by the WSMan implementation; basic, kerberos, negotiate,
    and ntlm.

    The HTTP proxy can also be used to tunnel a connection through the HTTP
    CONNECT request that is needed when the final target is a HTTPS endpoint.

    Args:
        url: The proxy URL.
        connect_timeout: The time, in seconds, to wait for the connection to
            complete.
        auth_provider: The authentication provider to use.
        ssl_context: The TLS context used to wrap the proxy connection.
        tunnel: If the connection should be tunneled through the proxy.
    """

    def __init__(
        self,
        url: str,
        connect_timeout: float | None,
        *,
        auth_provider: AuthProvider | None = None,
        ssl_context: ssl.SSLContext | None = None,
        tunnel: bool = False,
    ) -> None:
        super().__init__(url, connect_timeout)

        self.auth_provider = auth_provider
        self.ssl_context = ssl_context
        self.tunnel = tunnel

    def copy(self) -> HTTPProxy:
        return HTTPProxy(
            url=self.url,
            auth_provider=self.auth_provider.copy() if self.auth_provider else None,
            connect_timeout=self.connect_timeout,
            ssl_context=self.ssl_context,
            tunnel=self.tunnel,
        )

    async def wrap_stream_async(
        self,
        stream: httpcore.AsyncNetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.AsyncNetworkStream:
        if self.ssl_context:
            stream = await stream.start_tls(
                self.ssl_context,
                server_hostname=self.parsed_url.origin.host.decode("ascii"),
                timeout=self.connect_timeout,
            )

        if not self.tunnel:
            return stream

        connection = AsyncHTTPProxy(
            url=self.url,
            stream=stream,
            auth_provider=self.auth_provider,
            tunnel=True,
        )

        connect_request = _create_connect_request(target, self.parsed_url.origin)
        connect_response = await connection.handle_async_request(connect_request)
        check_response_status(
            connect_response,
            b"",
            msg="Proxy CONNECT failed.",
        )

        return stream

    def wrap_stream_sync(
        self,
        stream: httpcore.NetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.NetworkStream:
        if self.ssl_context:
            stream = stream.start_tls(
                self.ssl_context,
                server_hostname=self.parsed_url.origin.host.decode("ascii"),
                timeout=self.connect_timeout,
            )

        if not self.tunnel:
            return stream

        connection = SyncHTTPProxy(
            url=self.url,
            stream=stream,
            auth_provider=self.auth_provider,
            tunnel=True,
        )

        connect_request = _create_connect_request(target, self.parsed_url.origin)
        connect_response = connection.handle_request(connect_request)
        check_response_status(
            connect_response,
            b"",
            msg="Proxy CONNECT failed.",
        )

        return stream

    async def create_connection_async(
        self,
        stream: httpcore.AsyncNetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.AsyncConnectionInterface:
        if self.tunnel:
            return await super().create_connection_async(stream, target)
        else:
            return AsyncHTTPProxy(
                url=self.url,
                stream=stream,
                auth_provider=self.auth_provider,
            )

    def create_connection_sync(
        self,
        stream: httpcore.NetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.ConnectionInterface:
        if self.tunnel:
            return super().create_connection_sync(stream, target)
        else:
            return SyncHTTPProxy(
                url=self.url,
                stream=stream,
                auth_provider=self.auth_provider,
            )
