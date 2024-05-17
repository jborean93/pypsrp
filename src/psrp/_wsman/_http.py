# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import collections.abc
import ssl
import typing as t

import httpcore
import spnego
import spnego.channel_bindings
import spnego.tls

from ._auth import AuthProvider, WSManEncryptionProvider
from ._exceptions import WSManAuthenticationError, WSManHTTPError
from ._proxy import Proxy
from ._tls import get_tls_server_end_point_bindings

# Default for 'Accept-Encoding' is 'gzip, default' which normally
# doesn't matter on vanilla WinRM but for Exchange endpoints hosted on
# IIS they actually compress it with 1 of the 2 algorithms. By
# explicitly setting identity we are telling the server not to
# transform (compress) the data using the HTTP methods which we don't
# support. https://tools.ietf.org/html/rfc7231#section-5.3.4
_DEFAULT_HEADERS: collections.abc.Mapping[bytes | str, bytes | str] = {
    "Accept-Encoding": "identity",
    "Content-Type": "application/soap+xml;charset=UTF-8",
    "User-Agent": "Python PSRP Client",
}

_WWW_AUTH_HEADERS = (b"WWW-Authenticate", b"Authorization")


def _prepare_wsman_request(
    request: httpcore.Request,
    encrypt: bool,
    auth_provider: AuthProvider | None,
) -> tuple[httpcore.Request, bool]:
    """Prepares the WSMan request before sending."""
    is_final = True
    if encrypt and auth_provider and isinstance(auth_provider, WSManEncryptionProvider):
        headers = {k: v for k, v in request.headers}

        if auth_provider.complete:
            assert isinstance(request.stream, collections.abc.Iterable)
            to_encrypt = b"".join(request.stream)
            content, content_type = auth_provider.wrap(
                to_encrypt,
                headers[b"Content-Type"].decode(),
            )
            headers[b"Content-Type"] = content_type

        else:
            # If we are encrypting and the auth context isn't setup we
            # need to send a blank message to ensure we don't disclose the
            # contents.
            is_final = False
            content = b""

        headers[b"Content-Length"] = str(len(content)).encode()
        request = httpcore.Request(
            method=request.method,
            url=request.url,
            headers=[(k, v) for k, v in headers.items()],
            content=content,
            extensions=request.extensions,
        )

    return request, is_final


def _process_wsman_response(
    response: httpcore.Response,
    auth_provider: AuthProvider | None,
) -> httpcore.Response:
    """Processes the WSMan response after receiving."""
    headers = {k: v for k, v in response.headers}
    content_type = headers.get(b"Content-Type", None)

    if (
        content_type
        and auth_provider
        and auth_provider.complete
        and isinstance(auth_provider, WSManEncryptionProvider)
        and (
            content_type.startswith(b"multipart/encrypted;") or content_type.startswith(b"multipart/x-multi-encrypted;")
        )
    ):
        to_decrypt = response.content

        data, content_type = auth_provider.unwrap(
            bytearray(to_decrypt),
            content_type.decode(),
        )
        headers[b"Content-Length"] = str(len(data)).encode()
        headers[b"Content-Type"] = content_type

        return httpcore.Response(
            status=response.status,
            headers=[(k, v) for k, v in headers.items()],
            content=data,
            extensions=response.extensions,
        )

    else:
        return response


def add_http_header(
    headers: list[tuple[bytes, bytes]],
    name: bytes,
    value: bytes,
) -> None:
    """Adds/Replaces a HTTP header with the value provided."""
    for idx, header in enumerate(headers):
        if header[0] == name:
            headers[idx] = (name, value)
            return

    headers.append((name, value))


def check_response_status(
    response: httpcore.Response,
    content: bytes,
    msg: str | None = None,
) -> None:
    """Checks the response to see if it failed or contains a valid WSMan payload."""
    # A WSManFault has more information that the WSMan state machine can
    # handle with better context so we ignore those.
    if response.status != 200 and (not content or b"wsmanfault" not in content):
        raise WSManHTTPError(response.status, msg=msg)


def get_header_response_token(
    response: httpcore.Response | None,
    expected_label: bytes,
    auth_header_name: bytes,
    provider: AuthProvider,
) -> bytes | None:
    """Extracts the HTTP auth token from the WWW-Authenticate header."""
    if not response:
        return None

    www_authenticate = next(iter(v for k, v in response.headers if k == auth_header_name), None)
    if www_authenticate and len(token_split := www_authenticate.split(b" ", maxsplit=1)) == 2:
        if token_split[0] != expected_label:
            msg = f"Expecting {auth_header_name.decode()} label to be {expected_label.decode()} but got {token_split[0].decode()}"
            if auth_stage := provider.stage:
                msg += f"during stage: {auth_stage}"
            raise WSManAuthenticationError(401, msg=msg)

        try:
            return base64.b64decode(token_split[1])
        except ValueError:
            pass

    if auth_header_name in _WWW_AUTH_HEADERS:
        target = "Server"
        error_code = 401

    else:
        target = "Proxy server"
        error_code = 407

    if response.status == error_code:
        msg = f"{target} did not response with authentication token in header {auth_header_name.decode()}"
        if auth_stage := provider.stage:
            msg += f"during stage: {auth_stage}"
        raise WSManAuthenticationError(error_code, msg=msg)

    return None


class AsyncHTTPConnection(httpcore.AsyncConnectionInterface):
    def __init__(
        self,
        *,
        url: str,
        connect_timeout: float,
        auth_provider: AuthProvider | None = None,
        ssl_context: ssl.SSLContext | None = None,
        proxy: Proxy | None = None,
        auth_headers: tuple[bytes, bytes] = _WWW_AUTH_HEADERS,
    ) -> None:
        self._auth_headers = auth_headers
        self._auth_provider = auth_provider
        self._channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None
        self._connection: httpcore.AsyncConnectionInterface | None = None
        self._connect_timeout = connect_timeout
        self._ssl_context = ssl_context
        self._proxy = proxy
        self._url = url
        self._parsed_url = httpcore.URL(url)

    async def __aenter__(self) -> t.Self:
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._connection:
            await self._connection.aclose()

    async def handle_async_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        connection = await self._get_connection(request.url.origin)

        await self._add_authentication_headers(request, None)
        response = await connection.handle_async_request(request)

        while await self._add_authentication_headers(request, response):
            await response.aread()
            await response.aclose()
            response = await connection.handle_async_request(request)

        return response

    async def _add_authentication_headers(
        self,
        request: httpcore.Request,
        response: httpcore.Response | None,
    ) -> bool:
        if self._auth_provider is None or self._auth_provider.complete:
            return False

        in_token = get_header_response_token(
            response,
            self._auth_provider.http_auth_label,
            auth_header_name=self._auth_headers[0],
            provider=self._auth_provider,
        )
        if response and not in_token:
            return False

        out_token = await self._auth_provider.step_async(
            in_token=in_token,
            channel_bindings=self._channel_bindings,
        )

        if out_token is None:
            return False

        auth_value = self._auth_provider.http_auth_label
        if out_token:
            auth_value += b" " + base64.b64encode(out_token)

        add_http_header(
            request.headers,
            name=self._auth_headers[1],
            value=auth_value,
        )
        return True

    async def _get_connection(
        self,
        origin: httpcore.Origin,
    ) -> httpcore.AsyncConnectionInterface:
        if self._connection:
            return self._connection

        target_host = origin.host.decode("ascii")

        if self._proxy:
            stream = await httpcore.AnyIOBackend().connect_tcp(
                host=self._proxy.parsed_url.origin.host.decode("ascii"),
                port=self._proxy.parsed_url.origin.port,
                timeout=self._proxy.connect_timeout,
            )
            stream = await self._proxy.wrap_stream_async(stream, origin)

        else:
            stream = await httpcore.AnyIOBackend().connect_tcp(
                host=target_host,
                port=origin.port,
                timeout=self._connect_timeout,
            )

        if self._ssl_context:
            stream = await stream.start_tls(
                ssl_context=self._ssl_context,
                server_hostname=target_host,
                timeout=self._connect_timeout,
            )

            ssl_object = stream.get_extra_info("ssl_object")
            self._channel_bindings = get_tls_server_end_point_bindings(ssl_object)

        if self._proxy:
            self._connection = await self._proxy.create_connection_async(stream, origin)
        else:
            self._connection = httpcore.AsyncHTTP11Connection(origin, stream)

        return self._connection


class SyncHTTPConnection(httpcore.ConnectionInterface):
    def __init__(
        self,
        *,
        url: str,
        connect_timeout: float,
        auth_provider: AuthProvider | None = None,
        ssl_context: ssl.SSLContext | None = None,
        proxy: Proxy | None = None,
        auth_headers: tuple[bytes, bytes] = _WWW_AUTH_HEADERS,
    ) -> None:
        self._auth_headers = auth_headers
        self._auth_provider = auth_provider
        self._channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None
        self._connection: httpcore.ConnectionInterface | None = None
        self._connect_timeout = connect_timeout
        self._ssl_context = ssl_context
        self._proxy = proxy
        self._url = url
        self._parsed_url = httpcore.URL(url)

    def __enter__(self) -> t.Self:
        return self

    def __exit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._connection:
            self._connection.close()

    def handle_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        connection = self._get_connection(request.url.origin)

        self._add_authentication_headers(request, None)
        response = connection.handle_request(request)

        while self._add_authentication_headers(request, response):
            response.read()
            response.close()
            response = connection.handle_request(request)

        return response

    def _add_authentication_headers(
        self,
        request: httpcore.Request,
        response: httpcore.Response | None,
    ) -> bool:
        if self._auth_provider is None or self._auth_provider.complete:
            return False

        in_token = get_header_response_token(
            response,
            self._auth_provider.http_auth_label,
            auth_header_name=self._auth_headers[0],
            provider=self._auth_provider,
        )
        if response and not in_token:
            return False

        out_token = self._auth_provider.step(
            in_token=in_token,
            channel_bindings=self._channel_bindings,
        )

        if out_token is None:
            return False

        auth_value = self._auth_provider.http_auth_label
        if out_token:
            auth_value += b" " + base64.b64encode(out_token)

        add_http_header(
            request.headers,
            name=self._auth_headers[1],
            value=auth_value,
        )
        return True

    def _get_connection(
        self,
        origin: httpcore.Origin,
    ) -> httpcore.ConnectionInterface:
        if self._connection:
            return self._connection

        target_host = origin.host.decode("ascii")

        if self._proxy:
            stream = httpcore.SyncBackend().connect_tcp(
                host=self._proxy.parsed_url.origin.host.decode("ascii"),
                port=self._proxy.parsed_url.origin.port,
                timeout=self._proxy.connect_timeout,
            )
            stream = self._proxy.wrap_stream_sync(stream, origin)

        else:
            stream = httpcore.SyncBackend().connect_tcp(
                host=target_host,
                port=origin.port,
                timeout=self._connect_timeout,
            )

        if self._ssl_context:
            stream = stream.start_tls(
                ssl_context=self._ssl_context,
                server_hostname=target_host,
                timeout=self._connect_timeout,
            )

            ssl_object = stream.get_extra_info("ssl_object")
            self._channel_bindings = get_tls_server_end_point_bindings(ssl_object)

        if self._proxy:
            self._connection = self._proxy.create_connection_sync(stream, origin)
        else:
            self._connection = httpcore.HTTP11Connection(origin, stream)

        return self._connection


class AsyncWSManHTTP(AsyncHTTPConnection):
    """WSMan HTTP Transport.

    This class is used for communicating to a WSMan server. It will handle the
    authentication and other HTTP transport operations.

    Args:
        url: The WSMan URL to connect to.
        connect_timeout: The time, in seconds, to wait for the connection to be
            established.
        auth_provider: The WSMan authentication provider.
        encrypt: Whether to encrypt the WSMan payload using the provided auth
            provider.
        ssl_context: The TLS context to wrap the connection in for HTTPS endpoints.
            endpoints.
        proxy: Optional Proxy object to proxy the transport through.
    """

    def __init__(
        self,
        *,
        url: str,
        connect_timeout: float,
        auth_provider: AuthProvider | None,
        encrypt: bool,
        ssl_context: ssl.SSLContext | None,
        proxy: Proxy | None = None,
    ) -> None:
        super().__init__(
            url=url,
            connect_timeout=connect_timeout,
            auth_provider=auth_provider,
            ssl_context=ssl_context,
            proxy=proxy,
        )

        self._encrypt = encrypt

    def copy(self) -> AsyncWSManHTTP:
        """Creates a copy of the connection with the same authentication context."""
        return AsyncWSManHTTP(
            url=self._url,
            connect_timeout=self._connect_timeout,
            auth_provider=self._auth_provider.copy() if self._auth_provider else None,
            encrypt=self._encrypt,
            ssl_context=self._ssl_context,
            proxy=self._proxy.copy() if self._proxy else None,
        )

    async def wsman_post(
        self,
        content: bytes,
    ) -> bytes:
        response = await self.request(
            "POST",
            self._parsed_url,
            headers=_DEFAULT_HEADERS,
            content=content,
        )

        content = await response.aread()
        await response.aclose()
        check_response_status(response, content)

        return content

    async def handle_async_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        prepared_request, is_final_req = _prepare_wsman_request(
            request,
            self._encrypt,
            self._auth_provider,
        )

        response = await super().handle_async_request(prepared_request)
        if response.status == 200 and not is_final_req:
            await response.aread()
            await response.aclose()

            prepared_request, _ = _prepare_wsman_request(
                request,
                self._encrypt,
                self._auth_provider,
            )
            await self._add_authentication_headers(prepared_request, None)
            response = await super().handle_async_request(prepared_request)

        await response.aread()
        await response.aclose()
        return _process_wsman_response(response, self._auth_provider)


class SyncWSManHTTP(SyncHTTPConnection):
    """WSMan HTTP Transport.

    This class is used for communicating to a WSMan server. It will handle the
    authentication and other HTTP transport operations.

    Args:
        url: The WSMan URL to connect to.
        connect_timeout: The time, in seconds, to wait for the connection to be
            established.
        auth_provider: The WSMan authentication provider.
        encrypt: Whether to encrypt the WSMan payload using the provided auth
            provider.
        ssl_context: The TLS context to wrap the connection in for HTTPS endpoints.
            endpoints.
        proxy: Optional Proxy object to proxy the transport through.
    """

    def __init__(
        self,
        *,
        url: str,
        connect_timeout: float,
        auth_provider: AuthProvider | None,
        encrypt: bool,
        ssl_context: ssl.SSLContext | None,
        proxy: Proxy | None = None,
    ) -> None:
        super().__init__(
            url=url,
            connect_timeout=connect_timeout,
            auth_provider=auth_provider,
            ssl_context=ssl_context,
            proxy=proxy,
        )

        self._encrypt = encrypt

    def copy(self) -> SyncWSManHTTP:
        """Creates a copy of the connection with the same authentication context."""
        return SyncWSManHTTP(
            url=self._url,
            connect_timeout=self._connect_timeout,
            auth_provider=self._auth_provider.copy() if self._auth_provider else None,
            encrypt=self._encrypt,
            ssl_context=self._ssl_context,
            proxy=self._proxy.copy() if self._proxy else None,
        )

    def wsman_post(
        self,
        content: bytes,
    ) -> bytes:
        response = self.request(
            "POST",
            self._parsed_url,
            headers=_DEFAULT_HEADERS,
            content=content,
        )

        content = response.read()
        response.close()
        check_response_status(response, content)

        return content

    def handle_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        prepared_request, is_final_req = _prepare_wsman_request(
            request,
            self._encrypt,
            self._auth_provider,
        )

        response = super().handle_request(prepared_request)
        if response.status == 200 and not is_final_req:
            response.read()
            response.close()

            prepared_request, _ = _prepare_wsman_request(
                request,
                self._encrypt,
                self._auth_provider,
            )
            self._add_authentication_headers(prepared_request, None)
            response = super().handle_request(prepared_request)

        response.read()
        response.close()
        return _process_wsman_response(response, self._auth_provider)
