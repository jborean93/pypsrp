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


def _add_authorization_header(
    headers: list[tuple[bytes, bytes]],
    auth_value: bytes,
    auth_header_name: bytes,
) -> None:
    """Adds/Replaces the Authorization header with the value provided."""
    auth_idx = -1
    for idx, header in enumerate(headers):
        if header[0] == auth_header_name:
            auth_idx = idx
            break

    if auth_idx != -1:
        headers.pop(auth_idx)

    headers.append((auth_header_name, auth_value))


def _check_response_status(
    response: httpcore.Response,
    content: bytes,
) -> None:
    """Checks the response to see if it failed or contains a valid WSMan payload."""
    # A WSManFault has more information that the WSMan state machine can
    # handle with better context so we ignore those.
    if response.status != 200 and (not content or b"wsmanfault" not in content):
        # FIXME: Get better error message
        raise WSManHTTPError(response.status)


def _get_header_response_token(
    response: httpcore.Response | None,
    expected_label: bytes,
    auth_header_name: bytes,
    provider: AuthProvider,
) -> bytes | None:
    """Extracts the HTTP auth token from the WWW-Authenticate header."""
    if not response:
        return None

    www_authenticate = next(iter(v for k, v in response.headers if k == auth_header_name), None)
    if not www_authenticate or len(token_split := www_authenticate.split(b" ", maxsplit=1)) != 2:
        if response.status == 401:
            msg = f"Server did not response with authentication token in header {auth_header_name.decode()}"
            if auth_stage := provider.stage:
                msg += f"during stage: {auth_stage}"
            raise WSManAuthenticationError(401, msg=msg)

        return None

    if token_split[0] != expected_label:
        msg = f"Expecting {auth_header_name.decode()} label to be {expected_label.decode()} but got {token_split[0].decode()}"
        if auth_stage := provider.stage:
            msg += f"during stage: {auth_stage}"
        raise WSManAuthenticationError(401, msg=msg)

    return base64.b64decode(token_split[1])


def _prepare_wsman_request(
    request: httpcore.Request,
    encrypt: bool,
    auth_provider: AuthProvider,
) -> tuple[httpcore.Request, bool]:
    """Prepares the WSMan request before sending."""
    is_final = True
    if encrypt and isinstance(auth_provider, WSManEncryptionProvider):
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
    auth_provider: AuthProvider,
) -> httpcore.Response:
    """Processes the WSMan response after receiving."""
    headers = {k: v for k, v in response.headers}
    content_type = headers.get(b"Content-Type", None)

    if (
        content_type
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


class SyncWSManHTTP(httpcore.ConnectionInterface):
    def __init__(
        self,
        *,
        auth_provider: AuthProvider,
        connect_timeout: float,
        encrypt: bool,
        ssl_context: ssl.SSLContext | None,
        url: str,
    ) -> None:
        self._auth_provider: AuthProvider = auth_provider
        self._channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None
        self._connection: httpcore.ConnectionInterface | None = None
        self._connect_timeout = connect_timeout
        self._encrypt = encrypt
        self._ssl_context = ssl_context
        self._url = url
        self._parsed_url = httpcore.URL(url)

    def __enter__(self) -> SyncWSManHTTP:
        return self

    def __exit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        self.close()

    def copy(self) -> SyncWSManHTTP:
        """Creates a copy of the connection with the same authentication context."""
        return SyncWSManHTTP(
            auth_provider=self._auth_provider.copy(),
            connect_timeout=self._connect_timeout,
            ssl_context=self._ssl_context,
            url=self._url,
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
        _check_response_status(response, content)

        return content

    def close(self) -> None:
        if self._connection:
            self._connection.close()

    def handle_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        connection = self._get_connection(request.url.origin)
        prepared_request, is_final_req = _prepare_wsman_request(
            request,
            encrypt=self._encrypt,
            auth_provider=self._auth_provider,
        )

        self._add_authentication_headers(prepared_request, None)
        response = connection.handle_request(prepared_request)

        while self._add_authentication_headers(prepared_request, response):
            response.read()
            response.close()
            response = connection.handle_request(prepared_request)

        if response.status == 200 and not is_final_req:
            response.read()
            response.close()

            prepared_request, _ = _prepare_wsman_request(
                request,
                encrypt=self._encrypt,
                auth_provider=self._auth_provider,
            )
            self._add_authentication_headers(prepared_request, None)
            response = connection.handle_request(prepared_request)

        response.read()
        response.close()

        return _process_wsman_response(response, self._auth_provider)

    def _add_authentication_headers(
        self,
        request: httpcore.Request,
        response: httpcore.Response | None,
    ) -> bool:
        if self._auth_provider.complete:
            return False

        in_token = _get_header_response_token(
            response,
            self._auth_provider.http_auth_label,
            auth_header_name=b"WWW-Authenticate",
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

        _add_authorization_header(
            request.headers,
            auth_value,
            auth_header_name=b"Authorization",
        )
        return True

    def _get_connection(
        self,
        origin: httpcore.Origin,
    ) -> httpcore.ConnectionInterface:
        if self._connection:
            return self._connection

        host = origin.host.decode("ascii")

        network_backend = httpcore.SyncBackend()
        stream = network_backend.connect_tcp(
            host=host,
            port=origin.port,
            timeout=self._connect_timeout,
        )

        if self._ssl_context:
            stream = stream.start_tls(
                ssl_context=self._ssl_context,
                server_hostname=host,
                timeout=self._connect_timeout,
            )

            ssl_object = stream.get_extra_info("ssl_object")
            self._channel_bindings = get_tls_server_end_point_bindings(ssl_object)

        self._connection = httpcore.HTTP11Connection(
            origin=origin,
            stream=stream,
        )
        return self._connection


class AsyncWSManHTTP(httpcore.AsyncConnectionInterface):
    def __init__(
        self,
        *,
        auth_provider: AuthProvider,
        connect_timeout: float,
        encrypt: bool,
        ssl_context: ssl.SSLContext | None,
        url: str,
    ) -> None:
        self._auth_provider: AuthProvider = auth_provider
        self._channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None
        self._connection: httpcore.AsyncConnectionInterface | None = None
        self._connect_timeout = connect_timeout
        self._encrypt = encrypt
        self._ssl_context = ssl_context
        self._url = url
        self._parsed_url = httpcore.URL(url)

    async def __aenter__(self) -> AsyncWSManHTTP:
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self.aclose()

    def copy(self) -> AsyncWSManHTTP:
        """Creates a copy of the connection with the same authentication context."""
        return AsyncWSManHTTP(
            auth_provider=self._auth_provider.copy(),
            connect_timeout=self._connect_timeout,
            encrypt=self._encrypt,
            ssl_context=self._ssl_context,
            url=self._url,
        )

    async def aclose(self) -> None:
        if self._connection:
            await self._connection.aclose()

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
        _check_response_status(response, content)

        return content

    async def _add_authentication_headers(
        self,
        request: httpcore.Request,
        response: httpcore.Response | None,
    ) -> bool:
        if self._auth_provider.complete:
            return False

        in_token = _get_header_response_token(
            response,
            self._auth_provider.http_auth_label,
            auth_header_name=b"WWW-Authenticate",
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

        _add_authorization_header(
            request.headers,
            auth_value,
            auth_header_name=b"Authorization",
        )
        return True

    async def handle_async_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        connection = await self._get_connection(request.url.origin)
        prepared_request, is_final_req = _prepare_wsman_request(
            request,
            encrypt=self._encrypt,
            auth_provider=self._auth_provider,
        )

        await self._add_authentication_headers(prepared_request, None)
        response = await connection.handle_async_request(prepared_request)

        while await self._add_authentication_headers(prepared_request, response):
            await response.aread()
            await response.aclose()
            response = await connection.handle_async_request(prepared_request)

        if response.status == 200 and not is_final_req:
            await response.aread()
            await response.aclose()

            prepared_request, _ = _prepare_wsman_request(
                request,
                encrypt=self._encrypt,
                auth_provider=self._auth_provider,
            )
            await self._add_authentication_headers(prepared_request, None)
            response = await connection.handle_async_request(prepared_request)

        await response.aread()
        await response.aclose()

        return _process_wsman_response(response, self._auth_provider)

    async def _get_connection(
        self,
        origin: httpcore.Origin,
    ) -> httpcore.AsyncConnectionInterface:
        if not self._connection:
            self._connection, self._channel_bindings = await self._connection_factory(origin)
        return self._connection

    # async def _get_connection2(
    #     self,
    #     origin: httpcore.Origin,
    # ) -> httpcore.AsyncConnectionInterface:
    #     if self._connection:
    #         return self._connection

    #     host = origin.host.decode("ascii")

    #     network_backend = httpcore.AnyIOBackend()
    #     stream = await network_backend.connect_tcp(
    #         host=host,
    #         port=origin.port,
    #         timeout=self._connect_timeout,
    #     )

    #     if self._ssl_context:
    #         stream = await stream.start_tls(
    #             ssl_context=self._ssl_context,
    #             server_hostname=host,
    #             timeout=self._connect_timeout,
    #         )

    #         ssl_object = stream.get_extra_info("ssl_object")
    #         self._channel_bindings = get_tls_server_end_point_bindings(ssl_object)

    #     self._connection = httpcore.AsyncHTTP11Connection(
    #         origin=origin,
    #         stream=stream,
    #     )
    #     return self._connection


# class AsyncHTTPProxy(httpcore.AsyncConnectionInterface):

#     def __init__(
#         self,
#         *,
#         url: httpcore.URL,
#         auth_provider: AuthProvider | None = None,
#         ssl_context: ssl.SSLContext | None = None,
#     ) -> None:
#         self._auth_provider = auth_provider
#         self._ssl_context = ssl_context
#         self._url = url
#         self._connection: httpcore.AsyncConnectionInterface | None = None

#     async def handle_async_request(
#         self,
#         request: httpcore.Request,
#     ) -> httpcore.Response:
#         url = httpcore.URL(
#             scheme=self._url.scheme,
#             host=self._url.host,
#             port=self._url.port,
#             target=bytes(request.url),
#         )

#         connection = await self.create_connection()

#         # _add_authorization_header(request.headers, b"", b"")
#         # headers = merge_headers(self._proxy_headers, request.headers)

#         proxy_request = httpcore.Request(
#             method=request.method,
#             url=url,
#             headers=request.headers,
#             content=request.stream,
#             extensions=request.extensions,
#         )
#         return await connection.handle_async_request(proxy_request)

#     async def create_connection(self) -> httpcore.AsyncConnectionInterface:
#         if self._connection:
#             return self._connection

#         host = self._url.host.decode("ascii")

#         network_backend = httpcore.AnyIOBackend()
#         stream = await network_backend.connect_tcp(
#             host=host,
#             port=self._url.origin.port,
#             timeout=30.0,
#         )

#         if self._ssl_context:
#             stream = await stream.start_tls(
#                 ssl_context=self._ssl_context,
#                 server_hostname=host,
#                 timeout=30.0,
#             )

#         self._connection = httpcore.AsyncHTTP11Connection(
#             origin=self._url.origin,
#             stream=stream,
#         )
#         return self._connection


# class AsyncHTTPSProxy(httpcore.AsyncConnectionInterface):

#     async def handle_async_request(
#         self,
#         request: httpcore.Request,
#     ) -> httpcore.Response:
#         # Do CONNECT

#         # Send to underlying connection
#         url = httpcore.URL(
#             scheme=self._url.scheme,
#             host=self._url.host,
#             port=self._url.port,
#             target=bytes(request.url),
#         )

#         connection = await self.create_connection()

#         # _add_authorization_header(request.headers, b"", b"")
#         # headers = merge_headers(self._proxy_headers, request.headers)

#         proxy_request = httpcore.Request(
#             method=request.method,
#             url=url,
#             headers=request.headers,
#             content=request.stream,
#             extensions=request.extensions,
#         )
#         return await connection.handle_async_request(proxy_request)

#     async def create_connection(self) -> httpcore.AsyncConnectionInterface:
#         if self._connection:
#             return self._connection

#         host = self._url.host.decode("ascii")

#         network_backend = httpcore.AnyIOBackend()
#         stream = await network_backend.connect_tcp(
#             host=host,
#             port=self._url.origin.port,
#             timeout=30.0,
#         )

#         if self._ssl_context:
#             stream = await stream.start_tls(
#                 ssl_context=self._ssl_context,
#                 server_hostname=host,
#                 timeout=30.0,
#             )

#         self._connection = httpcore.AsyncHTTP11Connection(
#             origin=self._url.origin,
#             stream=stream,
#         )
#         return self._connection


"""Proxy needs to
WSMan HTTP
    + Connect to proxy socket
    + Do TLS with proxy if needed
    + Do WSMan dance
    + Wrap request with proxy headers and new URL
    + Send request to proxy
        + Do proxy auth dance until success or failure

WSMan HTTPS
    + Connect to proxy socket
    + Do TLS with proxy if needed
    + Do proxy CONNECT dance
        + With auth loop if needed
    + Wrap stream in another TLS stream
    + Provide cbt to WSMan
    + Do WSMan dance with auth
    + Send request to the wrapped TLS stream
"""
