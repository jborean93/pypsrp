# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
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

from ._auth import WSManAuthProvider, WSManEncryptionProvider
from ._exceptions import WSManAuthenticationError, WSManHTTPError
from ._tls import get_tls_server_end_point_bindings


def get_header_response_token(
    headers: list[tuple[bytes, bytes]],
    expected_label: bytes,
    auth_header: bytes,
) -> bytes | None:
    www_authenticate = next(iter(v for k, v in headers if k == auth_header), None)
    if not www_authenticate or len(token_split := www_authenticate.split(b" ", maxsplit=1)) != 2:
        return None

    if token_split[0] != expected_label:
        raise WSManAuthenticationError(
            f"Expecting {auth_header.decode()} label to be {expected_label.decode()} but got {token_split[0].decode()}",
            401,
        )

    return base64.b64decode(token_split[1])


class SyncWSManHTTP(httpcore.ConnectionInterface):
    def __init__(
        self,
        *,
        auth_provider: WSManAuthProvider,
        connect_timeout: float,
        encrypt: bool = True,
        ssl_context: ssl.SSLContext | None,
        url: str,
    ) -> None:
        self._auth_provider: WSManAuthProvider = auth_provider
        self._channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None
        self._connection: httpcore.AsyncConnectionInterface | None = None
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
        # Default for 'Accept-Encoding' is 'gzip, default' which normally
        # doesn't matter on vanilla WinRM but for Exchange endpoints hosted on
        # IIS they actually compress it with 1 of the 2 algorithms. By
        # explicitly setting identity we are telling the server not to
        # transform (compress) the data using the HTTP methods which we don't
        # support. https://tools.ietf.org/html/rfc7231#section-5.3.4
        headers: collections.abc.Mapping[bytes | str, bytes | str] = {
            "Accept-Encoding": "identity",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Python PSRP Client",
        }

        response = self.request(
            "POST",
            self._parsed_url,
            headers=headers,
            content=content,
        )

        content = response.read()
        response.close()

        # A WSManFault has more information that the WSMan state machine can
        # handle with better context so we ignore those.
        if response.status != 200 and (not content or b"wsmanfault" not in content):
            raise WSManHTTPError("foo", response.status)

        return content


class AsyncWSManHTTP(httpcore.AsyncConnectionInterface):
    def __init__(
        self,
        *,
        auth_provider: WSManAuthProvider,
        connect_timeout: float,
        encrypt: bool = True,
        ssl_context: ssl.SSLContext | None,
        url: str,
    ) -> None:
        self._auth_provider: WSManAuthProvider = auth_provider
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
        return AsyncWSManHTTP(
            auth_provider=self._auth_provider.copy(),
            connect_timeout=self._connect_timeout,
            ssl_context=self._ssl_context,
            url=self._url,
        )

    async def wsman_post(
        self,
        content: bytes,
    ) -> bytes:
        # Default for 'Accept-Encoding' is 'gzip, default' which normally
        # doesn't matter on vanilla WinRM but for Exchange endpoints hosted on
        # IIS they actually compress it with 1 of the 2 algorithms. By
        # explicitly setting identity we are telling the server not to
        # transform (compress) the data using the HTTP methods which we don't
        # support. https://tools.ietf.org/html/rfc7231#section-5.3.4
        headers: collections.abc.Mapping[bytes | str, bytes | str] = {
            "Accept-Encoding": "identity",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Python PSRP Client",
        }

        response = await self.request(
            "POST",
            self._parsed_url,
            headers=headers,
            content=content,
        )

        content = await response.aread()
        await response.aclose()

        # A WSManFault has more information that the WSMan state machine can
        # handle with better context so we ignore those.
        if response.status != 200 and (not content or b"wsmanfault" not in content):
            raise WSManHTTPError("foo", response.status)

        return content

    async def aclose(self) -> None:
        if self._connection:
            await self._connection.aclose()

    async def handle_async_request(
        self,
        request: httpcore.Request,
    ) -> httpcore.Response:
        connection = await self._get_connection(request.url.origin)
        prepared_request, is_final_req = self._prepare_request(request)

        await self._add_authentication_headers(prepared_request, None)
        response = await connection.handle_async_request(prepared_request)

        while await self._add_authentication_headers(prepared_request, response):
            await response.aread()
            await response.aclose()
            response = await connection.handle_async_request(prepared_request)

        if response.status == 200 and not is_final_req:
            await response.aread()
            await response.aclose()

            prepared_request, _ = self._prepare_request(request)
            await self._add_authentication_headers(prepared_request, None)
            response = await connection.handle_async_request(prepared_request)

        return await self._process_response(response)

    async def _add_authentication_headers(
        self,
        request: httpcore.Request,
        response: httpcore.Response | None,
    ) -> bool:
        if self._auth_provider.complete:
            return False

        in_token: bytes | None = None
        if response:
            in_token = get_header_response_token(
                response.headers,
                self._auth_provider.http_auth_label,
                auth_header=b"WWW-Authenticate",
            )

            if not in_token:
                if response.status == 401:
                    raise WSManAuthenticationError(
                        f"WSMan authentication failure - server did not respond with authentication token", 401
                    )
                else:
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

        auth_idx = -1
        for idx, header in enumerate(request.headers):
            if header[0] == b"Authorization":
                auth_idx = idx
                break

        if auth_idx != -1:
            request.headers.pop(auth_idx)

        request.headers.append((b"Authorization", auth_value))
        return True

    async def _get_connection(
        self,
        origin: httpcore.Origin,
    ) -> httpcore.AsyncConnectionInterface:
        if self._connection:
            return self._connection

        host = origin.host.decode("ascii")

        network_backend = httpcore.AnyIOBackend()
        stream = await network_backend.connect_tcp(
            host=host,
            port=origin.port,
            timeout=self._connect_timeout,
        )

        if self._ssl_context:
            stream = await stream.start_tls(
                ssl_context=self._ssl_context,
                server_hostname=host,
                timeout=self._connect_timeout,
            )

            ssl_object = stream.get_extra_info("ssl_object")
            self._channel_bindings = get_tls_server_end_point_bindings(ssl_object)

        self._connection = httpcore.AsyncHTTP11Connection(
            origin=origin,
            stream=stream,
        )
        return self._connection

    def _prepare_request(
        self,
        request: httpcore.Request,
    ) -> tuple[httpcore.Request, bool]:
        is_final = True
        if self._encrypt and isinstance(self._auth_provider, WSManEncryptionProvider):
            headers = {k: v for k, v in request.headers}

            if self._auth_provider.complete:
                assert isinstance(request.stream, collections.abc.Iterable)
                to_encrypt = b"".join(request.stream)
                content, content_type = self._auth_provider.wrap(
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

    async def _process_response(
        self,
        response: httpcore.Response,
    ) -> httpcore.Response:
        headers = {k: v for k, v in response.headers}
        content_type = headers.get(b"Content-Type", None)

        if (
            content_type
            and self._auth_provider.complete
            and isinstance(self._auth_provider, WSManEncryptionProvider)
            and (
                content_type.startswith(b"multipart/encrypted;")
                or content_type.startswith(b"multipart/x-multi-encrypted;")
            )
        ):
            to_decrypt = await response.aread()
            await response.aclose()

            data, content_type = self._auth_provider.unwrap(
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
