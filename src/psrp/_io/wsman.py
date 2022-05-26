# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import dataclasses
import functools
import ipaddress
import logging
import re
import ssl
import struct
import threading
import typing as t

import httpcore
import httpx
import spnego
import spnego.channel_bindings
import spnego.tls
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from psrp._compat import Literal
from psrp._exceptions import WSManHTTPError

log = logging.getLogger(__name__)

WWW_AUTH_PATTERN = re.compile(r"(CredSSP|Kerberos|Negotiate|NTLM)\s*([^,]*),?", re.I)

BOUNDARY_PATTERN = re.compile("boundary=[" '|\\"](.*)[' '|\\"]')


def decrypt_wsman(
    data: bytearray,
    content_type: str,
    context: spnego.ContextProxy,
) -> t.Tuple[bytes, str]:
    boundary_match = BOUNDARY_PATTERN.search(content_type)
    if not boundary_match:
        raise ValueError(f"Content type '{content_type}' did not match expected encrypted format")

    boundary = boundary_match.group(1)
    # Talking to Exchange endpoints gives a non-compliant boundary that has a space between the --boundary.
    # not ideal but we just need to handle it.
    parts = re.compile((r"--\s*%s\r\n" % re.escape(boundary)).encode()).split(data)
    parts = list(filter(None, parts))
    content_type = ""

    content = []
    for i in range(0, len(parts), 2):
        header = parts[i].strip()
        payload = parts[i + 1]

        content_type_and_length = header.split(b"OriginalContent: type=")[1].split(b";Length=")
        content_type = content_type_and_length[0].decode()
        expected_length = int(content_type_and_length[1])

        # remove the end MIME block if it exists
        payload = re.sub((r"--\s*%s--\r\n$" % boundary).encode(), b"", payload)

        wrapped_data = re.sub(r"\t?Content-Type: application/octet-stream\r\n".encode(), b"", payload)

        header_length = struct.unpack("<i", wrapped_data[:4])[0]
        b_header = wrapped_data[4 : 4 + header_length]
        b_enc_data = wrapped_data[4 + header_length :]
        unwrapped_data = context.unwrap_winrm(b_header, b_enc_data)
        actual_length = len(unwrapped_data)

        if actual_length != expected_length:
            raise ValueError(
                f"The actual length from the server does not match the expected length, "
                f"decryption failed, actual: {actual_length} != expected: {expected_length}"
            )
        content.append(unwrapped_data)

    return b"".join(content), content_type


def encrypt_wsman(
    data: bytearray,
    content_type: str,
    encryption_type: str,
    context: spnego.ContextProxy,
) -> t.Tuple[bytes, str]:
    boundary = "Encrypted Boundary"

    # If using CredSSP we must encrypt in 16KiB chunks.
    max_size = 16384 if "CredSSP" in encryption_type else len(data)
    chunks = [data[i : i + max_size] for i in range(0, len(data), max_size)]

    encrypted_chunks = []
    for chunk in chunks:
        enc_details = context.wrap_winrm(bytes(chunk))
        padding_length = enc_details.padding_length
        wrapped_data = struct.pack("<i", len(enc_details.header)) + enc_details.header + enc_details.data
        chunk_length = str(len(chunk) + padding_length)

        content = "\r\n".join(
            [
                f"--{boundary}",
                f"\tContent-Type: {encryption_type}",
                f"\tOriginalContent: type={content_type};Length={chunk_length}",
                f"--{boundary}",
                "\tContent-Type: application/octet-stream",
                "",
            ]
        )
        encrypted_chunks.append(content.encode() + wrapped_data)

    content_sub_type = "multipart/encrypted" if len(encrypted_chunks) == 1 else "multipart/x-multi-encrypted"
    content_type = f'{content_sub_type};protocol="{encryption_type}";boundary="{boundary}"'
    wrapped_data = b"".join(encrypted_chunks) + f"--{boundary}--\r\n".encode()

    return wrapped_data, content_type


def get_tls_server_end_point_hash(
    certificate_der: bytes,
) -> bytes:
    """Get Channel Binding hash.

    Get the channel binding tls-server-end-point hash value from the
    certificate passed in.

    Args:
        certificate_der: The X509 DER encoded certificate.

    Returns:
        bytes: The hash value to use for the channel binding token.
    """
    backend = default_backend()

    cert = x509.load_der_x509_certificate(certificate_der, backend)
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_algorithm = None

    # If the cert signature algorithm is unknown, md5, or sha1 then use sha256 otherwise use the signature
    # algorithm of the cert itself.
    if not hash_algorithm or hash_algorithm.name in ["md5", "sha1"]:
        digest = hashes.Hash(hashes.SHA256(), backend)
    else:
        digest = hashes.Hash(hash_algorithm, backend)

    digest.update(certificate_der)
    certificate_hash = digest.finalize()

    return certificate_hash


@dataclasses.dataclass(frozen=True)
class WSManConnectionData:
    """WSMan Connection Details.

    This stores all the WSMan connection specific details that makes it simpler
    to document/validate/pass the WSMan connection info in this library.

    See :class:`psrp._io.wsman.WSManInfo <WSManInfo>` for more information on
    all these settings.

    Attributes:
        connection_uri: The connection URI that will be used as the target.
        message_encryption: Whether message encryption will be used on the
            connection.
        tls: The TLS context object used for TLS connections.
    """

    connection_uri: str = dataclasses.field(init=False)
    message_encryption: bool = dataclasses.field(init=False)
    tls: ssl.SSLContext = dataclasses.field(init=False)

    server: dataclasses.InitVar[str]
    scheme: dataclasses.InitVar[t.Optional[Literal["http", "https"]]] = None
    port: dataclasses.InitVar[int] = -1  # Default is 5985 with http and 5986 with https
    path: dataclasses.InitVar[str] = "wsman"
    encryption: Literal["always", "auto", "never"] = "auto"
    ssl_context: t.Optional[ssl.SSLContext] = None
    verify: dataclasses.InitVar[t.Union[str, bool]] = True

    connection_timeout: float = 30.0
    read_timeout: float = 30.0

    # Authentication
    auth: Literal["basic", "certificate", "credssp", "kerberos", "negotiate", "ntlm"] = "negotiate"
    username: t.Optional[str] = None
    password: t.Optional[str] = dataclasses.field(repr=False, default=None)
    # Cert auth
    certificate_pem: t.Optional[str] = None
    certificate_key_pem: t.Optional[str] = None
    certificate_key_password: t.Optional[str] = dataclasses.field(repr=False, default=None)
    # SPNEGO
    negotiate_service: str = "http"
    negotiate_hostname: t.Optional[str] = None
    negotiate_delegate: bool = False
    negotiate_send_cbt: bool = True
    # CredSSP
    credssp_ssl_context: t.Optional[ssl.SSLContext] = None
    credssp_auth_mechanism: Literal["kerberos", "negotiate", "ntlm"] = "negotiate"
    credssp_minimum_version: t.Optional[int] = None

    # FUTURE: reconnection settings
    # FUTURE: Add proxy options

    def __post_init__(
        self,
        server: str,
        scheme: str,
        port: int,
        path: str,
        verify: t.Union[str, bool],
    ) -> None:
        raw_url = httpx.URL(server)

        if raw_url.is_absolute_url:
            object.__setattr__(self, "connection_uri", server)
        else:

            try:
                address = ipaddress.IPv6Address(server)
            except ipaddress.AddressValueError:
                pass
            else:
                server = "[%s]" % address.compressed

            if not scheme:
                scheme = "http" if port in [-1, 80, 5985] else "https"

            if port == -1:
                port = 5985 if scheme == "http" else 5986

            object.__setattr__(self, "connection_uri", f"{scheme}://{server}:{port}/{path}")

        object.__setattr__(self, "tls", self.ssl_context or httpx.create_ssl_context(verify=verify))
        object.__setattr__(self, "auth", self.auth.lower())
        if self.auth not in ["basic", "certificate", "credssp", "kerberos", "negotiate", "ntlm"]:
            raise ValueError(
                f"The auth value '{self.auth}' must be basic, certificate, credssp, kerberos, negotiate, or ntlm"
            )

        if self.auth == "certificate":
            if scheme != "https":
                raise ValueError("scheme='https' must be used with auth='certificate'")

            if not self.certificate_pem:
                raise ValueError("certificate_pem must be set when using auth='certificate'")

            self.tls.load_cert_chain(
                certfile=self.certificate_pem,
                keyfile=self.certificate_key_pem,
                password=self.certificate_key_password,
            )

        encryption = self.encryption.lower()
        if encryption == "always":
            if self.auth == "basic" or self.auth == "certificate":
                raise ValueError("Cannot use auth encryption with auth='basic' or auth='certificate'")

            object.__setattr__(self, "message_encryption", True)
        elif encryption == "auto":
            encrypt = scheme == "http"
            if encrypt and self.auth == "basic":
                raise ValueError("Must set encryption='never' when using auth='basic' over HTTP")

            object.__setattr__(self, "message_encryption", encrypt)
        elif encryption == "never":
            object.__setattr__(self, "message_encryption", False)
        else:
            raise ValueError(f"The encryption value '{encryption}' must be auto, always, or never")

        object.__setattr__(self, "credssp_auth_mechanism", self.credssp_auth_mechanism.lower())
        if self.credssp_auth_mechanism not in ["kerberos", "negotiate", "ntlm"]:
            raise ValueError(
                f"The credssp_auth_mechanism value '{self.credssp_auth_mechanism}' must be kerberos, negotiate, or ntlm"
            )

    def _get_default_headers(self) -> t.Dict[str, str]:
        """Get the default headers used with every WSMan request of this connection."""
        # Default for 'Accept-Encoding' is 'gzip, default' which normally doesn't matter on vanilla WinRM but for
        # Exchange endpoints hosted on IIS they actually compress it with 1 of the 2 algorithms. By explicitly setting
        # identity we are telling the server not to transform (compress) the data using the HTTP methods which we don't
        # support. https://tools.ietf.org/html/rfc7231#section-5.3.4
        headers: t.Dict[str, str] = {
            "Accept-Encoding": "identity",
            "User-Agent": "Python PSRP Client",
        }

        if self.auth == "certificate":
            headers["Authorization"] = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

        return headers


class AsyncResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: t.AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> t.AsyncIterator[bytes]:
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        if hasattr(self._stream, "aclose"):
            await self._stream.aclose()  # type: ignore[attr-defined] # hasattr check above


class SyncResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: t.Iterable[bytes]) -> None:
        self._stream = stream

    def __iter__(self) -> t.Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        if hasattr(self._stream, "close"):
            self._stream.close()  # type: ignore[attr-defined] # hasattr check above


class AsyncResponseData(httpx.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def __aiter__(self) -> t.AsyncIterator[bytes]:
        yield self._data

    async def aclose(self) -> None:
        pass


class SyncResponseData(httpx.SyncByteStream):
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __iter__(self) -> t.Iterator[bytes]:
        yield self._data

    def close(self) -> None:
        pass


class AsyncWSManTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        url: httpx.URL,
        connection_info: WSManConnectionData,
    ) -> None:
        self._connection = httpcore.AsyncHTTPConnection(
            httpcore.Origin(url.raw_scheme, url.raw_host, url.port or 5985),
            ssl_context=connection_info.tls,
        )

        self._protocol = connection_info.auth
        self._auth_header = {
            "negotiate": "Negotiate",
            "ntlm": "Negotiate",
            "kerberos": "Kerberos",
            "credssp": "CredSSP",
        }[self._protocol]
        self._context: t.Optional[spnego.ContextProxy] = None
        self._username = connection_info.username
        self._password = connection_info.password
        self._encrypt = connection_info.message_encryption
        self._service = connection_info.negotiate_service
        self._hostname_override = connection_info.negotiate_hostname or url.host
        self._disable_cbt = not connection_info.negotiate_send_cbt
        self._channel_bindings: t.Optional[spnego.channel_bindings.GssChannelBindings] = None
        self._delegate = connection_info.negotiate_delegate
        self._credssp_ssl_context = connection_info.credssp_ssl_context
        self._credssp_auth_mechanism = connection_info.credssp_auth_mechanism
        self._credssp_minimum_version = connection_info.credssp_minimum_version

    async def __aenter__(self) -> "AsyncWSManTransport":
        await self._connection.__aenter__()
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self._connection.__aexit__()  # pragma: no cover # Seems like httpx doesn't call this

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        if not self._context:
            auth_resp = await self._handle_async_auth(request)

            # If we didn't encrypt then the response from the auth phase contains our actual response. Also pass along
            # any errors back. Otherwise we need to drain the socket and read the dummy data to ensure the connection
            # is ready for the next request
            if not self._encrypt or auth_resp.status_code != 200:
                return auth_resp

            else:
                await auth_resp.aread()
                await auth_resp.aclose()

        req = self._wrap(request)

        resp = await self._connection.handle_async_request(req)

        return await self._unwrap(resp)

    async def _handle_async_auth(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        headers = request.headers.copy()
        stream: t.Union[bytes, httpx.AsyncByteStream, httpx.SyncByteStream] = request.stream
        ext = request.extensions.copy()
        if "trace" in ext:
            trace_func = functools.partial(self.trace, trace=ext["trace"])
            ext["trace"] = trace_func
        else:
            ext["trace"] = self.trace

        if self._encrypt:
            headers["Content-Length"] = "0"
            stream = b""

        out_token: t.Optional[bytes] = None
        while True:
            if out_token:
                encoded_token = base64.b64encode(out_token).decode()
                headers["Authorization"] = f"{self._auth_header} {encoded_token}"
                out_token = None

            req = httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=headers.raw,
                content=stream,
                extensions=ext,
            )

            resp = await self._connection.handle_async_request(req)
            response = await self._unwrap(resp)

            if self._context:
                auths = response.headers.get("WWW-Authenticate", "")
                auth_header = WWW_AUTH_PATTERN.search(auths)
                in_token = base64.b64decode(auth_header.group(2)) if auth_header else None
                if in_token:
                    out_token = self._context.step(in_token)

            if out_token:
                await response.aread()
                await response.aclose()

            else:
                return response

    async def trace(
        self,
        event_name: str,
        info: t.Dict[str, t.Any],
        trace: t.Optional[t.Callable[[str, t.Dict[str, t.Any]], t.Awaitable[None]]] = None,
    ) -> None:
        normalized_name = event_name.lower().replace(".", "_")
        event_handler = getattr(self, f"_{normalized_name}", None)
        if event_handler:
            await event_handler(info)

        if trace:
            await trace(event_name, info)

    async def _http11_send_request_headers_started(self, info: t.Dict[str, t.Any]) -> None:
        # The first request needs the context to be set up and the first token added as a header
        if self._context:
            return

        auth_kwargs: t.Dict[str, t.Any] = {
            "username": self._username,
            "password": self._password,
            "hostname": self._hostname_override,
            "service": self._service,
            "context_req": spnego.ContextReq.default,
            "options": spnego.NegotiateOptions.none,
        }

        if self._protocol == "credssp":
            if self._credssp_ssl_context:
                auth_kwargs["credssp_tls_context"] = spnego.tls.CredSSPTLSContext(self._credssp_ssl_context)

            if self._credssp_auth_mechanism != "negotiate":
                sub_auth = spnego.client(protocol=self._credssp_auth_mechanism, **auth_kwargs)
                auth_kwargs["credssp_negotiate_context"] = sub_auth

            if self._credssp_minimum_version is not None:
                auth_kwargs["credssp_min_protocol"] = self._credssp_minimum_version

        elif self._delegate:
            auth_kwargs["context_req"] |= spnego.ContextReq.delegate

        if self._encrypt:
            auth_kwargs["options"] |= spnego.NegotiateOptions.wrapping_winrm

        self._context = spnego.client(
            channel_bindings=self._channel_bindings,
            protocol=self._protocol,
            **auth_kwargs,
        )
        token = self._context.step() or b""
        encoded_token = base64.b64encode(token).decode()
        auth_value = f"{self._auth_header} {encoded_token}"
        info["request"].headers.append((b"Authorization", auth_value.encode()))

    async def _connection_start_tls_complete(self, info: t.Dict[str, t.Any]) -> None:
        # Once the TLS handshake is done we can immediately get the TLS channel bindings used later when creating the
        # auth context (as the headers have started).
        ssl_object = info["return_value"].get_extra_info("ssl_object")
        cert = ssl_object.getpeercert(True)
        cert_hash = get_tls_server_end_point_hash(cert)
        self._channel_bindings = spnego.channel_bindings.GssChannelBindings(
            application_data=b"tls-server-end-point:" + cert_hash
        )

    def _wrap(
        self,
        request: httpx.Request,
    ) -> httpcore.Request:
        if self._encrypt and self._context and self._context.complete:
            protocol = {
                "kerberos": "Kerberos",
                "credssp": "CredSSP",
            }.get(self._protocol, "SPNEGO")

            headers = request.headers

            data, content_type = encrypt_wsman(
                bytearray(request.content),
                headers["Content-Type"],
                f"application/HTTP-{protocol}-session-encrypted",
                self._context,
            )

            headers["Content-Type"] = content_type
            headers["Content-Length"] = str(len(data))

            return httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=headers.raw,
                content=data,
                extensions=request.extensions,
            )

        else:
            return httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )

    async def _unwrap(
        self,
        response: httpcore.Response,
    ) -> httpx.Response:
        headers = httpx.Headers(response.headers)
        content_type = headers.get("Content-Type", "")

        # A proxy will have these content types but cannot do the encryption so we must also check for self._encrypt.
        if (
            self._encrypt
            and self._context
            and self._context.complete
            and (
                content_type.startswith("multipart/encrypted;")
                or content_type.startswith("multipart/x-multi-encrypted;")
            )
        ):
            data = await response.aread()
            await response.aclose()

            data, content_type = decrypt_wsman(bytearray(data), content_type, self._context)
            headers["Content-Length"] = str(len(data))
            headers["Content-Type"] = content_type

            return httpx.Response(
                status_code=response.status,
                headers=headers,
                stream=AsyncResponseData(data),
                extensions=response.extensions,
            )

        else:
            return httpx.Response(
                status_code=response.status,
                headers=headers,
                stream=AsyncResponseStream(response.stream),  # type: ignore[arg-type] # Here it will be async
                extensions=response.extensions,
            )


class SyncWSManTransport(httpx.BaseTransport):
    def __init__(
        self,
        url: httpx.URL,
        connection_info: WSManConnectionData,
    ) -> None:
        self._connection = httpcore.HTTPConnection(
            httpcore.Origin(url.raw_scheme, url.raw_host, url.port or 5985),
            ssl_context=connection_info.tls,
        )

        self._protocol = connection_info.auth
        self._auth_header = {
            "negotiate": "Negotiate",
            "ntlm": "Negotiate",
            "kerberos": "Kerberos",
            "credssp": "CredSSP",
        }[self._protocol]
        self._context: t.Optional[spnego.ContextProxy] = None
        self._username = connection_info.username
        self._password = connection_info.password
        self._encrypt = connection_info.message_encryption
        self._service = connection_info.negotiate_service
        self._hostname_override = connection_info.negotiate_hostname or url.host
        self._disable_cbt = not connection_info.negotiate_send_cbt
        self._channel_bindings: t.Optional[spnego.channel_bindings.GssChannelBindings] = None
        self._delegate = connection_info.negotiate_delegate
        self._credssp_ssl_context = connection_info.credssp_ssl_context
        self._credssp_auth_mechanism = connection_info.credssp_auth_mechanism
        self._credssp_minimum_version = connection_info.credssp_minimum_version

    def __enter__(self) -> "SyncWSManTransport":
        self._connection.__enter__()
        return self

    def __exit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        self._connection.__exit__()  # pragma: no cover # Seems like httpx doesn't call this

    def handle_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        if not self._context:
            auth_resp = self._handle_sync_auth(request)

            # If we didn't encrypt then the response from the auth phase contains our actual response. Also pass along
            # any errors back. Otherwise we need to drain the socket and read the dummy data to ensure the connection
            # is ready for the next request
            if not self._encrypt or auth_resp.status_code != 200:
                return auth_resp

            else:
                auth_resp.read()
                auth_resp.close()

        req = self._wrap(request)

        resp = self._connection.handle_request(req)

        return self._unwrap(resp)

    def _handle_sync_auth(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        headers = request.headers.copy()
        stream: t.Union[bytes, httpx.AsyncByteStream, httpx.SyncByteStream] = request.stream
        ext = request.extensions.copy()
        if "trace" in ext:
            trace_func = functools.partial(self.trace, trace=ext["trace"])
            ext["trace"] = trace_func
        else:
            ext["trace"] = self.trace

        if self._encrypt:
            headers["Content-Length"] = "0"
            stream = b""

        out_token: t.Optional[bytes] = None
        while True:
            if out_token:
                encoded_token = base64.b64encode(out_token).decode()
                headers["Authorization"] = f"{self._auth_header} {encoded_token}"
                out_token = None

            req = httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=headers.raw,
                content=stream,
                extensions=ext,
            )

            resp = self._connection.handle_request(req)
            response = self._unwrap(resp)

            if self._context:
                auths = response.headers.get("WWW-Authenticate", "")
                auth_header = WWW_AUTH_PATTERN.search(auths)
                in_token = base64.b64decode(auth_header.group(2)) if auth_header else None
                if in_token:
                    out_token = self._context.step(in_token)

            if out_token:
                response.read()
                response.close()

            else:
                return response

    def trace(
        self,
        event_name: str,
        info: t.Dict[str, t.Any],
        trace: t.Optional[t.Callable[[str, t.Dict[str, t.Any]], None]] = None,
    ) -> None:
        normalized_name = event_name.lower().replace(".", "_")
        event_handler = getattr(self, f"_{normalized_name}", None)
        if event_handler:
            event_handler(info)

        if trace:
            trace(event_name, info)

    def _http11_send_request_headers_started(self, info: t.Dict[str, t.Any]) -> None:
        # The first request needs the context to be set up and the first token added as a header
        if self._context:
            return

        auth_kwargs: t.Dict[str, t.Any] = {
            "username": self._username,
            "password": self._password,
            "hostname": self._hostname_override,
            "service": self._service,
            "context_req": spnego.ContextReq.default,
            "options": spnego.NegotiateOptions.none,
        }

        if self._protocol == "credssp":
            if self._credssp_ssl_context:
                auth_kwargs["credssp_tls_context"] = spnego.tls.CredSSPTLSContext(self._credssp_ssl_context)

            if self._credssp_auth_mechanism != "negotiate":
                sub_auth = spnego.client(protocol=self._credssp_auth_mechanism, **auth_kwargs)
                auth_kwargs["credssp_negotiate_context"] = sub_auth

            if self._credssp_minimum_version is not None:
                auth_kwargs["credssp_min_protocol"] = self._credssp_minimum_version

        elif self._delegate:
            auth_kwargs["context_req"] |= spnego.ContextReq.delegate

        if self._encrypt:
            auth_kwargs["options"] |= spnego.NegotiateOptions.wrapping_winrm

        self._context = spnego.client(
            channel_bindings=self._channel_bindings,
            protocol=self._protocol,
            **auth_kwargs,
        )
        token = self._context.step() or b""
        encoded_token = base64.b64encode(token).decode()
        auth_value = f"{self._auth_header} {encoded_token}"
        info["request"].headers.append((b"Authorization", auth_value.encode()))

    def _connection_start_tls_complete(self, info: t.Dict[str, t.Any]) -> None:
        # Once the TLS handshake is done we can immediately get the TLS channel bindings used later when creating the
        # auth context (as the headers have started).
        ssl_object = info["return_value"].get_extra_info("ssl_object")
        cert = ssl_object.getpeercert(True)
        cert_hash = get_tls_server_end_point_hash(cert)
        self._channel_bindings = spnego.channel_bindings.GssChannelBindings(
            application_data=b"tls-server-end-point:" + cert_hash
        )

    def _wrap(
        self,
        request: httpx.Request,
    ) -> httpcore.Request:
        if self._encrypt and self._context and self._context.complete:
            protocol = {
                "kerberos": "Kerberos",
                "credssp": "CredSSP",
            }.get(self._protocol, "SPNEGO")

            headers = request.headers

            data, content_type = encrypt_wsman(
                bytearray(request.content),
                headers["Content-Type"],
                f"application/HTTP-{protocol}-session-encrypted",
                self._context,
            )

            headers["Content-Type"] = content_type
            headers["Content-Length"] = str(len(data))

            return httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=headers.raw,
                content=data,
                extensions=request.extensions,
            )

        else:
            return httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )

    def _unwrap(
        self,
        response: httpcore.Response,
    ) -> httpx.Response:
        headers = httpx.Headers(response.headers)
        content_type = headers.get("Content-Type", "")

        # A proxy will have these content types but cannot do the encryption so we must also check for self._encrypt.
        if (
            self._encrypt
            and self._context
            and self._context.complete
            and (
                content_type.startswith("multipart/encrypted;")
                or content_type.startswith("multipart/x-multi-encrypted;")
            )
        ):
            data = response.read()
            response.close()

            data, content_type = decrypt_wsman(bytearray(data), content_type, self._context)
            headers["Content-Length"] = str(len(data))
            headers["Content-Type"] = content_type

            return httpx.Response(
                status_code=response.status,
                headers=headers,
                stream=SyncResponseData(data),
                extensions=response.extensions,
            )

        else:
            return httpx.Response(
                status_code=response.status,
                headers=headers,
                stream=SyncResponseStream(response.stream),  # type: ignore[arg-type] # Here it will be async
                extensions=response.extensions,
            )


class AsyncWSManHTTP:
    def __init__(
        self,
        connection_info: WSManConnectionData,
    ) -> None:
        self.connection_uri = httpx.URL(connection_info.connection_uri)

        transport: t.Optional[httpx.AsyncBaseTransport] = None
        auth_handler: t.Optional[httpx.Auth] = None

        if connection_info.auth == "basic":
            auth_handler = httpx.BasicAuth(connection_info.username or "", connection_info.password or "")

        elif connection_info.auth in ["credssp", "kerberos", "negotiate", "ntlm"]:
            transport = AsyncWSManTransport(self.connection_uri, connection_info)

        self._http = httpx.AsyncClient(
            headers=connection_info._get_default_headers(),
            timeout=httpx.Timeout(
                max(connection_info.connection_timeout, connection_info.read_timeout),
                connect=connection_info.connection_timeout,
                read=connection_info.read_timeout,
            ),
            transport=transport,
            auth=auth_handler,
            verify=connection_info.tls,
        )
        self._conn_lock = asyncio.Lock()

    async def __aenter__(self) -> "AsyncWSManHTTP":
        await self.open()
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self.close()

    async def post(
        self,
        data: bytes,
        data_sent: t.Optional[asyncio.Event] = None,
    ) -> bytes:
        """POST WSMan data to the endpoint.

        The WSMan envelope is sent as a HTTP POST request to the endpoint
        specified. This method should deal with the encryption required for a
        request if it is necessary.

        Args:
            data: The WSMan envelope to send to the endpoint.
            data_sent: An event that is set once the client has sent the body.

        Returns:
            bytes: The WSMan response.
        """
        ext: t.Optional[t.Dict[str, t.Any]] = None
        if data_sent:

            async def trace(event_name: str, info: t.Dict[str, t.Any]) -> None:
                if event_name == "http11.send_request_body.complete" and data_sent:
                    data_sent.set()

            ext = {"trace": trace}

        async with self._conn_lock:
            response = await self._http.post(
                self.connection_uri,
                content=data,
                headers={
                    "Content-Type": "application/soap+xml;charset=UTF-8",
                },
                extensions=ext,
            )

        content = await response.aread()

        # A WSManFault has more information that the WSMan state machine can
        # handle with better context so we ignore those.
        if response.status_code != 200 and (not content or b"wsmanfault" not in content):
            try:
                response.raise_for_status()
            except httpx.HTTPError as e:
                raise WSManHTTPError(str(e), response.status_code) from e

        return content or b""

    async def open(self) -> None:
        """Opens the WSMan connection.

        Opens the WSMan connection and sets up the connection for sending any
        WSMan envelopes.
        """
        await self._http.__aenter__()

    async def close(self) -> None:
        """Closes the WSMan connection.

        Closes the WSMan connection and any sockets/connections that are in use.
        """
        await self._http.aclose()


class SyncWSManHTTP:
    def __init__(
        self,
        connection_info: WSManConnectionData,
    ) -> None:
        self.connection_uri = httpx.URL(connection_info.connection_uri)

        transport: t.Optional[httpx.BaseTransport] = None
        auth_handler: t.Optional[httpx.Auth] = None

        if connection_info.auth == "basic":
            auth_handler = httpx.BasicAuth(connection_info.username or "", connection_info.password or "")

        elif connection_info.auth in ["credssp", "kerberos", "negotiate", "ntlm"]:
            transport = SyncWSManTransport(self.connection_uri, connection_info)

        self._http = httpx.Client(
            headers=connection_info._get_default_headers(),
            timeout=httpx.Timeout(
                max(connection_info.connection_timeout, connection_info.read_timeout),
                connect=connection_info.connection_timeout,
                read=connection_info.read_timeout,
            ),
            transport=transport,
            auth=auth_handler,
            verify=connection_info.tls,
        )
        self._conn_lock = threading.Lock()

    def __enter__(self) -> "SyncWSManHTTP":
        self.open()
        return self

    def __exit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        self.close()

    def post(
        self,
        data: bytes,
        data_sent: t.Optional[threading.Event] = None,
    ) -> bytes:
        """POST WSMan data to the endpoint.

        The WSMan envelope is sent as a HTTP POST request to the endpoint
        specified. This method should deal with the encryption required for a
        request if it is necessary.

        Args:
            data: The WSMan envelope to send to the endpoint.
            data_sent: An event that is set once the client has sent the body.

        Returns:
            bytes: The WSMan response.
        """
        ext: t.Optional[t.Dict[str, t.Any]] = None
        if data_sent:

            def trace(event_name: str, info: t.Dict[str, t.Any]) -> None:
                if event_name == "http11.send_request_body.complete" and data_sent:
                    data_sent.set()

            ext = {"trace": trace}

        with self._conn_lock:
            response = self._http.post(
                self.connection_uri,
                content=data,
                headers={
                    "Content-Type": "application/soap+xml;charset=UTF-8",
                },
                extensions=ext,
            )

        content = response.read()

        # A WSManFault has more information that the WSMan state machine can
        # handle with better context so we ignore those.
        if response.status_code != 200 and (not content or b"wsmanfault" not in content):
            try:
                response.raise_for_status()
            except httpx.HTTPError as e:
                raise WSManHTTPError(str(e), response.status_code) from e

        return content or b""

    def open(self) -> None:
        """Opens the WSMan connection.

        Opens the WSMan connection and sets up the connection for sending any
        WSMan envelopes.
        """
        self._http.__enter__()

    def close(self) -> None:
        """Closes the WSMan connection.

        Closes the WSMan connection and any sockets/connections that are in use.
        """
        self._http.close()
