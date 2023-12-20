# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import ssl
import typing as t

import spnego
import spnego.channel_bindings
import spnego.tls
from spnego.channel_bindings import GssChannelBindings

BOUNDARY_PATTERN = re.compile("boundary=[" '|\\"](.*)[' '|\\"]')


class WSManAuthProvider:
    """WSMan Authentication Provider stub."""

    @property
    def complete(self) -> bool:
        """Whether more tokens need to be produced for the HTTP header."""
        raise NotImplementedError()  # pragma: nocover

    @property
    def http_auth_label(self) -> bytes:
        """The value for the HTTP Authorization header."""
        raise NotImplementedError()  # pragma: nocover

    def copy(self) -> WSManAuthProvider:
        return self

    async def step_async(
        self,
        in_token: bytes | None = None,
        channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None,
    ) -> bytes | None:
        """Async version of step."""
        return self.step(in_token=in_token, channel_bindings=channel_bindings)

    def step(
        self,
        in_token: bytes | None = None,
        channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None,
    ) -> bytes | None:
        """Performs an auth step to produce an auth token.

        Performs a step to produce an output token included in the HTTP
        Authorization header. This should continue to be called until the
        provider is complete and no more tokens are produced.

        Args:
            in_token: Input token to perform the step with.
            channel_bindings: Optional channel bindings to perform the step
                with.

        Returns:
            Optional[bytes]: The auth token to provide in the Authorization
            header. An explicit None value means there is no auth token and to
            not include any Authorization header in the request. An empty byte
            string indicates just the http_auth_label should be in the
            Authorization header.
        """
        raise NotImplementedError()  # pragma: nocover


class WSManEncryptionProvider:
    """WSMan Encryption Provider stub."""

    def wrap(
        self,
        data: bytes,
        content_type: str,
    ) -> tuple[bytes, bytes]:
        """Wraps the WSMan data.

        Wraps/encrypts the WSMan data provided.

        Args:
            data: The WSMan data to wrap.
            content_type: The Content-Type of the data to wrap.

        Returns:
            tuple[bytes, bytes]: The wrapped data and the new Content-Type that
            the wrapped data represents.
        """
        raise NotImplementedError()  # pragma: nocover

    def unwrap(
        self,
        data: bytes,
        content_type: str,
    ) -> tuple[bytes, bytes]:
        """Unwraps the WSMan data.

        Unwraps/decrypts the WSMan data provided.

        Args:
            data: The WSMan data to unwrap.
            content_type: The Content-Type of the wrapped data.

        Returns:
            tuple[bytes, bytes]: The unwrapped data and the Content-Type of the
            unwrapped data.
        """
        raise NotImplementedError()  # pragma: nocover


class WSManBasicAuth(WSManAuthProvider):
    """WSMan Basic Auth.

    Implementation for Basic auth over WSMan.

    Args:
        username: The username.
        password: The password.
    """

    def __init__(
        self,
        *,
        username: str,
        password: str,
    ) -> None:
        self._auth_token = f"{username}:{password}".encode("utf-8")

    @property
    def complete(self) -> bool:
        return False

    @property
    def http_auth_label(self) -> bytes:
        return b"Basic"

    def step(
        self,
        in_token: bytes | None = None,
        channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None,
    ) -> bytes | None:
        return self._auth_token


class WSManCertificateAuth(WSManAuthProvider):
    """WSMan Certificate Auth.

    Implementation for Certificate auth over WSMan. Certificate auth is special
    where no token is provided with the Authorization header except the URI
    value. The certificate details are provided in the ssl.SSLContext when
    the TLS channel was set up.
    """

    @property
    def complete(self) -> bool:
        return False

    @property
    def http_auth_label(self) -> bytes:
        return b"http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

    def step(
        self,
        in_token: bytes | None = None,
        channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None,
    ) -> bytes | None:
        return b""


class _WSManSpnegoAuth(WSManAuthProvider, WSManEncryptionProvider):
    def __init__(
        self,
        *,
        context: spnego.ContextProxy,
        enc_protocol: str,
    ) -> None:
        self._context = context
        self._encryption_type = f"application/HTTP-{enc_protocol}-session-encrypted"

    @property
    def complete(self) -> bool:
        return self._context.complete

    @property
    def _max_enc_block_size(self) -> int | None:
        return None

    async def step_async(
        self,
        in_token: bytes | None = None,
        channel_bindings: GssChannelBindings | None = None,
    ) -> bytes | None:
        # Step calls could block internally on some C functions. We run in a
        # separate thread to ensure it doesn't block any other tasks in the
        # loop.
        exec = concurrent.futures.ThreadPoolExecutor()
        return await asyncio.get_running_loop().run_in_executor(exec, self.step, in_token, channel_bindings)

    def step(
        self,
        in_token: bytes | None = None,
        channel_bindings: spnego.channel_bindings.GssChannelBindings | None = None,
    ) -> bytes | None:
        out_token = self._context.step(
            in_token=in_token,
            channel_bindings=channel_bindings,
        )

        return out_token or None

    def wrap(
        self,
        data: bytes,
        content_type: str,
    ) -> tuple[bytes, bytes]:
        boundary = "Encrypted Boundary"

        max_size = self._max_enc_block_size
        if max_size is None:
            max_size = len(data)
        chunks = [data[i : i + max_size] for i in range(0, len(data), max_size)]

        encrypted_chunks = []
        for chunk in chunks:
            enc_details = self._context.wrap_winrm(bytes(chunk))
            padding_length = enc_details.padding_length
            wrapped_data = (
                len(enc_details.header).to_bytes(length=4, byteorder="little", signed=False)
                + enc_details.header
                + enc_details.data
            )
            chunk_length = str(len(chunk) + padding_length)

            content = "\r\n".join(
                [
                    f"--{boundary}",
                    f"\tContent-Type: {self._encryption_type}",
                    f"\tOriginalContent: type={content_type};Length={chunk_length}",
                    f"--{boundary}",
                    "\tContent-Type: application/octet-stream",
                    "",
                ]
            )
            encrypted_chunks.append(content.encode() + wrapped_data)

        content_sub_type = "multipart/encrypted" if len(encrypted_chunks) == 1 else "multipart/x-multi-encrypted"
        content_type = f'{content_sub_type};protocol="{self._encryption_type}";boundary="{boundary}"'
        wrapped_data = b"".join(encrypted_chunks) + f"--{boundary}--\r\n".encode()

        return wrapped_data, content_type.encode()

    def unwrap(
        self,
        data: bytes,
        content_type: str,
    ) -> tuple[bytes, bytes]:
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

            header_length = int.from_bytes(wrapped_data[:4], byteorder="little", signed=False)
            b_header = wrapped_data[4 : 4 + header_length]
            b_enc_data = wrapped_data[4 + header_length :]
            unwrapped_data = self._context.unwrap_winrm(b_header, b_enc_data)
            actual_length = len(unwrapped_data)

            if actual_length != expected_length:
                raise ValueError(
                    f"The actual length from the server does not match the expected length, "
                    f"decryption failed, actual: {actual_length} != expected: {expected_length}"
                )
            content.append(unwrapped_data)

        return b"".join(content), content_type.encode()


class WSManNegotiateAuth(_WSManSpnegoAuth):
    """WSMan Negotiate Auth.

    Implementation for Negotiate auth over WSMan. This also has support for
    WSMan encryption using the authenticated context.

    Args:
        username: The username, if not set will attempt to use current user
            context if available.
        password: The password, if not set will attempt to use the current user
            context if available.
        hostname: The target hostname to authenticate with, this is used for
            service authentication and should match the target in the HTTP
            request.
        service: The target service name, defaults to http.
        delegate: Request a delegatable ticket, only works with Kerberos auth.
        protocol: The protocol to use, defaults to negotiate but can be set
            to 'kerberos', or 'ntlm'.
        context: Inner use only.
    """

    def __init__(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        hostname: str = "unspecified",
        service: str = "http",
        delegate: bool = False,
        protocol: str = "negotiate",
        context: spnego.ContextProxy | None = None,
    ) -> None:
        if not context:
            context_req = spnego.ContextReq.default
            if delegate:
                context_req |= spnego.ContextReq.delegate

            context = spnego.client(
                username=username,
                password=password,
                hostname=hostname,
                service=service,
                protocol=protocol,
                context_req=context_req,
            )

        if context.protocol == "kerberos":
            enc_protocol = "Kerberos"
            self._http_auth_label = b"Kerberos"
        else:
            enc_protocol = "SPNEGO"
            self._http_auth_label = b"Negotiate"

        super().__init__(context=context, enc_protocol=enc_protocol)

    @property
    def http_auth_label(self) -> bytes:
        return self._http_auth_label

    def copy(self) -> WSManNegotiateAuth:
        return WSManNegotiateAuth(context=self._context.new_context())


class WSManCredSSPAuth(_WSManSpnegoAuth):
    """WSMan CredSSP Auth.

    Implementation for CredSSP auth over WSMan. This also has support for
    WSMan encryption using the authenticated context.

    Args:
        username: The username, must be set for CredSSP.
        password: The password, must be set for CredSSP.
        hostname: The target hostname to authenticate with, this is used for
            service authentication and should match the target in the HTTP
            request.
        service: The target service name, defaults to http.
        min_protocol: The minimum CredSSP protocol version on the server that
            is accepted by the client. The default depends on the version of
            pyspnego that is installed.
        tls_context: Use the provided SSLContext object when building the
            CredSSP channel instead of the pyspnego defaults.
        negotiate_protocol: The protocol to use for the inner negotiate auth
            context, default to "negotiate" but can be set to "kerberos" or
            "ntlm".
        context: Inner use only.
    """

    def __init__(
        self,
        *,
        username: str,
        password: str,
        hostname: str = "unspecified",
        service: str = "http",
        min_protocol: int | None = None,
        tls_context: ssl.SSLContext | None = None,
        negotiate_protocol: str | None = None,
        context: spnego.ContextProxy | None = None,
    ) -> None:
        if not context:
            context_kwargs: dict[str, t.Any] = {}
            if min_protocol is not None:
                context_kwargs["credssp_min_protocol"] = min_protocol

            if negotiate_protocol:
                context_kwargs["credssp_negotiate_context"] = spnego.client(
                    username=username,
                    password=password,
                    hostname=hostname,
                    service=service,
                    protocol=negotiate_protocol,
                )

            if tls_context:
                context_kwargs["credssp_tls_context"] = spnego.tls.CredSSPTLSContext(tls_context)

            context = spnego.client(
                username=username,
                password=password,
                hostname=hostname,
                service=service,
                protocol="credssp",
                **context_kwargs,
            )

        super().__init__(context=context, enc_protocol="CredSSP")

    @property
    def http_auth_label(self) -> bytes:
        return b"CredSSP"

    @property
    def _max_enc_block_size(self) -> int | None:
        # CredSSP uses TLS which has a max block size of 16KiB
        return 16384

    def copy(self) -> WSManCredSSPAuth:
        return WSManCredSSPAuth(username="", password="", context=self._context.new_context())
