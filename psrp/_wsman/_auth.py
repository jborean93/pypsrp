# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import functools
import httpx
import logging
import re
import spnego
import spnego.channel_bindings
import typing

from httpcore import (
    AsyncByteStream,
    AsyncHTTPTransport,
)

from ._bytestreams import (
    PlainByteStream,
)

from ._encryption import (
    decrypt_wsman,
    encrypt_wsman,
)

from ._utils import (
    get_tls_server_end_point_hash,
    Headers,
    URL,
)

logger = logging.getLogger(__name__)


WWW_AUTH_PATTERN = re.compile(r'(CredSSP|Kerberos|Negotiate|NTLM)\s*([^,]*),?', re.I)


def _async_wrap(func, *args, **kwargs):
    """ Runs a sync function in the background. """
    loop = asyncio.get_running_loop()
    task = loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

    return task


class AsyncAuth:

    SUPPORTS_ENCRYPTION = False

    async def arequest(
            self,
            connection: AsyncHTTPTransport,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
            auths_header: str = 'WWW-Authenticate',
            authz_header: str = 'Authorization',
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        return await connection.arequest(method, url, headers=headers,
                                         stream=stream, ext=ext)

    def reset(self):
        pass


class AsyncNoAuth(AsyncAuth):
    pass


class AsyncNegotiateAuth(AsyncAuth):

    SUPPORTS_ENCRYPTION = True

    def __init__(
            self,
            credential: typing.Any = None,
            protocol: str = 'negotiate',
            encrypt: bool = True,
            service: str = 'HTTP',
            hostname_override: typing.Optional[str] = None,
            disable_cbt: bool = False,
            delegate: bool = False,
            credssp_allow_tlsv1: bool = False,
            credssp_require_kerberos: bool = False,
    ):
        valid_protocols = ['kerberos', 'negotiate', 'ntlm', 'credssp']
        if protocol not in valid_protocols:
            raise ValueError(f"{type(self).__name__} protocol only supports {', '.join(valid_protocols)}")

        self.protocol = protocol.lower()

        self._context = None
        self.__complete = False
        self._credential = credential
        self._encrypt = encrypt
        self._service = service
        self._hostname_override = hostname_override
        self._disable_cbt = disable_cbt
        self._delegate = delegate
        self._credssp_allow_tlsv1 = credssp_allow_tlsv1
        self._credssp_require_kerberos = credssp_require_kerberos

    @property
    def _complete(self) -> bool:
        # Some proxies don't reply with the
        return self.__complete or (self._context and self._context.complete)

    async def arequest(
            self,
            connection: AsyncHTTPTransport,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
            auths_header: str = 'WWW-Authenticate',
            authz_header: str = 'Authorization',
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        if not self._complete:
            response = await self.auth_flow(
                connection, method, url, headers=headers,
                stream=(None if self._encrypt else stream), ext=ext,
                auths_header=auths_header, authz_header=authz_header
            )

            # If we didn't encrypt then the response from the auth phase
            # contains our actual response. Also pass along any errors back.
            if not self._encrypt or response[0] != 200:
                return response

        headers, stream = await self._wrap_stream(headers, stream)
        status_code, headers, stream, ext = await connection.arequest(
            method, url, headers=headers.raw, stream=stream, ext=ext
        )
        headers, stream = await self._unwrap_stream(headers, stream)

        return status_code, headers.raw, stream, ext

    async def auth_flow(
            self,
            connection: AsyncHTTPTransport,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
            auths_header: str = 'WWW-Authenticate',
            authz_header: str = 'Authorization',
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        auth_header = {
            'negotiate': 'Negotiate',
            'ntlm': 'Negotiate',
            'kerberos': 'Kerberos',
            'credssp': 'CredSSP',
        }[self.protocol]

        # Get the TLS object for CBT if required - will be None when connecting over HTTP
        cbt = None
        ssl_object = None
        if hasattr(connection, 'socket'):
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
        send_headers, stream = await self._wrap_stream(headers, stream)
        out_token = await _async_wrap(self._context.step)
        while not self._context.complete or out_token is not None:
            send_headers[authz_header] = f'{auth_header} {base64.b64encode(out_token).decode()}'
            status_code, headers, stream, ext = await connection.arequest(
                method, url, headers=send_headers.raw, stream=stream, ext=ext
            )
            headers, stream = await self._unwrap_stream(headers, stream)

            auth_header = headers.get(auths_header, '')
            in_token = WWW_AUTH_PATTERN.search(auth_header)
            if in_token:
                in_token = base64.b64decode(in_token.group(2))

            # If there was no token received from the host then we just break the auth cycle.
            if not in_token:
                # Some proxies don't seem to return the mutual auth token which
                # break the _context.complete checker later on. Because mutual
                # auth doesn't matter for proxies we just override that check.
                self.__complete = True
                break

            out_token = await _async_wrap(self._context.step, in_token)

        return status_code, headers.raw, stream, ext

    def reset(self):
        self._context = None

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
            enc_data, content_type = encrypt_wsman(
                dec_data, temp_headers['Content-Type'],
                f'application/HTTP-{protocol}-session-encrypted',
                self._context)
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
        # self._connection.expires_at = _time() + self._keepalive_expiry

        temp_headers = httpx.Headers(headers)

        content_type = temp_headers.get('Content-Type', '')

        # A proxy will have these content types but cannot do the encryption so
        # we must also check for self._encrypt.
        if (
            self._encrypt and (
                content_type.startswith('multipart/encrypted;') or
                content_type.startswith('multipart/x-multi-encrypted;')
            )
        ):
            data, content_type = decrypt_wsman(data, content_type, self._context)
            temp_headers['Content-Length'] = str(len(data))
            temp_headers['Content-Type'] = content_type

        return temp_headers, PlainByteStream(bytes(data))


class AsyncBasicAuth(AsyncAuth):

    def __init__(
            self,
            username: str,
            password: str,
    ):
        credential = f'{username or ""}:{password or ""}'.encode('utf-8')
        self._token = f'Basic {base64.b64encode(credential).decode()}'
        self._complete = False

    async def arequest(
            self,
            connection: AsyncHTTPTransport,
            method: bytes,
            url: URL,
            headers: Headers = None,
            stream: AsyncByteStream = None,
            ext: typing.Dict = None,
            auths_header: str = 'WWW-Authenticate',
            authz_header: str = 'Authorization',
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        headers = httpx.Headers(headers)

        if not self._complete:
            headers[authz_header] = self._token
            self._complete = True

        return await connection.arequest(
            method, url, headers=headers.raw, stream=stream, ext=ext,
        )

    def reset(self):
        self._complete = False
