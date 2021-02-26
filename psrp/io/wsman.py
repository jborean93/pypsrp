# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import abc

import httpcore
import httpx
import re
import struct
import typing

from urllib.parse import urlparse

from .._wsman._async import (
    AsyncWSManTransport,
)


class WSManConnectionBase(metaclass=abc.ABCMeta):
    """The WSManConnection contract.

    This is the WSManConnection contract that defines what is required for a WSMan IO class to be used by this library.
    """

    async def __aenter__(self):
        """ Implements 'async with' for the WSMan connection. """
        await self.open()
        return self

    def __enter__(self):
        """ Implements 'with' for the WSMan connection. """
        self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """ Implements the closing method for 'async with' for the WSMan connection. """
        await self.close()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ Implements the closing method for 'with' for the WSMan connection. """
        self.close()

    @abc.abstractmethod
    def send(
            self,
            data: bytes,
    ) -> bytes:
        """Send WSMan data to the endpoint.

        The WSMan envelope is sent as a HTTP POST request to the endpoint specified. This method should deal with the
        encryption required for a request if it is necessary.

        Args:
            data: The WSMan envelope to send to the endpoint.

        Returns:
            bytes: The WSMan response.
        """
        pass

    @abc.abstractmethod
    def open(self):
        """Opens the WSMan connection.

        Opens the WSMan connection and sets up the connection for sending any WSMan envelopes.
        """
        pass

    @abc.abstractmethod
    def close(self):
        """Closes the WSMan connection.

        Closes the WSMan connection and any sockets/connections that are in use.
        """
        pass


class AsyncWSManConnection(WSManConnectionBase):

    def __init__(
            self,
            connection_uri: str,
            encryption: str = 'auto',
            verify: typing.Union[str, bool] = True,
            connection_timeout: int = 30,
            read_timeout: int = 30,
            # TODO reconnection and proxy settings
            proxy: typing.Optional[str] = None,

            auth: str = 'negotiate',
            username: typing.Optional[str] = None,
            password: typing.Optional[str] = None,

            # Cert auth
            certificate_pem: typing.Optional[str] = None,
            certificate_key_pem: typing.Optional[str] = None,
            certificate_password: typing.Optional[str] = None,

            # SPNEGO
            negotiate_service: str = 'HTTP',
            negotiate_hostname: typing.Optional[str] = None,
            negotiate_delegate: bool = False,
            send_cbt: bool = True,

            # CredSSP
            credssp_allow_tlsv1: bool = False,
            credssp_require_kerberos: bool = False,
    ):
        self.connection_uri = urlparse(connection_uri)
        self.username = username or ''
        self.auth = auth

        if encryption not in ["auto", "always", "never"]:
            raise ValueError("The encryption value '%s' must be auto, always, or never" % encryption)

        self.encrypt = {
            'auto': self.connection_uri.scheme == 'http',
            'always': True,
            'never': False,
        }[encryption]

        # Default for 'Accept-Encoding' is 'gzip, default' which normally doesn't matter on vanilla WinRM but for
        # Exchange endpoints hosted on IIS they actually compress it with 1 of the 2 algorithms. By explicitly setting
        # identity we are telling the server not to transform (compress) the data using the HTTP methods which we don't
        # support. https://tools.ietf.org/html/rfc7231#section-5.3.4
        headers = {
            'Accept-Encoding': 'identity',
            'User-Agent': 'Python PSRP Client',
        }

        client_kwargs = {}
        ssl_context = httpx.create_ssl_context(verify=verify)
        keepalive_expiry = 5.0

        transport = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            max_keepalive_connections=1,
            keepalive_expiry=keepalive_expiry,
        )

        supported_auths = ['basic', 'certificate', 'negotiate', 'kerberos', 'ntlm', 'credssp']
        if auth not in supported_auths:
            raise ValueError("The specified auth '%s' is not supported, please select one of '%s'"
                             % (auth, ", ".join(supported_auths)))

        elif auth == 'basic':
            client_kwargs['auth'] = (username, password)

        elif auth == 'certificate':
            # TODO: Test password (3-tuple).
            headers['Authorization'] = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual'
            client_kwargs['cert'] = (certificate_pem, certificate_key_pem, certificate_password)

        else:
            wsman_auth_kwargs = {
                'service': negotiate_service,
                'hostname_override': negotiate_hostname,
                'disable_cbt': not send_cbt,
                'delegate': negotiate_delegate,
                'credssp_allow_tlsv1': credssp_allow_tlsv1,
                'credssp_require_kerberos': credssp_require_kerberos,
            }
            transport = AsyncWSManTransport(
                ssl_context=ssl_context,
                keepalive_expiry=keepalive_expiry,
                username=username,
                password=password,
                protocol=auth,
                encrypt=self.encrypt,
                **wsman_auth_kwargs,
            )

        # TODO: Proxy/SOCKS
        # TODO: Reconnection
        timeout = httpx.Timeout(max(connection_timeout, read_timeout), connect=connection_timeout, read=read_timeout)
        self._http = httpx.AsyncClient(headers=headers, timeout=timeout, transport=transport, proxies={'http': proxy})

    async def send(
            self,
            data: bytes,
    ) -> bytes:
        a = ''
        response = await self._http.post(self.connection_uri.geturl(), content=data, headers={
            'Content-Type': 'application/soap+xml;charset=UTF-8',
        })

        content = await response.aread()
        await response.aclose()

        if response.status_code != 200 and not content:
            response.raise_for_status()

        return content

    async def open(self):
        await self._http.__aenter__()

    async def close(self):
        await self._http.aclose()


class WSManConnection(WSManConnectionBase):

    def send(
            self,
            data: bytes,
    ):
        pass

    def open(self):
        self._http.__enter__()
        if self.encrypt:
            self.send(b'')

    def close(self):
        pass


def _decrypt_wsman(
        data: bytes,
        content_type: str,
        context,
) -> bytes:
    boundary = re.search('boundary=[''|\\"](.*)[''|\\"]', content_type).group(1)
    # Talking to Exchange endpoints gives a non-compliant boundary that has a space between the --boundary.
    # not ideal but we just need to handle it.
    parts = re.compile((r"--\s*%s\r\n" % re.escape(boundary)).encode()).split(data)
    parts = list(filter(None, parts))

    content = []
    for i in range(0, len(parts), 2):
        header = parts[i].strip()
        payload = parts[i + 1]

        expected_length = int(header.split(b"Length=")[1])

        # remove the end MIME block if it exists
        payload = re.sub((r'--\s*%s--\r\n$' % boundary).encode(), b'', payload)

        wrapped_data = payload.replace(b"\tContent-Type: application/octet-stream\r\n", b"")

        header_length = struct.unpack("<i", wrapped_data[:4])[0]
        b_header = wrapped_data[4:4 + header_length]
        b_enc_data = wrapped_data[4 + header_length:]
        unwrapped_data = context.unwrap_winrm(b_header, b_enc_data)
        actual_length = len(unwrapped_data)

        if actual_length != expected_length:
            raise Exception("The encrypted length from the server does not match the expected length, "
                            "decryption failed, actual: %d != expected: %d"
                            % (actual_length, expected_length))
        content.append(unwrapped_data)

    return b"".join(content)


def _encrypt_wsman(
        data: bytes,
        content_type: str,
        encryption_type: str,
        context,
) -> typing.Tuple[bytes, str]:
    boundary = 'Encrypted Boundary'

    # If using CredSSP we must encrypt in 16KiB chunks.
    max_size = 16384 if 'CredSSP' in encryption_type else len(data)
    chunks = [data[i:i + max_size] for i in range(0, len(data), max_size)]

    encrypted_chunks = []
    for chunk in chunks:
        enc_details = context.wrap_winrm(chunk)
        padding_length = enc_details.padding_length
        wrapped_data = struct.pack("<i", len(enc_details.header)) + enc_details.header + enc_details.data
        chunk_length = str(len(chunk) + padding_length)

        content = "\r\n".join([
            '--%s' % boundary,
            '\tContent-Type: %s' % encryption_type,
            '\tOriginalContent: type=%s;Length=%s' % (content_type, chunk_length),
            '--%s' % boundary,
            '\tContent-Type: application/octet-stream',
            '',
        ])
        encrypted_chunks.append(content.encode() + wrapped_data)

    content_sub_type = 'multipart/encrypted' if len(encrypted_chunks) == 1 else 'multipart/x-multi-encrypted'
    content_type = '%s;protocol="%s";boundary="%s"' % (content_sub_type, encryption_type, boundary)
    data = b"".join(encrypted_chunks) + ("--%s--\r\n" % boundary).encode()

    return data, content_type
