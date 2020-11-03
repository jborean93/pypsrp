# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import abc
import base64
import httpx
import re
import spnego
import spnego.channel_bindings
import struct
import typing

from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm


class _NoAuthenticationContext(Exception):
    pass


def get_tls_server_end_point_hash(certificate_der: bytes) -> bytes:
    backend = default_backend()

    cert = x509.load_der_x509_certificate(certificate_der, backend)
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_algorithm = None

    # If the cert signature algorithm is unknown, md5, or sha1 then use sha256 otherwise use the signature
    # algorithm of the cert itself.
    if not hash_algorithm or hash_algorithm.name in ['md5', 'sha1']:
        digest = hashes.Hash(hashes.SHA256(), backend)
    else:
        digest = hashes.Hash(hash_algorithm, backend)

    digest.update(certificate_der)
    certificate_hash = digest.finalize()

    return certificate_hash


def _select_protocol(
        auth_header: str,
        protocol: str
) -> str:
    auth_header_l = auth_header.lower()
    selected_protocol = auth_header_l

    if auth_header_l != protocol:
        if protocol == 'negotiate':
            # The protocol specified by the user was negotiate but the server did not response with Negotiate.
            # When creating the auth context use the protocol explicitly set by the server (Kerberos or NTLM).
            selected_protocol = auth_header_l

        elif auth_header_l == 'negotiate':
            # The server specified it supports Negotiate but the user wants either NTLM or Kerberos. Use what the
            # user prefers as it should work with Negotiate.
            selected_protocol = protocol

        else:
            raise ValueError("Server responded with the auth protocol '%s' which is incompatible with the "
                             "specified auth_provider '%s'" % (auth_header, protocol))

    return selected_protocol


def _valid_auth_headers(
        www_authenticate: str,
        accepted_protocols: typing.List[str]
) -> str:
    matched_protocols = [p for p in accepted_protocols if p.lower() in www_authenticate.lower()]
    if not matched_protocols:
        raise Exception("The server did not response with one of the following authentication methods %s - "
                        "actual: '%s'" % (", ".join(accepted_protocols), www_authenticate))

    return matched_protocols[0]


class WSManAuth(httpx.Auth):
    """WSMan HTTP authentication handler for httpx.

    The WSMan HTTP authentication handler for any request sent over the WSMan client. This handles Negotiate, Kerberos,
    NTLM, and CredSSP authentication through the pyspnego library.

    Params:
        username: The username to use.
        password: The password to use.
        protocol: The protocol to use, can be negotiate, kerberos, ntlm, or credssp.
        encryption_required: Whether WSMan encryption is required for the connection or not.
        service: Override the default SPN service (HTTP) if required for Kerberos SPN lookups.
        hostname_override: Override the default SPN principal name (endpoint) if required for Kerberos SPN lookups.
        send_cbt: Whether to attach the Channel Binding Token over a HTTPS connection or not. Does not apply to
            `protocol='credssp'`.
        delegate: Whether to request a delegated Kerberos ticket or not. Does not apply to `protocol='credssp'`.
        credssp_allow_tlsv1: For `protocol='credssp'`, allow TLSv1.0 connections, default is just TLSv1.2+.
        credssp_require_kerberos: For `protocol='credssp'`, make sure that Kerberos is available for negotiation. This
            does not ensure Kerberos is used in the authentication attempt, it just makes sure that it is available to
            be used.
    """

    def __init__(
            self,
            username: typing.Optional[str] = None,
            password: typing.Optional[str] = None,
            protocol: str = 'negotiate',
            encryption_required: bool = False,
            service: str = 'HTTP',
            hostname_override: typing.Optional[str] = None,
            send_cbt: bool = True,
            delegate: bool = False,
            credssp_allow_tlsv1: bool = False,
            credssp_require_kerberos: bool = False,
    ):
        self.username = username
        self.password = password
        self.protocol = protocol.lower()
        self.service = service
        self.hostname_override = hostname_override
        self.send_cbt = False if self.protocol == 'credssp' else send_cbt  # CredSSP does not use CBT at all.

        self._auth_header = None
        self._context = None
        self._context_req = spnego.ContextReq.default
        self._spnego_options = spnego.NegotiateOptions.none

        if encryption_required:
            self._spnego_options |= spnego.NegotiateOptions.wrapping_winrm

        if self.protocol == 'credssp':
            self._accepted_protocols = ['CredSSP']

            if credssp_allow_tlsv1:
                self._spnego_options |= spnego.NegotiateOptions.credssp_allow_tlsv1

            if credssp_require_kerberos:
                self._spnego_options |= spnego.NegotiateOptions.negotiate_kerberos

        elif self.protocol in ['negotiate', 'kerberos', 'ntlm']:
            self._accepted_protocols = ['Negotiate', 'Kerberos', 'NTLM']

            if delegate:
                self._context_req |= spnego.ContextReq.delegate

        else:
            raise ValueError("%s only supports credssp, negotiate, kerberos, or ntlm authentication"
                             % type(self).__name__)

        escaped_protocols = '|'.join([re.escape(p) for p in self._accepted_protocols])
        self._regex = re.compile(r'(%s)\s*([^,]*),?' % escaped_protocols, re.I)

    @property
    def encryption_type(self) -> str:
        """ Returns the WSMan encryption Content-Type for the authentication protocol used. """
        if self._auth_header is None:
            raise _NoAuthenticationContext

        elif self._auth_header in ['Negotiate', 'NTLM']:
            protocol = 'SPNEGO'

        elif self._auth_header == 'Kerberos':
            protocol = 'Kerberos'

        elif self._auth_header == 'CredSSP':
            protocol = 'CredSSP'

        else:
            raise ValueError("Unknown authentication header used '%s'" % self._auth_header)

        return 'application/HTTP-%s-session-encrypted' % protocol

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        response = yield request
        if response.status_code != 401:
            return

        self._auth_header = _valid_auth_headers(response.headers.get('www-authenticate', ''), self._accepted_protocols)
        selected_protocol = _select_protocol(self._auth_header, self.protocol)

        # Get the TLS object for CBT if required - will be None when connecting over HTTP
        socket = response.stream.connection.connection.socket.sock

        cbt = None
        if self.send_cbt and hasattr(socket, 'getpeercert'):
            cert = socket.getpeercert(True)
            cert_hash = get_tls_server_end_point_hash(cert)
            cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-server-end-point:" + cert_hash)

        auth_hostname = self.hostname_override or response.url.host
        self._context = spnego.client(self.username, self.password, hostname=auth_hostname, service=self.service,
                                      channel_bindings=cbt, context_req=self._context_req, protocol=selected_protocol,
                                      options=self._spnego_options)

        out_token = self._context.step()
        while not self._context.complete or out_token is not None:
            request.headers['Authorization'] = "%s %s" % (self._auth_header, base64.b64encode(out_token).decode())

            # send the request with the auth token and get the response
            response = yield request

            auth_header = response.headers.get('www-authenticate', '')
            in_token = self._regex.search(auth_header)
            if in_token:
                in_token = base64.b64decode(in_token.group(2))

            # If there was no token received from the host then we just break the auth cycle.
            if in_token in [None, b""]:
                break

            out_token = self._context.step(in_token)

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> typing.AsyncGenerator[httpx.Request, httpx.Response]:
        """ Handles the authentication attempts for WSMan when receiving a 401 response. """
        # TODO: Send first header optimistically
        response = yield request
        if response.status_code != 401:
            return

        self._auth_header = _valid_auth_headers(response.headers.get('www-authenticate', ''), self._accepted_protocols)
        selected_protocol = _select_protocol(self._auth_header, self.protocol)

        # Get the TLS object for CBT if required - will be None when connecting over HTTP
        sw = response.stream.connection.connection.socket.stream_writer
        ssl_object = sw.get_extra_info('ssl_object')

        cbt = None
        if self.send_cbt and ssl_object:
            cert = ssl_object.getpeercert(True)
            cert_hash = get_tls_server_end_point_hash(cert)
            cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-server-end-point:" + cert_hash)

        # FIXME: Need to run this in a separate thread? so it doesn't block other connections.
        auth_hostname = self.hostname_override or response.url.host
        self._context = spnego.client(self.username, self.password, hostname=auth_hostname, service=self.service,
                                      channel_bindings=cbt, context_req=self._context_req, protocol=selected_protocol,
                                      options=self._spnego_options)

        out_token = self._context.step()
        while not self._context.complete or out_token is not None:
            request.headers['Authorization'] = "%s %s" % (self._auth_header, base64.b64encode(out_token).decode())

            # send the request with the auth token and get the response
            response = yield request

            auth_header = response.headers.get('www-authenticate', '')
            in_token = self._regex.search(auth_header)
            if in_token:
                in_token = base64.b64decode(in_token.group(2))

            # If there was no token received from the host then we just break the auth cycle.
            if in_token in [None, b""]:
                break

            out_token = self._context.step(in_token)

    def wrap(self, data: bytes) -> typing.Tuple[bytes, int]:
        """ Wraps the data for use with WSMan encryption. """
        enc_details = self._context.wrap_winrm(data)
        enc_data = struct.pack("<i", len(enc_details.header)) + enc_details.header + enc_details.data

        return enc_data, enc_details.padding_length

    def unwrap(self, data: bytes) -> bytes:
        """ Unwraps the data from WSMan encryption. """
        header_length = struct.unpack("<i", data[:4])[0]
        b_header = data[4:4 + header_length]
        b_enc_data = data[4 + header_length:]

        return self._context.unwrap_winrm(b_header, b_enc_data)
       

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
            encryption: str = 'never',
            verify: typing.Union[str, bool] = True,
            connection_timeout: int = 30,
            read_timeout: int = 30,
            # TODO reconnection and proxy settings

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
        self._auth_kwargs = {}

        supported_auths = ['basic', 'certificate', 'negotiate', 'kerberos', 'ntlm', 'credssp']
        if auth not in supported_auths:
            raise ValueError("The specified auth '%s' is not supported, please select one of '%s'"
                             % (auth, ", ".join(supported_auths)))

        elif auth == 'basic':
            self.encrypt = False  # FIXME: add proper checks when running over HTTP

            self._auth_kwargs['auth'] = (username, password)

        elif auth == 'certificate':
            self.encrypt = False  # Must already be under HTTPS which has encryption.

            # TODO: Test password (3-tuple).
            headers['Authorization'] = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual'
            self._auth_kwargs['cert'] = (certificate_pem, certificate_key_pem, certificate_password)

        else:
            wsman_auth_kwargs = {
                'service': negotiate_service,
                'hostname_override': negotiate_hostname,
                'send_cbt': send_cbt,
                'delegate': negotiate_delegate,
                'credssp_allow_tlsv1': credssp_allow_tlsv1,
                'credssp_require_kerberos': credssp_require_kerberos,
            }

            self._auth_kwargs['auth'] = WSManAuth(username=username, password=password, protocol=auth,
                                                  encryption_required=self.encrypt, **wsman_auth_kwargs)

        # TODO: Proxy/SOCKS
        # TODO: Reconnection
        httpx.Limits()
        timeout = httpx.Timeout(max(connection_timeout, read_timeout), connect=connection_timeout, read=read_timeout)
        self._http = httpx.AsyncClient(headers=headers, timeout=timeout, verify=verify, **self._auth_kwargs)

        # FIXME: Remove this hack
        # https://github.com/encode/httpx/issues/1395
        self._http._transport._keepalive_expiry = 120.0

    async def send(
            self,
            data: bytes,
    ) -> bytes:
        content_type = 'application/soap+xml;charset=UTF-8'

        if data and self.encrypt:
            try:
                data, content_type = _encrypt_wsman(data, content_type, self._http.auth)

            except _NoAuthenticationContext:
                # Encryption requires an authentication context to be set up which only happens when we've sent a
                # request. Send a blank request to set up the context and return again.
                await self.send(b'')
                return await self.send(data)

        # FIXME: Handle connection being dropped from the pool after Keep-Alive expiry
        response = await self._http.post(self.connection_uri.geturl(), content=data, headers={
            'Content-Type': content_type,
        })
        
        content = response.content
        if content:
            content_type = response.headers.get('content-type', '')

            if content_type.startswith("multipart/encrypted;") or \
                    content_type.startswith("multipart/x-multi-encrypted;"):
                content = _decrypt_wsman(content, content_type, self._http.auth)

        elif response.status_code != 200:
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
        auth_context: WSManAuth,
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
        unwrapped_data = auth_context.unwrap(wrapped_data)
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
        auth_context: WSManAuth,
) -> typing.Tuple[bytes, str]:
    encryption_type = auth_context.encryption_type
    boundary = 'Encrypted Boundary'

    # If using CredSSP we must encrypt in 16KiB chunks.
    max_size = 16384 if 'CredSSP' in encryption_type else len(data)
    chunks = [data[i:i + max_size] for i in range(0, len(data), max_size)]

    encrypted_chunks = []
    for chunk in chunks:
        wrapped_data, padding_length = auth_context.wrap(chunk)
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
