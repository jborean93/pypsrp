# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import httpx
import re
import spnego
import spnego.channel_bindings
import struct
import typing

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm


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
        if self._auth_header in ['Negotiate', 'NTLM']:
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
