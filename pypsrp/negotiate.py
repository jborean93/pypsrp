# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import re
import sys
import warnings

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm
from requests.auth import AuthBase
from requests.packages.urllib3.response import HTTPResponse

from pypsrp.exceptions import AuthenticationError
from pypsrp.spgnego import get_auth_context
from pypsrp._utils import to_bytes, get_hostname

log = logging.getLogger(__name__)


class NoCertificateRetrievedWarning(Warning):
    pass


class UnknownSignatureAlgorithmOID(Warning):
    pass


class HTTPNegotiateAuth(AuthBase):

    def __init__(self, username=None, password=None, auth_provider='auto',
                 send_cbt=True, service='WSMAN', delegate=False,
                 hostname_override=None, wrap_required=False):
        """
        Creates a HTTP auth context that uses Microsoft's Negotiate protocol
        to complete the auth process. This currently only supports the NTLM
        and Kerberos providers in the Negotiate protocol.

        :param username: The username to authenticate with, if not specified
            this will be with the user currently logged in (Windows only) or
            the default Kerberos ticket in the cache
        :param password: The password for username, if not specified this will
            try to use implicit credentials available to the user
        :param auth_provider: The authentication provider to use
            'auto': Will try to use Kerberos if available and fallback to NTLM
                if that fails
            'ntlm': Will only use NTLM
            'kerberos': Will only use Kerberos and will fail if this is not
                available
        :param send_cbt: Try to bind the channel token (HTTPS only) to the auth
            process, default is True
        :param service: The service part of the SPN to authenticate with,
            defaults to HTTP
        :param delegate: Whether to get an auth token that allows the token to
            be delegated to other servers, this is only used with Kerberos and
            defaults to False
        :param hostname_override: Override the hostname used as part of the
            SPN, by default the hostname is based on the URL of the request
        :param wrap_required: Whether message encryption (wrapping) is
            required (controls what auth context is used)
        """
        self.username = username
        self.password = password
        self.auth_provider = auth_provider
        self.send_cbt = send_cbt
        self.service = service
        self.delegate = delegate
        self.hostname_override = hostname_override
        self.wrap_required = wrap_required
        self.contexts = {}

        self._regex = re.compile(r'Negotiate\s*([^,]*),?', re.I)

    def __call__(self, request):
        request.headers['Connection'] = 'Keep-Alive'
        request.register_hook('response', self.response_hook)

        return request

    def response_hook(self, response, **kwargs):
        if response.status_code == 401:
            self._check_auth_supported(response, "Negotiate")
            response = self.handle_401(response, **kwargs)

        return response

    def handle_401(self, response, **kwargs):
        host = get_hostname(response.url)
        if self.send_cbt:
            cbt_app_data = HTTPNegotiateAuth._get_cbt_data(response)

        auth_hostname = self.hostname_override or host
        context, token_gen, out_token = get_auth_context(
            self.username, self.password, self.auth_provider, cbt_app_data,
            auth_hostname, self.service, self.delegate, self.wrap_required
        )
        self.contexts[host] = context

        while not context.complete or out_token is not None:
            # consume content and release the original connection to allow the
            # new request to reuse the same one.
            response.content
            response.raw.release_conn()

            # create a request with the Negotiate token present
            request = response.request.copy()
            log.debug("Sending http request with new auth token")
            self._set_auth_token(request, out_token, "Negotiate")

            # send the request with the auth token and get the response
            response = response.connection.send(request, **kwargs)

            # attempt to retrieve the auth token response
            in_token = self._get_auth_token(response, self._regex)

            # break if there was no token received from the host and return the
            # last response
            if in_token in [None, b""]:
                log.debug("Did not receive a http response with an auth "
                          "response, stopping authentication process")
                break

            out_token = token_gen.send(in_token)

        return response

    @staticmethod
    def _check_auth_supported(response, auth_provider):
        auth_supported = response.headers.get('www-authenticate', '')
        if auth_provider.upper() not in auth_supported.upper():
            error_msg = "The server did not response with the " \
                        "authentication method of %s - actual: '%s'" \
                        % (auth_provider, auth_supported)
            raise AuthenticationError(error_msg)

    @staticmethod
    def _set_auth_token(request, token, auth_provider):
        encoded_token = base64.b64encode(token)
        auth_header = to_bytes("%s " % auth_provider) + encoded_token
        request.headers['Authorization'] = auth_header

    @staticmethod
    def _get_auth_token(response, pattern):
        auth_header = response.headers.get('www-authenticate', '')
        token_match = pattern.search(auth_header)

        if not token_match:
            return None

        token = token_match.group(1)
        return base64.b64decode(token)

    @staticmethod
    def _get_cbt_data(response):
        """
        Tries to get the channel binding token as specified in RFC 5929 to pass
        along to the authentication provider. This is usually the SHA256
        hash of the certificate of the HTTPS endpoint appended onto the string
        'tls-server-end-point'.

        If the socket is not an SSL socker or the raw HTTP object is not a
        urllib3 HTTPResponse, then None will be returned and no channel binding
        data is passed onto the auth context

        :param response: The server's response which is used to sniff out the
            server's certificate
        :return: A byte string containing the CBT prefix and cert hash to pass
            onto the auth context
        """
        app_data = None
        raw_response = response.raw

        if isinstance(raw_response, HTTPResponse):
            try:
                if sys.version_info > (3, 0):
                    socket = raw_response._fp.fp.raw._sock
                else:
                    socket = raw_response._fp.fp._sock
            except AttributeError as err:
                warning = "Failed to get raw socket for CBT from urllib3 " \
                          "resp: %s" % str(err)
                warnings.warn(warning, NoCertificateRetrievedWarning)
            else:
                try:
                    cert = socket.getpeercert(True)
                except AttributeError:
                    pass
                else:
                    cert_hash = HTTPNegotiateAuth._get_certificate_hash(cert)
                    app_data = b"tls-server-end-point:" + cert_hash
        else:
            warning = "Requests is running with a non urllib3 backend, " \
                      "cannot retrieve server cert for CBT. Raw type: %s" \
                      % type(response).__name__
            warnings.warn(warning, NoCertificateRetrievedWarning)

        return app_data

    @staticmethod
    def _get_certificate_hash(certificate_der):
        """
        Get's the server's certificate hash for the tls-server-end-point
        channel binding.

        According to https://tools.ietf.org/html/rfc5929#section-4.1, this is
        calculated by
            Using the SHA256 is the signatureAlgorithm is MD5 or SHA1
            The signatureAlgorithm if the hash function is neither MD5 or SHA1

        :param certificate_der: The byte string of the server's certificate
        :return: The byte string containing the hash of the server's
            certificate
        """
        backend = default_backend()

        cert = x509.load_der_x509_certificate(certificate_der, backend)

        try:
            hash_algorithm = cert.signature_hash_algorithm
        except UnsupportedAlgorithm as ex:
            warning = "Failed to get the signature algorithm from the " \
                      "certificate, unable to pass channel bindings data: %s" \
                      % str(ex)
            warnings.warn(warning, UnknownSignatureAlgorithmOID)
            return None

        # if the cert signature algorithm is either md5 or sha1 then use sha256
        # otherwise use the signature algorithm of the cert itself
        if hash_algorithm.name in ['md5', 'sha1']:
            digest = hashes.Hash(hashes.SHA256(), backend)
        else:
            digest = hashes.Hash(hash_algorithm, backend)

        digest.update(certificate_der)
        certificate_hash = digest.finalize()

        return certificate_hash
