# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import requests
import warnings

from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import AuthenticationError, WinRMTransportError
from pypsrp.negotiate import HTTPNegotiateAuth
from pypsrp._utils import to_string, get_hostname

HAVE_CREDSSP = False
CREDSSP_IMP_ERR = None
try:
    from requests_credssp import HttpCredSSPAuth
    HAVE_CREDSSP = True
except ImportError as err:
    CREDSSP_IMP_ERR = err

log = logging.getLogger(__name__)


class TransportHTTP(object):

    SUPPORTED_AUTHS = ["basic", "certificate", "credssp", "kerberos",
                       "negotiate", "ntlm"]

    AUTH_KWARGS = {
        "certificate": ["certificate_key_pem", "certificate_pem"],
        "credssp": ["credssp_auth_provider", "credssp_disable_tlsv1_2",
                    "credssp_minimum_version"],
        "negotiate": ["negotiate_delegate", "negotiate_hostname_override",
                      "negotiate_send_cbt", "negotiate_service"],
    }

    def __init__(self, server, port, username=None, password=None, ssl=True,
                 path="wsman", auth="negotiate", cert_validation=True,
                 connection_timeout=30, encryption='auto', proxy=None,
                 no_proxy=False, **kwargs):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.path = path

        if auth not in self.SUPPORTED_AUTHS:
            raise ValueError("The specified auth '%s' is not supported, "
                             "please select on of '%s'"
                             % (auth, ", ".join(self.SUPPORTED_AUTHS)))
        self.auth = auth
        self.cert_validation = cert_validation
        self.connection_timeout = connection_timeout

        # determine the message encryption logic
        if encryption not in ["auto", "always", "never"]:
            raise ValueError("The encryption value '%s' must be auto, "
                             "always, or never")
        enc_providers = ["credssp", "kerberos", "negotiate", "ntlm"]
        if ssl:
            # msg's are automatically encrypted with TLS, we only want message
            # encryption if always was specified
            self.wrap_required = encryption == "always"
            if encryption and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='auto' or use one of the following providers: "
                    "%s" % (self.auth, ", ".join(enc_providers))
                )
        else:
            # msg's should always be encrypted when not using SSL, unless the
            # user specifies to never encrypt
            self.wrap_required = not encryption == "never"
            if encryption and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='never', use ssl=True or use one of the "
                    "following providers: %s"
                    % (self.auth, ", ".join(enc_providers))
                )
        self.encryption = None

        self.proxy = proxy
        self.no_proxy = no_proxy

        for kwarg_list in self.AUTH_KWARGS.values():
            for kwarg in kwarg_list:
                setattr(self, kwarg, kwargs.get(kwarg, None))

        self.endpoint = "%s://%s:%d/%s" \
                        % ("https" if ssl else "http", server, port, path)
        log.info("Initialising HTTP transport for endpoint: %s"
                 % self.endpoint)
        self.session = None

        # used when building tests, keep commented out
        # self._test_messages = []

    def send(self, message):
        hostname = get_hostname(self.endpoint)
        if self.session is None:
            self.session = self._build_session()

            # need to send an initial blank message to setup the security
            # context required for encryption
            if self.wrap_required:
                request = requests.Request('POST', self.endpoint, data=None)
                prep_request = self.session.prepare_request(request)
                self._send_request(prep_request, hostname)

        log.debug("Sending message: %s" % message)
        # for testing, keep commented out
        # self._test_messages.append({"request": message.decode('utf-8'),
        #                             "response": None})

        headers = self.session.headers
        if self.wrap_required:
            content_type, payload = self.encryption.wrap_message(message,
                                                                 hostname)
            type_header = '%s;protocol="%s";boundary="Encrypted Boundary"' \
                          % (content_type, self.encryption.protocol)
            headers.update({
                'Content-Type': type_header,
                'Content-Length': str(len(payload)),
            })
        else:
            payload = message
            headers['Content-Type'] = "application/soap+xml;charset=UTF-8"

        request = requests.Request('POST', self.endpoint, data=payload,
                                   headers=headers)
        prep_request = self.session.prepare_request(request)
        return self._send_request(prep_request, hostname)

    def _send_request(self, request, hostname):
        response = self.session.send(request, timeout=self.connection_timeout)

        content_type = response.headers.get('content-type', "")
        if content_type.startswith("multipart/encrypted;") or \
                content_type.startswith("multipart/x-multi-encrypted;"):
            response_content = self.encryption.unwrap_message(response.content,
                                                              hostname)
            response_text = to_string(response_content)
        else:
            response_content = response.content
            response_text = response.text if response_content else ''

        log.debug("Received message: %s" % response_text)
        # for testing, keep commented out
        # self._test_messages[-1]['response'] = response_text
        try:
            response.raise_for_status()
        except requests.HTTPError as err:
            response = err.response
            if response.status_code == 401:
                raise AuthenticationError("Failed to authenticate the user %s "
                                          "with %s"
                                          % (self.username, self.auth))
            else:
                code = response.status_code
                raise WinRMTransportError('http', code, response_text)

        return response_content

    def _build_session(self):
        log.debug("Building requests session with auth %s" % self.auth)
        self._suppress_library_warnings()

        session = requests.Session()
        session.headers['User-Agent'] = "Python PSRP Client"

        # get the env requests settings
        session.trust_env = True
        settings = session.merge_environment_settings(url=self.endpoint,
                                                      proxies={},
                                                      stream=None,
                                                      verify=None,
                                                      cert=None)

        # set the proxy config
        session.proxies = settings['proxies']
        if self.proxy is not None:
            proxy_key = 'https' if self.ssl else 'http'
            session.proxies = {
                proxy_key: self.proxy
            }
        elif self.no_proxy:
            session.proxies = None

        # set cert validation config
        session.verify = self.cert_validation

        # if cert_validation is a bool (no path specified), not False and there
        # are env settings for verification, set those env settings
        if isinstance(self.cert_validation, bool) and self.cert_validation \
                and settings['verify'] is not None:
            session.verify = settings['verify']

        build_auth = getattr(self, "_build_auth_%s" % self.auth)
        build_auth(session)
        return session

    def _build_auth_basic(self, session):
        if self.username is None:
            raise ValueError("For basic auth, the username must be specified")
        if self.password is None:
            raise ValueError("For basic auth, the password must be specified")

        session.auth = requests.auth.HTTPBasicAuth(username=self.username,
                                                   password=self.password)

    def _build_auth_certificate(self, session):
        if self.certificate_key_pem is None:
            raise ValueError("For certificate auth, the path to the "
                             "certificate key pem file must be specified with "
                             "certificate_key_pem")
        if self.certificate_pem is None:
            raise ValueError("For certificate auth, the path to the "
                             "certificate pem file must be specified with "
                             "certificate_pem")

        session.cert = (self.certificate_pem, self.certificate_key_pem)
        session.headers['Authorization'] = \
            "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

    def _build_auth_credssp(self, session):
        if not HAVE_CREDSSP:
            raise ImportError("Cannot use CredSSP auth as requests-credssp is "
                              "not installed: %s" % str(CREDSSP_IMP_ERR))

        if self.username is None:
            raise ValueError("For credssp auth, the username must be "
                             "specified")
        if self.password is None:
            raise ValueError("For credssp auth, the password must be"
                             "specified")

        kwargs = self._get_auth_kwargs('credssp')
        session.auth = HttpCredSSPAuth(username=self.username,
                                       password=self.password,
                                       **kwargs)
        self.encryption = WinRMEncryption(
            session.auth, "application/HTTP-CredSSP-session-encrypted"
        )

    def _build_auth_kerberos(self, session):
        self._build_auth_negotiate(session, "kerberos")


    def _build_auth_negotiate(self, session, auth_provider="auto"):
        kwargs = self._get_auth_kwargs('negotiate')

        session.auth = HTTPNegotiateAuth(username=self.username,
                                         password=self.password,
                                         auth_provider=auth_provider,
                                         wrap_required=self.wrap_required,
                                         **kwargs)
        self.encryption = WinRMEncryption(
            session.auth, "application/HTTP-SPNEGO-session-encrypted"
        )

    def _build_auth_ntlm(self, session):
        self._build_auth_negotiate(session, "ntlm")

    def _get_auth_kwargs(self, auth_provider):
        kwargs = {}
        for kwarg in self.AUTH_KWARGS[auth_provider]:
            kwarg_value = getattr(self, kwarg, None)
            if kwarg_value is not None:
                kwargs[kwarg] = kwarg_value

        return kwargs

    def _suppress_library_warnings(self):
        # try to suppress known warnings from requests if possible
        try:
            from requests.packages.urllib3.exceptions import \
                InsecurePlatformWarning
            warnings.simplefilter('ignore', category=InsecurePlatformWarning)
        except:
            pass

        try:
            from requests.packages.urllib3.exceptions import SNIMissingWarning
            warnings.simplefilter('ignore', category=SNIMissingWarning)
        except:
            pass

        # if we're explicitly ignoring validation, try to suppress
        # InsecureRequestWarning, since the user opted-in
        if self.cert_validation is False:
            try:
                from requests.packages.urllib3.exceptions import \
                    InsecureRequestWarning
                warnings.simplefilter('ignore',
                                      category=InsecureRequestWarning)
            except:
                pass
