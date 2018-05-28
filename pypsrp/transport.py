# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import requests
import warnings

from pypsrp.exceptions import AuthenticationError, WinRMTransportError

log = logging.getLogger(__name__)


class TransportHTTP(object):

    def __init__(self, server, port, username, password, ssl=True,
                 path="wsman", auth="negotiate"):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.path = path
        self.auth = auth

        self.endpoint = "%s://%s:%d/%s" \
                        % ("https" if ssl else "http", server, port, path)
        log.info("Initialising HTTP transport for endpoint: %s"
                 % self.endpoint)
        self.session = None

        # used when building tests, keep commented out
        self._test_messages = []

    def send(self, message):
        if self.session is None:
            self.session = self._build_session()

        log.debug("Sending message: %s" % message)

        # for testing, keep commented out
        self._test_messages.append({"request": message.decode('utf-8'),
                                    "response": None})
        request = requests.Request('POST', self.endpoint, data=message)
        prep_request = self.session.prepare_request(request)

        response = self.session.send(prep_request)
        response_text = response.text if response.content else ''

        # for testing, keep commented out
        self._test_messages[-1]['response'] = response_text
        log.debug("Received message: %s" % response_text)
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

        return response.content

    def _build_session(self):
        log.debug("Building requests session with auth %s" % self.auth)
        self._suppress_library_warnings()
        session = requests.Session()
        session.verify = False
        session.auth = requests.auth.HTTPBasicAuth(username=self.username,
                                                   password=self.password)

        session.headers['Content-Type'] = "application/soap+xml;charset=UTF-8"
        session.headers['User-Agent'] = "Python PSRP Client"
        return session

    def _suppress_library_warnings(self):
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
        try:
            from requests.packages.urllib3.exceptions import \
                InsecureRequestWarning
            warnings.simplefilter('ignore', category=InsecureRequestWarning)
        except:
            pass
