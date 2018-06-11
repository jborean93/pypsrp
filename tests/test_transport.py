import os
import requests

import pytest

import pypsrp.transport as pypsrp_transport

from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import AuthenticationError, WinRMTransportError
from pypsrp.negotiate import HTTPNegotiateAuth
from pypsrp.transport import TransportHTTP

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


@pytest.fixture('function')
def reset_imports():
    # ensure the changes to these globals aren't persisted after each test
    orig_has_credssp = pypsrp_transport.HAS_CREDSSP
    orig_credssp_imp_err = pypsrp_transport.CREDSSP_IMP_ERR
    yield None
    pypsrp_transport.HAS_CREDSSP = orig_has_credssp
    pypsrp_transport.CREDSSP_IMP_ERR = orig_credssp_imp_err


class TestTransportHTTP(object):

    def test_not_supported_auth(self):
        with pytest.raises(ValueError) as err:
            TransportHTTP("", "", auth="fake")
        assert str(err.value) == \
            "The specified auth 'fake' is not supported, please select one " \
            "of 'basic, certificate, credssp, kerberos, negotiate, ntlm'"

    def test_invalid_encryption_value(self):
        with pytest.raises(ValueError) as err:
            TransportHTTP("", "", encryption="fake")
        assert str(err.value) == \
            "The encryption value 'fake' must be auto, always, or never"

    def test_encryption_always_not_valid_auth_ssl(self):
        with pytest.raises(ValueError) as err:
            TransportHTTP("", "", auth="basic", encryption="always", ssl=True)
        assert str(err.value) == \
            "Cannot use message encryption with auth 'basic', either set " \
            "encryption='auto' or use one of the following auth providers: " \
            "credssp, kerberos, negotiate, ntlm"

    def test_encryption_auto_not_valid_auth_no_ssl(self):
        with pytest.raises(ValueError) as err:
            TransportHTTP("", "", auth="basic", encryption="auto", ssl=False)
        assert str(err.value) == \
            "Cannot use message encryption with auth 'basic', either set " \
            "encryption='never', use ssl=True or use one of the following " \
            "auth providers: credssp, kerberos, negotiate, ntlm"

    def test_build_basic_no_username(self):
        transport = TransportHTTP("")
        with pytest.raises(ValueError) as err:
            transport._build_auth_basic(None)
        assert str(err.value) == \
            "For basic auth, the username must be specified"

    def test_build_basic_no_password(self):
        transport = TransportHTTP("", username="user")
        with pytest.raises(ValueError) as err:
            transport._build_auth_basic(None)
        assert str(err.value) == \
            "For basic auth, the password must be specified"

    def test_build_basic(self):
        transport = TransportHTTP("", username="user", password="pass",
                                  auth="basic")
        session = transport._build_session()
        assert transport.encryption is None
        assert isinstance(session.auth, requests.auth.HTTPBasicAuth)
        assert session.auth.username == "user"
        assert session.auth.password == "pass"

    def test_build_certificate_no_key_pem(self):
        transport = TransportHTTP("")
        with pytest.raises(ValueError) as err:
            transport._build_auth_certificate(None)
        assert str(err.value) == \
            "For certificate auth, the path to the certificate key pem file " \
            "must be specified with certificate_key_pem"

    def test_build_certificate_no_pem(self):
        transport = TransportHTTP("", certificate_key_pem="path")
        with pytest.raises(ValueError) as err:
            transport._build_auth_certificate(None)
        assert str(err.value) == \
            "For certificate auth, the path to the certificate pem file " \
            "must be specified with certificate_pem"

    def test_build_certificate_not_ssl(self):
        transport = TransportHTTP("", certificate_key_pem="path",
                                  certificate_pem="path", ssl=False)
        with pytest.raises(ValueError) as err:
            transport._build_auth_certificate(None)
        assert str(err.value) == "For certificate auth, SSL must be used"

    def test_build_certificate(self):
        transport = TransportHTTP("", auth="certificate",
                                  certificate_key_pem="key_pem",
                                  certificate_pem="pem")
        session = transport._build_session()
        assert transport.encryption is None
        assert session.auth is None
        assert session.cert == ("pem", "key_pem")
        assert session.headers['Authorization'] == \
            "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/" \
            "https/mutual"

    def test_build_credssp_not_imported(self, reset_imports):
        pypsrp_transport.HAS_CREDSSP = False
        pypsrp_transport.CREDSSP_IMP_ERR = "import failed"
        transport = TransportHTTP("")
        with pytest.raises(ImportError) as err:
            transport._build_auth_credssp(None)
        assert str(err.value) == \
            "Cannot use CredSSP auth as requests-credssp is not " \
            "installed: import failed"

    def test_build_credssp_no_username(self, reset_imports):
        pypsrp_transport.HAS_CREDSSP = True
        transport = TransportHTTP("")
        with pytest.raises(ValueError) as err:
            transport._build_auth_credssp(None)
        assert str(err.value) == \
            "For credssp auth, the username must be specified"

    def test_build_credssp_no_password(self, reset_imports):
        pypsrp_transport.HAS_CREDSSP = True
        transport = TransportHTTP("", username="user")
        with pytest.raises(ValueError) as err:
            transport._build_auth_credssp(None)
        assert str(err.value) == \
            "For credssp auth, the password must be specified"

    def test_build_credssp_no_kwargs(self):
        credssp = pytest.importorskip("requests_credssp")

        transport = TransportHTTP("", username="user", password="pass",
                                  auth="credssp")
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.CREDSSP
        assert isinstance(session.auth, credssp.HttpCredSSPAuth)
        assert session.auth.auth_mechanism == 'auto'
        assert session.auth.disable_tlsv1_2 is False
        assert session.auth.minimum_version == 2
        assert session.auth.password == 'pass'
        assert session.auth.username == 'user'

    def test_build_credssp_with_kwargs(self):
        credssp = pytest.importorskip("requests_credssp")

        transport = TransportHTTP("", username="user", password="pass",
                                  auth="credssp",
                                  credssp_auth_mechanism="kerberos",
                                  credssp_disable_tlsv1_2=True,
                                  credssp_minimum_version=5)

        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.CREDSSP
        assert isinstance(session.auth, credssp.HttpCredSSPAuth)
        assert session.auth.auth_mechanism == 'kerberos'
        assert session.auth.disable_tlsv1_2 is True
        assert session.auth.minimum_version == 5
        assert session.auth.password == 'pass'
        assert session.auth.username == 'user'

    def test_build_kerberos(self):
        transport = TransportHTTP("", auth="kerberos")
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.SPNEGO
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "kerberos"
        assert session.auth.delegate is False
        assert session.auth.hostname_override is None
        assert session.auth.password is None
        assert session.auth.send_cbt is True
        assert session.auth.service == 'WSMAN'
        assert session.auth.username is None
        assert session.auth.wrap_required is False

    def test_build_kerberos_with_kwargs(self):
        transport = TransportHTTP("", auth="kerberos", username="user",
                                  ssl=False, password="pass",
                                  negotiate_delegate=True,
                                  negotiate_hostname_override="host",
                                  negotiate_send_cbt=False,
                                  negotiate_service="HTTP")
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.SPNEGO
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "kerberos"
        assert session.auth.delegate is True
        assert session.auth.hostname_override == "host"
        assert session.auth.password == "pass"
        assert session.auth.send_cbt is False
        assert session.auth.service == 'HTTP'
        assert session.auth.username == "user"
        assert session.auth.wrap_required is True

    def test_build_negotiate(self):
        transport = TransportHTTP("")
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.SPNEGO
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "auto"
        assert session.auth.delegate is False
        assert session.auth.hostname_override is None
        assert session.auth.password is None
        assert session.auth.send_cbt is True
        assert session.auth.service == 'WSMAN'
        assert session.auth.username is None
        assert session.auth.wrap_required is False

    def test_build_negotiate_with_kwargs(self):
        transport = TransportHTTP("", auth="negotiate", username="user",
                                  ssl=False, password="pass",
                                  negotiate_delegate=True,
                                  negotiate_hostname_override="host",
                                  negotiate_send_cbt=False,
                                  negotiate_service="HTTP")
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.SPNEGO
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "auto"
        assert session.auth.delegate is True
        assert session.auth.hostname_override == "host"
        assert session.auth.password == "pass"
        assert session.auth.send_cbt is False
        assert session.auth.service == 'HTTP'
        assert session.auth.username == "user"
        assert session.auth.wrap_required is True

    def test_build_ntlm(self):
        transport = TransportHTTP("", auth="ntlm")
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.SPNEGO
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "ntlm"
        assert session.auth.delegate is False
        assert session.auth.hostname_override is None
        assert session.auth.password is None
        assert session.auth.send_cbt is True
        assert session.auth.service == 'WSMAN'
        assert session.auth.username is None
        assert session.auth.wrap_required is False

    def test_build_ntlm_with_kwargs(self):
        transport = TransportHTTP("", auth="ntlm", username="user",
                                  ssl=False, password="pass",
                                  negotiate_delegate=True,
                                  negotiate_hostname_override="host",
                                  negotiate_send_cbt=False,
                                  negotiate_service="HTTP",
                                  cert_validation=False)
        session = transport._build_session()
        assert isinstance(transport.encryption, WinRMEncryption)
        assert transport.encryption.protocol == WinRMEncryption.SPNEGO
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "ntlm"
        assert session.auth.delegate is True
        assert session.auth.hostname_override == "host"
        assert session.auth.password == "pass"
        assert session.auth.send_cbt is False
        assert session.auth.service == 'HTTP'
        assert session.auth.username == "user"
        assert session.auth.wrap_required is True

    def test_build_session_default(self):
        transport = TransportHTTP("")
        session = transport._build_session()
        assert session.headers['User-Agent'] == "Python PSRP Client"
        assert session.trust_env is True
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.proxies == {}
        assert session.verify is True

    def test_build_session_cert_validate(self):
        transport = TransportHTTP("", cert_validation=True)
        session = transport._build_session()
        assert session.verify is True

    def test_build_session_cert_validate_env(self):
        transport = TransportHTTP("", cert_validation=True)
        os.environ['REQUESTS_CA_BUNDLE'] = 'path_to_REQUESTS_CA_CERT'
        try:
            session = transport._build_session()
        finally:
            del os.environ['REQUESTS_CA_BUNDLE']
        assert session.verify == 'path_to_REQUESTS_CA_CERT'

    def test_build_session_cert_validate_path_override_env(self):
        transport = TransportHTTP("", cert_validation="kwarg_path")
        os.environ['REQUESTS_CA_BUNDLE'] = 'path_to_REQUESTS_CA_CERT'
        try:
            session = transport._build_session()
        finally:
            del os.environ['REQUESTS_CA_BUNDLE']
        assert session.verify == 'kwarg_path'

    def test_build_session_cert_no_validate(self):
        transport = TransportHTTP("", cert_validation=False)
        session = transport._build_session()
        assert session.verify is False

    def test_build_session_cert_no_validate_override_env(self):
        transport = TransportHTTP("", cert_validation=False)
        os.environ['REQUESTS_CA_BUNDLE'] = 'path_to_REQUESTS_CA_CERT'
        try:
            session = transport._build_session()
        finally:
            del os.environ['REQUESTS_CA_BUNDLE']
        assert session.verify is False

    def test_build_session_proxies_default(self):
        transport = TransportHTTP("")
        session = transport._build_session()
        assert session.proxies == {}

    def test_build_session_proxies_env(self):
        transport = TransportHTTP("")
        os.environ['https_proxy'] = "https://envproxy"
        try:
            session = transport._build_session()
        finally:
            del os.environ['https_proxy']
        assert session.proxies == {"https": "https://envproxy"}

    def test_build_session_proxies_kwarg(self):
        transport = TransportHTTP("", proxy="https://kwargproxy")
        session = transport._build_session()
        assert session.proxies == {"https": "https://kwargproxy"}

    def test_build_session_proxies_kwarg_non_ssl(self):
        transport = TransportHTTP("", proxy="http://kwargproxy", ssl=False)
        session = transport._build_session()
        assert session.proxies == {"http": "http://kwargproxy"}

    def test_build_session_proxies_env_kwarg_override(self):
        transport = TransportHTTP("", proxy="https://kwargproxy")
        os.environ['https_proxy'] = "https://envproxy"
        try:
            session = transport._build_session()
        finally:
            del os.environ['https_proxy']
        assert session.proxies == {"https": "https://kwargproxy"}

    def test_build_session_proxies_env_no_proxy_override(self):
        transport = TransportHTTP("", no_proxy=True)
        os.environ['https_proxy'] = "https://envproxy"
        try:
            session = transport._build_session()
        finally:
            del os.environ['https_proxy']
        assert session.proxies == {}

    def test_build_session_proxies_kwarg_ignore_no_proxy(self):
        transport = TransportHTTP("", proxy="https://kwargproxy",
                                  no_proxy=True)
        session = transport._build_session()
        assert session.proxies == {"https": "https://kwargproxy"}

    def test_send_without_encryption(self, monkeypatch):
        send_mock = MagicMock()

        monkeypatch.setattr(TransportHTTP, "_send_request", send_mock)

        transport = TransportHTTP("server")
        transport.send(b"message")

        assert send_mock.call_count == 1
        actual_request, actual_hostname = send_mock.call_args[0]

        assert actual_request.body == b"message"
        assert actual_request.url == "https://server:5986/wsman"
        assert actual_request.headers['content-type'] == \
            "application/soap+xml;charset=UTF-8"
        assert actual_hostname == "server"

    def test_send_with_encryption(self, monkeypatch):
        send_mock = MagicMock()
        wrap_mock = MagicMock()
        wrap_mock.return_value = "multipart/encrypted", b"wrapped"

        monkeypatch.setattr(TransportHTTP, "_send_request", send_mock)
        monkeypatch.setattr(WinRMEncryption, "wrap_message", wrap_mock)

        transport = TransportHTTP("server", ssl=False)
        transport.send(b"message")
        transport.send(b"message 2")

        assert send_mock.call_count == 3
        actual_request1, actual_hostname1 = send_mock.call_args_list[0][0]
        actual_request2, actual_hostname2 = send_mock.call_args_list[1][0]
        actual_request3, actual_hostname3 = send_mock.call_args_list[2][0]

        assert actual_hostname1 == "server"
        assert actual_hostname2 == "server"
        assert actual_hostname3 == "server"

        assert actual_request1.body is None
        assert actual_request1.url == "http://server:5985/wsman"

        assert actual_request2.body == b"wrapped"
        assert actual_request2.headers['content-type'] == \
            'multipart/encrypted;protocol="application/' \
            'HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
        assert actual_request2.url == "http://server:5985/wsman"

        assert actual_request3.body == b"wrapped"
        assert actual_request3.headers['content-type'] == \
            'multipart/encrypted;protocol="application/' \
            'HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
        assert actual_request3.url == "http://server:5985/wsman"

        assert wrap_mock.call_count == 2
        assert wrap_mock.call_args_list[0][0][0] == b"message"
        assert wrap_mock.call_args_list[0][0][1] == "server"
        assert wrap_mock.call_args_list[1][0][0] == b"message 2"
        assert wrap_mock.call_args_list[1][0][1] == "server"

    def test_send_default(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = "application/soap+xml;charset=UTF-8"

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request, "server")
        assert actual == b"content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == 30

    def test_send_timeout_kwargs(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = "application/soap+xml;charset=UTF-8"

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = TransportHTTP("server", ssl=True, connection_timeout=20)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request, "server")
        assert actual == b"content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == 20

    def test_send_auth_error(self, monkeypatch):
        response = requests.Response()
        response.status_code = 401

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        with pytest.raises(AuthenticationError) as err:
            transport._send_request(prep_request, "server")
        assert str(err.value) == "Failed to authenticate the user None with " \
                                 "negotiate"

    def test_send_winrm_error_blank(self, monkeypatch):
        response = requests.Response()
        response.status_code = 500
        response._content = b""

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        with pytest.raises(WinRMTransportError) as err:
            transport._send_request(prep_request, "server")
        assert str(err.value) == "Bad HTTP response returned from the " \
                                 "server. Code: 500, Content: ''"
        assert err.value.code == 500
        assert err.value.protocol == 'http'
        assert err.value.response_text == ''

    def test_send_winrm_error_content(self, monkeypatch):
        response = requests.Response()
        response.status_code = 500
        response._content = b"error msg"

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        with pytest.raises(WinRMTransportError) as err:
            transport._send_request(prep_request, "server")
        assert str(err.value) == "Bad HTTP response returned from the " \
                                 "server. Code: 500, Content: 'error msg'"
        assert err.value.code == 500
        assert err.value.protocol == 'http'
        assert err.value.response_text == 'error msg'

    def test_send_winrm_encrypted_single(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = \
            'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-' \
            'encrypted";boundary="Encrypted Boundary'

        send_mock = MagicMock()
        send_mock.return_value = response
        unwrap_mock = MagicMock()
        unwrap_mock.return_value = b"unwrapped content"

        monkeypatch.setattr(requests.Session, "send", send_mock)
        monkeypatch.setattr(WinRMEncryption, "unwrap_message", unwrap_mock)

        transport = TransportHTTP("server", ssl=False)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request, "server")
        assert actual == b"unwrapped content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == 30

        assert unwrap_mock.call_count == 1
        assert unwrap_mock.call_args[0] == (b"content", "server")
        assert unwrap_mock.call_args[1] == {}

    def test_send_winrm_encrypted_multiple(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = \
            'multipart/x-multi-encrypted;protocol="application/HTTP-CredSSP-' \
            'session-encrypted";boundary="Encrypted Boundary'

        send_mock = MagicMock()
        send_mock.return_value = response
        unwrap_mock = MagicMock()
        unwrap_mock.return_value = b"unwrapped content"

        monkeypatch.setattr(requests.Session, "send", send_mock)
        monkeypatch.setattr(WinRMEncryption, "unwrap_message", unwrap_mock)

        transport = TransportHTTP("server", ssl=False)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request, "server")
        assert actual == b"unwrapped content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == 30

        assert unwrap_mock.call_count == 1
        assert unwrap_mock.call_args[0] == (b"content", "server")
        assert unwrap_mock.call_args[1] == {}
