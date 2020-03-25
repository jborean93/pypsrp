import re
import types

import pytest

import pypsrp.spnego as spnego

from ntlm_auth.ntlm import NtlmContext
from ntlm_auth.session_security import SessionSecurity

from pypsrp.spnego import get_auth_context, GSSAPIContext, NTLMContext, \
    SSPIContext

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


@pytest.fixture('function')
def reset_imports():
    # ensure the changes to these globals aren't persisted after each test
    orig_has_gssapi = spnego.HAS_GSSAPI
    orig_has_gssapi_encryption = spnego.HAS_GSSAPI_ENCRYPTION
    orig_has_sspi = spnego.HAS_SSPI
    yield None
    spnego.HAS_GSSAPI = orig_has_gssapi
    spnego.HAS_GSSAPI_ENCRYPTION = orig_has_gssapi_encryption
    spnego.HAS_SSPI = orig_has_sspi


class TestGetAuthContext(object):

    def test_invalid_provider(self):
        expected = "Invalid auth_provider specified fake, must be auto, kerberos, or ntlm"
        with pytest.raises(ValueError, match=re.escape(expected)):
            get_auth_context("", "", "fake", None, None, None, False, False, None)

    def test_fail_only_ntlm(self, reset_imports):
        spnego.HAS_SSPI = False
        spnego.HAS_GSSAPI = False

        expected = "The auth_provider specified 'kerberos' cannot be used without GSSAPI or SSPI being installed, " \
                   "select auto or install GSSAPI or SSPI"
        with pytest.raises(ValueError, match=re.escape(expected)):
            get_auth_context("", "", "kerberos", None, None, None, False, False, 'negotiate')

    @pytest.mark.parametrize('provider, header', [['ntlm', 'kerberos'], ['kerberos', 'ntlm']])
    def test_fail_provider_does_not_match_server_response(self, provider, header):
        expected = "Server responded with the auth protocol '%s' which is incompatible with the specified auth_" \
                   "provider '%s'" % (header, provider)
        with pytest.raises(ValueError, match=re.escape(expected)):
            get_auth_context("", "", provider, None, None, None, False, False, header)

    def test_get_auth_no_sspi_or_gssapi(self, reset_imports):
        spnego.HAS_GSSAPI = False
        spnego.HAS_SSPI = False
        context, gen, token = get_auth_context("", "", "auto", None, None, None, False, False, 'negotiate')

        assert isinstance(context, NTLMContext)
        assert token.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")

    def test_get_auth_has_gssapi_ntlm_with_cred(self, reset_imports):
        spnego.HAS_GSSAPI = True
        spnego.HAS_SSPI = False
        context, gen, token = get_auth_context("", "", "ntlm", None, None, None, False, True, 'negotiate')

        assert isinstance(context, NTLMContext)
        assert token.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")

    def test_get_auth_has_gssapi_no_encryption_and_ntlm(self, reset_imports,
                                                        monkeypatch):
        gss = pytest.importorskip("gssapi")
        spnego.HAS_GSSAPI_ENCRYPTION = False

        mock_set_sec = MagicMock(side_effect=gss.exceptions.GSSError(65536, 0))
        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)

        context, gen, token = get_auth_context("", "", "auto", None, "host", "service", False, True, 'negotiate')

        assert isinstance(context, NTLMContext)
        assert token.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")
        assert len(mock_set_sec.call_args) == 2
        assert mock_set_sec.call_args[0] == (gss.OID.from_int_seq("1.3.6.1.4.1.7165.655.1.3"),)
        assert isinstance(mock_set_sec.call_args[1]['context'], gss.SecurityContext)
        assert mock_set_sec.call_args[1]['value'] == b"\x00\x00\x00\x00"

    def test_get_auth_has_gssapi_kerb_failure(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_set_sec = MagicMock(side_effect=gss.exceptions.GSSError(65536, 0))

        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)

        # gssapi will fail because the user is not a valid user, we expect
        # this to happen and should result in NTLMContext being returned
        context, gen, token = get_auth_context("", "", "auto", None, "host", "service", False, False, 'negotiate')

        assert isinstance(context, NTLMContext)
        assert token.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")

    @pytest.mark.parametrize('auth, provider, wrap', [
        ['auto', 'Negotiate', False],
        ['auto', 'Negotiate', True],
        ['kerberos', 'Kerberos', False],
        ['kerberos', 'Kerberos', True],
        ['ntlm', 'Ntlm', False],
        ['ntlm', 'Ntlm', True],
    ])
    def test_get_auth_has_sspi(self, reset_imports, auth, provider, wrap,
                               monkeypatch):
        spnego.HAS_SSPI = True

        def _step(self, token=None):
            yield b"token"

        mock_init = MagicMock()
        monkeypatch.setattr(SSPIContext, "init_context", mock_init)
        monkeypatch.setattr(SSPIContext, "step", _step)

        context, gen, token = get_auth_context("", "", auth, None, "host", "service", False, wrap, 'negotiate')

        assert isinstance(context, SSPIContext)
        assert context.auth_provider == provider
        assert mock_init.call_count == 1
        assert isinstance(gen, types.GeneratorType)
        assert token == b"token"

    def test_get_auth_gssapi_auto_successful(self, monkeypatch):
        pytest.importorskip("gssapi")

        def _step(self, token=None):
            yield b"token"

        mock_set_sec = MagicMock()
        mock_init = MagicMock()
        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)
        monkeypatch.setattr(GSSAPIContext, "init_context", mock_init)
        monkeypatch.setattr(GSSAPIContext, "step", _step)

        context, gen, token = get_auth_context("", "", "auto", None, "host", "service", False, False, 'negotiate')

        assert isinstance(context, GSSAPIContext)
        assert context.auth_provider == "1.3.6.1.5.5.2"
        assert mock_init.call_count == 1
        assert isinstance(gen, types.GeneratorType)
        assert token == b"token"

    @pytest.mark.parametrize('header_token', ['negotiate', 'kerberos'])
    def test_get_auth_gssapi_auto_kerb_avail(self, header_token, monkeypatch):
        gss = pytest.importorskip("gssapi")

        def _step(self, token=None):
            yield b"token"

        mock_set_sec = MagicMock(side_effect=gss.exceptions.GSSError(65536, 0))
        mock_init = MagicMock()
        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)
        monkeypatch.setattr(GSSAPIContext, "init_context", mock_init)
        monkeypatch.setattr(GSSAPIContext, "step", _step)

        context, gen, token = get_auth_context("", "", "auto", None, "host", "service", False, False, header_token)

        assert isinstance(context, GSSAPIContext)
        assert context.auth_provider == "1.2.840.113554.1.2.2"
        assert mock_init.call_count == 1
        assert isinstance(gen, types.GeneratorType)
        assert token == b"token"

    def test_get_auth_gssapi_kerb_all_avail(self, monkeypatch):
        pytest.importorskip("gssapi")

        def _step(self, token=None):
            yield b"token"

        mock_set_sec = MagicMock()
        mock_init = MagicMock()
        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)
        monkeypatch.setattr(GSSAPIContext, "init_context", mock_init)
        monkeypatch.setattr(GSSAPIContext, "step", _step)

        context, gen, token = get_auth_context("", "", "kerberos", None, "host", "service", False, False, 'negotiate')

        assert isinstance(context, GSSAPIContext)
        assert context.auth_provider == "1.2.840.113554.1.2.2"
        assert mock_init.call_count == 1
        assert isinstance(gen, types.GeneratorType)
        assert token == b"token"

    def test_get_auth_gssapi_kerb_only_kerb(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        def _step(self, token=None):
            yield b"token"

        mock_set_sec = MagicMock(side_effect=gss.exceptions.GSSError(65536, 0))
        mock_init = MagicMock()
        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)
        monkeypatch.setattr(GSSAPIContext, "init_context", mock_init)
        monkeypatch.setattr(GSSAPIContext, "step", _step)

        context, gen, token = get_auth_context("", "", "kerberos", None, "host", "service", False, False, 'negotiate')

        assert isinstance(context, GSSAPIContext)
        assert context.auth_provider == "1.2.840.113554.1.2.2"
        assert mock_init.call_count == 1
        assert isinstance(gen, types.GeneratorType)
        assert token == b"token"

    def test_get_auth_gssapi_kerb_not_available(self, reset_imports,
                                                monkeypatch):
        pytest.importorskip("gssapi")

        spnego.HAS_GSSAPI_ENCRYPTION = False

        def _step(self, token=None):
            yield b"token"

        mock_set_sec = MagicMock()
        monkeypatch.setattr('gssapi.raw.set_sec_context_option', mock_set_sec)

        expected = "The auth_provider specified 'kerberos' is not available as message encryption is required but " \
                   "is not available on the current system. Either disable encryption, use https or specify auto/ntlm"
        with pytest.raises(ValueError, match=re.escape(expected)):
            get_auth_context("", "", "kerberos", None, "host", "service", False, True, 'negotiate')


class TestSSPIContext(object):

    def test_sspi_init_params(self):
        actual = SSPIContext("username", "password", "auto", None, "host",
                             "http", False)
        assert actual.username == "username"
        assert actual.domain == ""
        assert actual.password == "password"
        assert actual.auth_provider == "Negotiate"
        assert actual._target_spn == "HTTP/host"
        assert actual.cbt_app_data is None

    def test_sspi_implicit_username(self):
        actual = SSPIContext(None, None, "ntlm", None, "host", "http", False)
        assert actual.username is None
        assert actual.domain is None
        assert actual.password is None
        assert actual.auth_provider == "Ntlm"

    def test_sspi_cbt_data(self):
        actual = SSPIContext("domain\\user", "pass", "kerberos", b"cbt",
                             "host", "http", False)
        assert actual.username == "user"
        assert actual.domain == "domain"
        assert actual.password == "pass"
        assert actual.auth_provider == "Kerberos"
        assert actual.cbt_app_data == b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                                      b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                                      b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                                      b"\x03\x00\x00\x00\x20\x00\x00\x00" \
                                      b"cbt"

    def test_sspi_completed(self):
        class MockSecContext(object):

            def __init__(self):
                self.authenticated = False

        context = SSPIContext("user", "pass", "auto", None, "host", "http", False)
        context._context = MockSecContext()
        assert context.complete is False
        context._context.authenticated = True
        assert context.complete is True

    def test_sspi_step(self, monkeypatch):
        class MockSecContext(object):

            def __init__(self):
                self.authenticated = False
                self._first = True

        def _step(self, token):
            if self._context._first:
                self._context._first = False
                return b"token"
            else:
                self._context.authenticated = True
                return b""

        monkeypatch.setattr(SSPIContext, "_step", _step)
        context = SSPIContext("user", "pass", "auto", None, "host", "http", False)
        context._context = MockSecContext()

        gen = context.step()
        actual = next(gen)
        assert actual == b"token"
        assert context.complete is False
        actual2 = gen.send(b"next token")
        assert actual2 is None
        assert context.complete is True

    def test_sspi_wrap(self):
        class MockSecContext(object):

            def encrypt(self, data):
                return data + b"-encrypted", b"header"

        context = SSPIContext("user", "pass", "auto", None, "host", "http", False)

        context._context = MockSecContext()
        actual_header, actual_data = context.wrap(b"data")
        assert actual_header == b"header"
        assert actual_data == b"data-encrypted"

    def test_sspi_unwrap(self):
        class MockSecContext(object):

            def decrypt(self, data, header):
                return header + data

        context = SSPIContext("user", "pass", "auto", None, "host", "http", False)

        context._context = MockSecContext()
        actual = context.unwrap(b"header", b"data")
        assert actual == b"headerdata"


class TestGSSAPIContext(object):

    def test_gssapi_properties(self):
        actual = GSSAPIContext(None, None, "auto", None, "hostname", "http",
                               True, True)
        assert actual.username is None
        assert actual.domain == ""
        assert actual._target_spn == "http@hostname"

    def test_gssapi_step(self):
        class MockSecContext(object):

            def __init__(self):
                self.complete = False
                self._first = True

            def step(self, in_token=None):
                if self._first:
                    self._first = False
                    return b"token"
                else:
                    self.complete = True
                    return in_token

        context = GSSAPIContext(None, None, "auto", None, "hostname", "http", True, True)

        context._context = MockSecContext()
        assert context.complete is False

        gen = context.step()

        actual = next(gen)
        assert actual == b"token"
        assert context.complete is False

        actual2 = gen.send(b"new token")
        assert actual2 == b"new token"
        assert context.complete

    def test_gssapi_unwrap(self):
        context = GSSAPIContext(None, None, "auto", None, "hostname", "http", True, True)
        context._context = MagicMock()
        context.unwrap(b"header", b"data")
        method_calls = context._context.method_calls
        assert len(method_calls) == 1
        assert method_calls[0][0] == "unwrap"
        assert method_calls[0][1] == (b"headerdata",)
        assert method_calls[0][2] == {}

    def test_gssapi_init_context_auto(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_con = MagicMock()
        monkeypatch.setattr(GSSAPIContext, "_get_security_context", mock_con)
        context = GSSAPIContext("user", "pass", "auto", None, "hostname", "http", True, True)

        context.init_context()
        name, mech, spn, user, password, delegate, wrap, cbt = \
            mock_con.call_args[0]
        assert name == gss.NameType.user
        assert mech == gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['auto'])
        assert spn == "http@hostname"
        assert user == "user"
        assert password == "pass"
        assert delegate is True
        assert wrap is True
        assert cbt is None

    def test_gssapi_init_context_auto_no_delegate_wrap(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_con = MagicMock()
        monkeypatch.setattr(GSSAPIContext, "_get_security_context", mock_con)
        context = GSSAPIContext("user", "pass", "auto", None, "hostname", "http", False, False)

        context.init_context()
        name, mech, spn, user, password, delegate, wrap, cbt = mock_con.call_args[0]
        assert name == gss.NameType.user
        assert mech == gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['auto'])
        assert spn == "http@hostname"
        assert user == "user"
        assert password == "pass"
        assert delegate is False
        assert wrap is False
        assert cbt is None

    def test_gssapi_init_context_kerberos(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_con = MagicMock()
        monkeypatch.setattr(GSSAPIContext, "_get_security_context", mock_con)
        context = GSSAPIContext("user", "pass", "kerberos", None, "hostname", "http", True, True)

        context.init_context()
        name, mech, spn, user, password, delegate, wrap, cbt = mock_con.call_args[0]
        assert name == gss.NameType.kerberos_principal
        assert mech == gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        assert spn == "http@hostname"
        assert user == "user"
        assert password == "pass"
        assert delegate is True
        assert wrap is True
        assert cbt is None

    def test_gssapi_init_context_ntlm(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_con = MagicMock()
        monkeypatch.setattr(GSSAPIContext, "_get_security_context", mock_con)
        context = GSSAPIContext("user", "pass", "ntlm", None, "hostname", "http", True, True)

        context.init_context()
        name, mech, spn, user, password, delegate, wrap, cbt = mock_con.call_args[0]
        assert name == gss.NameType.user
        assert mech == gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['ntlm'])
        assert spn == "http@hostname"
        assert user == "user"
        assert password == "pass"
        assert delegate is True
        assert wrap is True
        assert cbt is None

    def test_gssapi_init_context_with_cbt(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_con = MagicMock()
        monkeypatch.setattr(GSSAPIContext, "_get_security_context", mock_con)
        context = GSSAPIContext("user", "pass", "auto", b"cbt", "hostname", "http", True, True)

        context.init_context()
        name, mech, spn, user, password, delegate, wrap, cbt = mock_con.call_args[0]
        assert name == gss.NameType.user
        assert mech == gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['auto'])
        assert spn == "http@hostname"
        assert user == "user"
        assert password == "pass"
        assert delegate is True
        assert wrap is True

        assert isinstance(cbt, gss.raw.ChannelBindings)
        assert cbt.application_data == b"cbt"

    def test_gssapi_get_sec_context_kerberos(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock()
        mock_acquire_cred = MagicMock()
        mock_context = MagicMock()

        monkeypatch.setattr(gss, 'Credentials', mock_cred)
        monkeypatch.setattr(gss.raw, 'acquire_cred_with_password', mock_acquire_cred)
        monkeypatch.setattr(gss, 'SecurityContext', mock_context)

        name_type = gss.NameType.kerberos_principal
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        spn = "http@hostname"
        username = "user@domain.com"
        password = "password"
        delegate = False
        wrap_required = False
        cbt = None

        GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)

        assert mock_cred.call_count == 1
        assert mock_cred.call_args[0] == ()
        assert mock_cred.call_args[1]['name'] == gss.Name(base=username, name_type=name_type)
        assert mock_cred.call_args[1]['usage'] == 'initiate'
        assert mock_cred.call_args[1]['mechs'] == [mech]

        assert mock_acquire_cred.call_count == 0

        assert mock_context.call_count == 1
        assert mock_context.call_args[0] == ()
        assert mock_context.call_args[1]['name'] == gss.Name(spn, name_type=gss.NameType.hostbased_service)
        assert isinstance(mock_context.call_args[1]['creds'], MagicMock)
        assert mock_context.call_args[1]['usage'] == "initiate"
        assert mock_context.call_args[1]['mech'] == mech
        assert mock_context.call_args[1]['flags'] == gss.RequirementFlag.mutual_authentication | \
            gss.RequirementFlag.out_of_sequence_detection
        assert mock_context.call_args[1]['channel_bindings'] == cbt

    def test_gssapi_get_sec_context_wrap(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock()
        mock_acquire_cred = MagicMock()
        mock_context = MagicMock()

        monkeypatch.setattr(gss, 'Credentials', mock_cred)
        monkeypatch.setattr(gss.raw, 'acquire_cred_with_password', mock_acquire_cred)
        monkeypatch.setattr(gss, 'SecurityContext', mock_context)

        name_type = gss.NameType.kerberos_principal
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        spn = "http@hostname"
        username = "user@domain.com"
        password = "password"
        delegate = False
        wrap_required = True
        cbt = None

        GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)

        assert mock_cred.call_count == 1
        assert mock_cred.call_args[0] == ()
        assert mock_cred.call_args[1]['name'] == gss.Name(base=username, name_type=name_type)
        assert mock_cred.call_args[1]['usage'] == 'initiate'
        assert mock_cred.call_args[1]['mechs'] == [mech]

        assert mock_acquire_cred.call_count == 0

        assert mock_context.call_count == 1
        assert mock_context.call_args[0] == ()
        assert mock_context.call_args[1]['name'] == gss.Name(spn, name_type=gss.NameType.hostbased_service)
        assert isinstance(mock_context.call_args[1]['creds'], MagicMock)
        assert mock_context.call_args[1]['usage'] == "initiate"
        assert mock_context.call_args[1]['mech'] == mech
        assert mock_context.call_args[1]['flags'] == \
            gss.RequirementFlag.mutual_authentication | \
            gss.RequirementFlag.out_of_sequence_detection | \
            gss.RequirementFlag.confidentiality
        assert mock_context.call_args[1]['channel_bindings'] == cbt

    def test_gssapi_get_sec_context_delegate(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock()
        mock_acquire_cred = MagicMock()
        mock_context = MagicMock()

        monkeypatch.setattr(gss, 'Credentials', mock_cred)
        monkeypatch.setattr(gss.raw, 'acquire_cred_with_password', mock_acquire_cred)
        monkeypatch.setattr(gss, 'SecurityContext', mock_context)

        name_type = gss.NameType.kerberos_principal
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        spn = "http@hostname"
        username = "user@domain.com"
        password = "password"
        delegate = True
        wrap_required = False
        cbt = None

        GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)

        assert mock_cred.call_count == 1
        assert mock_cred.call_args[0] == ()
        assert mock_cred.call_args[1]['name'] == gss.Name(base=username, name_type=name_type)
        assert mock_cred.call_args[1]['usage'] == 'initiate'
        assert mock_cred.call_args[1]['mechs'] == [mech]

        assert mock_acquire_cred.call_count == 0

        assert mock_context.call_count == 1
        assert mock_context.call_args[0] == ()
        assert mock_context.call_args[1]['name'] == gss.Name(spn, name_type=gss.NameType.hostbased_service)
        assert isinstance(mock_context.call_args[1]['creds'], MagicMock)
        assert mock_context.call_args[1]['usage'] == "initiate"
        assert mock_context.call_args[1]['mech'] == mech
        assert mock_context.call_args[1]['flags'] == \
            gss.RequirementFlag.mutual_authentication | \
            gss.RequirementFlag.out_of_sequence_detection | \
            gss.RequirementFlag.delegate_to_peer
        assert mock_context.call_args[1]['channel_bindings'] == cbt

    def test_gssapi_get_sec_context_kerb_fail_no_pass(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock(side_effect=gss.exceptions.GSSError(458752, 0))

        monkeypatch.setattr(gss, 'Credentials', mock_cred)

        name_type = gss.NameType.kerberos_principal
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        spn = "http@server2016.domain.local"
        username = None
        password = None
        delegate = False
        wrap_required = False
        cbt = None

        with pytest.raises(gss.exceptions.GSSError) as err:
            GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)
        assert err.value.maj_code == 458752
        assert err.value.min_code == 0

    def test_gssapi_get_sec_context_kerb_fail_with_pass(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock(side_effect=gss.exceptions.GSSError(458752, 0))
        mock_acquire_cred = MagicMock()
        mock_context = MagicMock()

        monkeypatch.setattr(gss, 'Credentials', mock_cred)
        monkeypatch.setattr(gss.raw, 'acquire_cred_with_password',
                            mock_acquire_cred)
        monkeypatch.setattr(gss, 'SecurityContext', mock_context)

        name_type = gss.NameType.kerberos_principal
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        spn = "http@hostname"
        username = "user@domain.com"
        password = "password"
        delegate = True
        wrap_required = False
        cbt = None

        GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)

        assert mock_cred.call_count == 1
        assert mock_cred.call_args[0] == ()
        assert mock_cred.call_args[1]['name'] == gss.Name(base=username, name_type=name_type)
        assert mock_cred.call_args[1]['usage'] == 'initiate'
        assert mock_cred.call_args[1]['mechs'] == [mech]

        assert mock_acquire_cred.call_count == 1
        assert mock_acquire_cred.call_args[0] == (gss.Name(base=username, name_type=name_type), b"password")
        assert mock_acquire_cred.call_args[1]['usage'] == 'initiate'
        assert mock_acquire_cred.call_args[1]['mechs'] == [mech]

        assert mock_context.call_count == 1
        assert mock_context.call_args[0] == ()
        assert mock_context.call_args[1]['name'] == gss.Name(spn, name_type=gss.NameType.hostbased_service)
        assert isinstance(mock_context.call_args[1]['creds'], MagicMock)
        assert mock_context.call_args[1]['usage'] == "initiate"
        assert mock_context.call_args[1]['mech'] == mech
        assert mock_context.call_args[1]['flags'] == \
            gss.RequirementFlag.mutual_authentication | \
            gss.RequirementFlag.out_of_sequence_detection | \
            gss.RequirementFlag.delegate_to_peer
        assert mock_context.call_args[1]['channel_bindings'] == cbt

    def test_gssapi_get_sec_context_auto(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock()
        mock_acquire_cred = MagicMock()
        mock_context = MagicMock()

        monkeypatch.setattr(gss, 'Credentials', mock_cred)
        monkeypatch.setattr(gss.raw, 'acquire_cred_with_password', mock_acquire_cred)
        monkeypatch.setattr(gss, 'SecurityContext', mock_context)

        name_type = gss.NameType.user
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['auto'])
        spn = "http@hostname"
        username = "user@domain.com"
        password = "password"
        delegate = False
        wrap_required = False
        cbt = b"cbt"

        GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)

        assert mock_cred.call_count == 0

        assert mock_acquire_cred.call_count == 1
        assert mock_acquire_cred.call_args[0] == (gss.Name(base=username, name_type=name_type), b"password")
        assert mock_acquire_cred.call_args[1]['usage'] == 'initiate'
        assert mock_acquire_cred.call_args[1]['mechs'] == [mech]

        assert mock_context.call_count == 1
        assert mock_context.call_args[0] == ()
        assert mock_context.call_args[1]['name'] == gss.Name(spn, name_type=gss.NameType.hostbased_service)
        assert isinstance(mock_context.call_args[1]['creds'], MagicMock)
        assert mock_context.call_args[1]['usage'] == "initiate"
        assert mock_context.call_args[1]['mech'] == mech
        assert mock_context.call_args[1]['flags'] == \
            gss.RequirementFlag.mutual_authentication | \
            gss.RequirementFlag.out_of_sequence_detection
        assert mock_context.call_args[1]['channel_bindings'] == cbt

    def test_gssapi_get_sec_context_auto_implicit(self, monkeypatch):
        gss = pytest.importorskip("gssapi")

        mock_cred = MagicMock()
        mock_acquire_cred = MagicMock()
        mock_context = MagicMock()

        monkeypatch.setattr(gss, 'Credentials', mock_cred)
        monkeypatch.setattr(gss.raw, 'acquire_cred_with_password', mock_acquire_cred)
        monkeypatch.setattr(gss, 'SecurityContext', mock_context)

        name_type = gss.NameType.user
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['kerberos'])
        spn = "http@hostname"
        username = None
        password = None
        delegate = False
        wrap_required = False
        cbt = None

        GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)

        assert mock_cred.call_count == 1
        assert mock_cred.call_args[0] == ()
        assert mock_cred.call_args[1]['name'] is None
        assert mock_cred.call_args[1]['usage'] == 'initiate'
        assert mock_cred.call_args[1]['mechs'] == [mech]

        assert mock_acquire_cred.call_count == 0

        assert mock_context.call_count == 1
        assert mock_context.call_args[0] == ()
        assert mock_context.call_args[1]['name'] == gss.Name(spn, name_type=gss.NameType.hostbased_service)
        assert isinstance(mock_context.call_args[1]['creds'], MagicMock)
        assert mock_context.call_args[1]['usage'] == "initiate"
        assert mock_context.call_args[1]['mech'] == mech
        assert mock_context.call_args[1]['flags'] == gss.RequirementFlag.mutual_authentication | \
            gss.RequirementFlag.out_of_sequence_detection
        assert mock_context.call_args[1]['channel_bindings'] == cbt

    def test_gssapi_get_sec_context_ntlm_implicit(self):
        gss = pytest.importorskip("gssapi")

        name_type = gss.NameType.user
        mech = gss.OID.from_int_seq(GSSAPIContext._AUTH_PROVIDERS['ntlm'])
        spn = "http@hostname"
        username = None
        password = None
        delegate = False
        wrap_required = False
        cbt = None

        expected = "Can only use implicit credentials with kerberos or auto (with no credentials) authentication"
        with pytest.raises(ValueError, match=re.escape(expected)):
            GSSAPIContext._get_security_context(name_type, mech, spn, username, password, delegate, wrap_required, cbt)


class TestNTLMContext(object):

    @pytest.mark.parametrize('username, expected_domain, expected_user', [
        ["username", "", "username"],
        ["username@domain.com", "", "username@domain.com"],
        ["domain\\username", "domain", "username"],
        ["domain\\user\\slash", "domain", "user\\slash"],
    ])
    def test_username_domain(self, username, expected_domain, expected_user):
        actual = NTLMContext(username, "password", None)
        assert actual.domain == expected_domain
        assert actual.username == expected_user

    def test_fail_no_username(self):
        with pytest.raises(ValueError) as err:
            NTLMContext(None, None, None)
        assert str(err.value) == "Cannot use ntlm-auth with no username set"

    def test_fail_no_password(self):
        with pytest.raises(ValueError) as err:
            NTLMContext("username", None, None)
        assert str(err.value) == "Cannot use ntlm-auth with no password set"

    def test_init_context_no_cbt(self):
        context = NTLMContext("username", "password", None)
        context.init_context()
        assert context.complete is False
        assert isinstance(context._context, NtlmContext)
        assert context._context.cbt_data is None

    def test_init_context_with_cbt(self):
        context = NTLMContext("username", "password", b"cbt")
        context.init_context()
        actual = context._context.cbt_data.get_data()
        assert actual == b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                         b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                         b"\x03\x00\x00\x00cbt"

    def test_step(self):
        context = NTLMContext("username", "password", None)
        context.init_context()

        gen = context.step()
        msg1 = next(gen)
        assert msg1.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")

        msg2 = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
               b"\x02\x00\x00\x00\x2f\x82\x88\xe2" \
               b"\x38\x00\x00\x00\x33\x82\x8a\xe2" \
               b"\x01\x23\x45\x67\x89\xab\xcd\xef" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x24\x00\x24\x00\x44\x00\x00\x00" \
               b"\x06\x00\x70\x17\x00\x00\x00\x0f" \
               b"\x53\x00\x65\x00\x72\x00\x76\x00" \
               b"\x65\x00\x72\x00\x02\x00\x0c\x00" \
               b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
               b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
               b"\x53\x00\x65\x00\x72\x00\x76\x00" \
               b"\x65\x00\x72\x00\x00\x00\x00\x00"
        msg3 = gen.send(msg2)
        assert msg3.startswith(b"NTLMSSP\x00\x03\x00\x00\x00")
        assert context.complete

    def test_wrap_unwrap(self):
        context = NTLMContext("username", "password", None)
        context.init_context()

        gen = context.step()
        next(gen)
        msg2 = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
               b"\x02\x00\x00\x00\x2f\x82\x88\xe2" \
               b"\x38\x00\x00\x00\x33\x82\x8a\xe2" \
               b"\x01\x23\x45\x67\x89\xab\xcd\xef" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x24\x00\x24\x00\x44\x00\x00\x00" \
               b"\x06\x00\x70\x17\x00\x00\x00\x0f" \
               b"\x53\x00\x65\x00\x72\x00\x76\x00" \
               b"\x65\x00\x72\x00\x02\x00\x0c\x00" \
               b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
               b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
               b"\x53\x00\x65\x00\x72\x00\x76\x00" \
               b"\x65\x00\x72\x00\x00\x00\x00\x00"
        gen.send(msg2)

        plaintext_client = b"client"
        plaintext_server = b"server"
        server_sec = SessionSecurity(
            context._context._session_security.negotiate_flags,
            context._context._session_security.exported_session_key, "server"
        )

        client_header, client_wrap = context.wrap(plaintext_client)
        assert client_header.startswith(b"\x01\x00\x00\x00")
        assert len(client_header) == 16
        assert client_wrap != plaintext_client

        client_plaintext = server_sec.unwrap(client_wrap, client_header)
        assert client_plaintext == plaintext_client

        server_wrap, server_header = server_sec.wrap(plaintext_server)
        assert server_header.startswith(b"\x01\x00\x00\x00")
        assert len(server_header) == 16
        assert server_wrap != plaintext_server

        server_plaintext = context.unwrap(server_header, server_wrap)
        assert server_plaintext == plaintext_server
