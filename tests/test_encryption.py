import pytest

from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import WinRMError


class MockAuthCREDSSP(object):

    def __init__(self):
        class TlsConnection(object):
            def get_cipher_name(self):
                return "ECDHE-RSA-AES256-GCM-SHA384"
        self.tls_connection = TlsConnection()

    def wrap(self, data):
        return data + b"-encrypted"

    def unwrap(self, data):
        return data[:len(data) - 10]


class MockAuthSPNEGO(object):

    def wrap(self, data):
        return b"header ", data + b"-encrypted"

    def unwrap(self, header, data):
        return data[:len(data) - 10]


class MockAuth(object):

    def __init__(self, auth):
        self.contexts = {
            'hostname': auth
        }


class TestWinRMEncryption(object):

    def test_wrap_small_spnego(self):
        plaintext = b"plaintext"
        encryption = WinRMEncryption(MockAuth(MockAuthSPNEGO()),
                                     WinRMEncryption.SPNEGO)
        expected = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=9\r\n" \
                   b"--Encrypted Boundary\r\n\tContent-Type: application/" \
                   b"octet-stream\r\n\x07\x00\x00\x00header plaintext-" \
                   b"encrypted--Encrypted Boundary--\r\n"
        actual_type, actual = encryption.wrap_message(plaintext, "hostname")

        assert "multipart/encrypted" == actual_type
        assert expected == actual

    def test_wrap_small_credsp(self):
        plaintext = b"plaintext"
        encryption = WinRMEncryption(MockAuth(MockAuthCREDSSP()),
                                     WinRMEncryption.CREDSSP)
        expected = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=9\r\n" \
                   b"--Encrypted Boundary\r\n\tContent-Type: application/" \
                   b"octet-stream\r\n\x10\x00\x00\x00plaintext-encrypted" \
                   b"--Encrypted Boundary--\r\n"
        actual_type, actual = encryption.wrap_message(plaintext, "hostname")

        assert "multipart/encrypted" == actual_type
        assert expected == actual

    def test_wrap_large_spnego(self):
        plaintext = b"a" * 20000
        encryption = WinRMEncryption(MockAuth(MockAuthSPNEGO()),
                                     WinRMEncryption.SPNEGO)
        expected = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=20000" \
                   b"\r\n--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/octet-stream\r\n\x07\x00\x00\x00header " + plaintext + \
                   b"-encrypted--Encrypted Boundary--\r\n"
        actual_type, actual = encryption.wrap_message(plaintext, "hostname")

        assert "multipart/encrypted" == actual_type
        assert expected == actual

    def test_wrap_large_credsp(self):
        plaintext = b"a" * 20000
        encryption = WinRMEncryption(MockAuth(MockAuthCREDSSP()),
                                     WinRMEncryption.CREDSSP)
        expected = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=16384" \
                   b"\r\n--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/octet-stream\r\n\x10\x00\x00\x00" + b"a" * 16384 + \
                   b"-encrypted--Encrypted Boundary\r\n\tContent-Type: " \
                   b"application/HTTP-CredSSP-session-encrypted\r\n" \
                   b"\tOriginalContent: type=application/soap+xml;" \
                   b"charset=UTF-8;Length=3616\r\n--Encrypted Boundary\r\n" \
                   b"\tContent-Type: application/octet-stream\r\n" \
                   b"\x10\x00\x00\x00" + b"a" * 3616 + \
                   b"-encrypted--Encrypted Boundary--\r\n"
        actual_type, actual = encryption.wrap_message(plaintext, "hostname")

        assert "multipart/x-multi-encrypted" == actual_type
        assert expected == actual

    def test_unwrap_small_spnego(self):
        expected = b"plaintext"
        encryption = WinRMEncryption(MockAuth(MockAuthSPNEGO()),
                                     WinRMEncryption.SPNEGO)
        bwrapped = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=9\r\n" \
                   b"--Encrypted Boundary\r\n\tContent-Type: application/" \
                   b"octet-stream\r\n\x07\x00\x00\x00header plaintext-" \
                   b"encrypted--Encrypted Boundary--\r\n"
        actual = encryption.unwrap_message(bwrapped, "hostname")
        assert expected == actual

    def test_unwrap_small_spnego_without_end_hyphens(self):
        expected = b"plaintext"
        encryption = WinRMEncryption(MockAuth(MockAuthSPNEGO()),
                                     WinRMEncryption.SPNEGO)
        bwrapped = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=9\r\n" \
                   b"--Encrypted Boundary\r\n\tContent-Type: application/" \
                   b"octet-stream\r\n\x07\x00\x00\x00header plaintext-" \
                   b"encrypted--Encrypted Boundary\r\n"
        actual = encryption.unwrap_message(bwrapped, "hostname")
        assert expected == actual

    def test_unwrap_small_credsp(self):
        expected = b"plaintext"
        encryption = WinRMEncryption(MockAuth(MockAuthCREDSSP()),
                                     WinRMEncryption.CREDSSP)
        bwrapped = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=9\r\n" \
                   b"--Encrypted Boundary\r\n\tContent-Type: application/" \
                   b"octet-stream\r\n\x10\x00\x00\x00plaintext-encrypted" \
                   b"--Encrypted Boundary--\r\n"
        actual = encryption.unwrap_message(bwrapped, "hostname")

        assert expected == actual

    def test_unwrap_large_spnego(self):
        expected = b"a" * 20000
        encryption = WinRMEncryption(MockAuth(MockAuthSPNEGO()),
                                     WinRMEncryption.SPNEGO)
        bwrapped = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=20000" \
                   b"\r\n--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/octet-stream\r\n\x07\x00\x00\x00header " + expected + \
                   b"-encrypted--Encrypted Boundary--\r\n"
        actual = encryption.unwrap_message(bwrapped, "hostname")

        assert expected == actual

    def test_unwrap_large_credsp(self):
        expected = b"a" * 20000
        encryption = WinRMEncryption(MockAuth(MockAuthCREDSSP()),
                                     WinRMEncryption.CREDSSP)
        bwrapped = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=16384" \
                   b"\r\n--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/octet-stream\r\n\x10\x00\x00\x00" + b"a" * 16384 + \
                   b"-encrypted--Encrypted Boundary\r\n\tContent-Type: " \
                   b"application/HTTP-CredSSP-session-encrypted\r\n" \
                   b"\tOriginalContent: type=application/soap+xml;" \
                   b"charset=UTF-8;Length=3616\r\n--Encrypted Boundary\r\n" \
                   b"\tContent-Type: application/octet-stream\r\n" \
                   b"\x10\x00\x00\x00" + b"a" * 3616 + \
                   b"-encrypted--Encrypted Boundary--\r\n"
        actual = encryption.unwrap_message(bwrapped, "hostname")

        assert expected == actual

    def test_unwrap_length_mismatch(self):
        encryption = WinRMEncryption(MockAuth(MockAuthSPNEGO()),
                                     WinRMEncryption.SPNEGO)
        bwrapped = b"--Encrypted Boundary\r\n\tContent-Type: application" \
                   b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: " \
                   b"type=application/soap+xml;charset=UTF-8;Length=9\r\n" \
                   b"--Encrypted Boundary\r\n\tContent-Type: application/" \
                   b"octet-stream\r\n\x07\x00\x00\x00header plain-" \
                   b"encrypted--Encrypted Boundary--\r\n"

        with pytest.raises(WinRMError) as err:
            encryption.unwrap_message(bwrapped, "hostname")

        assert str(err.value) == \
            "The encrypted length from the server does not match the " \
            "expected length, decryption failed, actual: 5 != expected: 9"

    @pytest.mark.parametrize('cipher, expected', [
        ['ECDHE-RSA-AES128-GCM-SHA256', 16],
        ['RC4-MD5', 16],
        ['ECDH-ECDSA-3DES-SHA256', 34],
        ['ECDH-RSA-AES-SHA384', 50],
        ['ECDH-RSA-AES', 2],

    ])
    def test_get_credssp_trailer_length(self, cipher, expected):
        encryption = WinRMEncryption(None, WinRMEncryption.CREDSSP)
        actual = encryption._credssp_trailer(30, cipher)

        assert expected == actual
