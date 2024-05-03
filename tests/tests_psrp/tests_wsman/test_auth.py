from __future__ import annotations

# def test_wrap_small_spnego():
#     plaintext = b"plaintext"

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = (
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
#     )
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-SPNEGO-session-encrypted",
#         MockAuth(),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_wrap_spnego_padded():
#     plaintext = b"plaintext"

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=10\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = (
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
#     )
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-SPNEGO-session-encrypted",
#         MockAuth(padding=True),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_wrap_small_kerberos():
#     plaintext = b"plaintext"

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-Kerberos-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = (
#         'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"'
#     )
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-Kerberos-session-encrypted",
#         MockAuth(),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_wrap_small_credsp():
#     plaintext = b"plaintext"

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = (
#         'multipart/encrypted;protocol="application/HTTP-CredSSP-session-encrypted";boundary="Encrypted Boundary"'
#     )
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-CredSSP-session-encrypted",
#         MockAuth(),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_wrap_large_spnego():
#     plaintext = b"a" * 20000

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=20000"
#         b"\r\n--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/octet-stream\r\n\x10\x00\x00\x00reallylongheader" + plaintext + b"-encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = (
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
#     )
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-SPNEGO-session-encrypted",
#         MockAuth(),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_wrap_large_kerberos():
#     plaintext = b"a" * 20000

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-Kerberos-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=20000"
#         b"\r\n--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/octet-stream\r\n\x10\x00\x00\x00reallylongheader" + plaintext + b"-encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = (
#         'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"'
#     )
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-Kerberos-session-encrypted",
#         MockAuth(),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_wrap_large_credsp():
#     plaintext = b"a" * 20000

#     expected_msg = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=16384"
#         b"\r\n--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/octet-stream\r\n\x10\x00\x00\x00reallylongheader"
#         + b"a" * 16384
#         + b"-encrypted--Encrypted Boundary\r\n\tContent-Type: "
#         b"application/HTTP-CredSSP-session-encrypted\r\n"
#         b"\tOriginalContent: type=application/soap+xml;"
#         b"charset=UTF-8;Length=3616\r\n--Encrypted Boundary\r\n"
#         b"\tContent-Type: application/octet-stream\r\n"
#         b"\x10\x00\x00\x00reallylongheader" + b"a" * 3616 + b"-encrypted--Encrypted Boundary--\r\n"
#     )
#     expected_type = 'multipart/x-multi-encrypted;protocol="application/HTTP-CredSSP-session-encrypted";boundary="Encrypted Boundary"'
#     actual_msg, actual_type = wsman.encrypt_wsman(
#         plaintext,
#         "application/soap+xml;charset=UTF-8",
#         "application/HTTP-CredSSP-session-encrypted",
#         MockAuth(),
#     )

#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_small_spnego():
#     expected_msg = b"plaintext"
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary--\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_small_spnego_without_end_hyphens():
#     expected_msg = b"plaintext"
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_small_spnego_without_tabs():
#     expected_msg = b"plaintext"
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary\r\nContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\nOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\nContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted--Encrypted Boundary\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_small_kerberos():
#     expected_msg = b"plaintext"
#     expected_type = "application/soap+xml;charset=UTF-8"

#     # The spaces after -- on each boundary is on purpose, some MS implementations do this.
#     bwrapped = bytearray(
#         b"-- Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-Kerberos-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"-- Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-"
#         b"encrypted-- Encrypted Boundary--\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_small_credsp():
#     expected_msg = b"plaintext"
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary2\r\n\tContent-Type: application"
#         b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary2\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplaintext-encrypted"
#         b"--Encrypted Boundary2--\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-CredSSP-session-encrypted";boundary="Encrypted Boundary2"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_large_spnego():
#     expected_msg = b"a" * 20000
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=20000"
#         b"\r\n--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/octet-stream\r\n\x10\x00\x00\x00reallylongheader" + expected_msg + b"-encrypted--Encrypted Boundary--\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_large_kerberos():
#     expected_msg = b"a" * 20000
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-Kerberos-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=20000"
#         b"\r\n--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/octet-stream\r\n\x10\x00\x00\x00reallylongheader" + expected_msg + b"-encrypted--Encrypted Boundary--\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_large_credsp():
#     expected_msg = b"a" * 20000
#     expected_type = "application/soap+xml;charset=UTF-8"

#     bwrapped = bytearray(
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-CredSSP-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=16384"
#         b"\r\n--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/octet-stream\r\n\x10\x00\x00\x00reallylongheader"
#         + b"a" * 16384
#         + b"-encrypted--Encrypted Boundary\r\n\tContent-Type: "
#         b"application/HTTP-CredSSP-session-encrypted\r\n"
#         b"\tOriginalContent: type=application/soap+xml;"
#         b"charset=UTF-8;Length=3616\r\n--Encrypted Boundary\r\n"
#         b"\tContent-Type: application/octet-stream\r\n"
#         b"\x10\x00\x00\x00reallylongheader" + b"a" * 3616 + b"-encrypted--Encrypted Boundary--\r\n"
#     )

#     actual_msg, actual_type = wsman.decrypt_wsman(
#         bwrapped,
#         'multipart/x-multi-encrypted;protocol="application/HTTP-CredSSP-session-encrypted";boundary="Encrypted Boundary"',
#         MockAuth(),
#     )
#     assert expected_msg == actual_msg
#     assert expected_type == actual_type


# def test_unwrap_length_mismatch():
#     bwrapped = (
#         b"--Encrypted Boundary\r\n\tContent-Type: application"
#         b"/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
#         b"type=application/soap+xml;charset=UTF-8;Length=9\r\n"
#         b"--Encrypted Boundary\r\n\tContent-Type: application/"
#         b"octet-stream\r\n\x10\x00\x00\x00reallylongheaderplain-"
#         b"encrypted--Encrypted Boundary--\r\n"
#     )

#     expected = (
#         "The actual length from the server does not match the expected length, "
#         "decryption failed, actual: 5 != expected: 9"
#     )
#     with pytest.raises(ValueError, match=re.escape(expected)):
#         wsman.decrypt_wsman(
#             bwrapped,
#             'multipart/x-multi-encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"',
#             MockAuth(),
#         )


# def test_unwrap_invalid_content_type():
#     expected = "Content type 'test content type' did not match expected encrypted format"
#     with pytest.raises(ValueError, match=re.escape(expected)):
#         wsman.decrypt_wsman(
#             b"data",
#             "test content type",
#             MockAuth(),
#         )
