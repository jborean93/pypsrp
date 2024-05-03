from __future__ import annotations

import base64
import collections
import datetime
import pathlib
import re
import typing as t

import cryptography.x509 as x509
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

# @pytest.fixture(scope="function")
# def keypair(tmpdir: pathlib.Path) -> pathlib.Path:
#     key_path = tmpdir / "cert.pem"

#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#         backend=default_backend(),
#     )

#     subject = issuer = x509.Name(
#         [
#             x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "AU"),
#             x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Queensland"),
#             x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Brisbane"),
#             x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "My Company"),
#             x509.NameAttribute(x509.NameOID.COMMON_NAME, "mysite.com"),
#         ]
#     )

#     cert = (
#         x509.CertificateBuilder()
#         .subject_name(subject)
#         .issuer_name(issuer)
#         .public_key(private_key.public_key())
#         .serial_number(x509.random_serial_number())
#         .not_valid_before(datetime.datetime.utcnow())
#         .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
#         .add_extension(
#             x509.SubjectAlternativeName([x509.DNSName("localhost")]),
#             critical=False,
#         )
#         .sign(private_key, SHA256())
#     )

#     with open(key_path, mode="wb") as fd:
#         fd.write(
#             private_key.private_bytes(
#                 encoding=Encoding.PEM,
#                 format=PrivateFormat.TraditionalOpenSSL,
#                 encryption_algorithm=NoEncryption(),
#             )
#         )
#         fd.write(cert.public_bytes(Encoding.PEM))

#     return key_path


# @pytest.mark.parametrize(
#     "args, kwargs, expected",
#     [
#         (("http://server/",), {}, "http://server/"),
#         (("http://server:1234/",), {}, "http://server:1234/"),
#         (("http://server/wsman",), {}, "http://server/wsman"),
#         (("http://server:5985/wsman",), {}, "http://server:5985/wsman"),
#         (("https://server:5986/wsman",), {}, "https://server:5986/wsman"),
#         ((("server",), {}, "http://server:5985/wsman")),
#         (((), {"server": "server"}, "http://server:5985/wsman")),
#         ((("server", "http"), {}, "http://server:5985/wsman")),
#         (((), {"server": "server", "scheme": "http"}, "http://server:5985/wsman")),
#         ((("server", "http", 5985), {}, "http://server:5985/wsman")),
#         ((("server", "http", 80), {}, "http://server:80/wsman")),
#         ((("server", "http", 5986), {}, "http://server:5986/wsman")),
#         (((), {"server": "server", "scheme": "http", "port": 5985}, "http://server:5985/wsman")),
#         ((("server", "http", 5985, "wsman"), {}, "http://server:5985/wsman")),
#         ((("server", "https", 5986, "wsman"), {}, "https://server:5986/wsman")),
#         ((("server", "http", 5986, "wsman"), {}, "http://server:5986/wsman")),
#         (((), {"server": "server", "scheme": "http", "port": 5985, "path": "wsman"}, "http://server:5985/wsman")),
#         ((("server",), {"port": 80}, "http://server:80/wsman")),
#         ((("server",), {"port": 5985}, "http://server:5985/wsman")),
#         ((("server",), {"port": 5986}, "https://server:5986/wsman")),
#         ((("2001:0db8:0a0b:12f0:0000:0000:0000:0001",), {}, "http://[2001:db8:a0b:12f0::1]:5985/wsman")),
#         ((("2001:db8:a0b:12f0::1",), {}, "http://[2001:db8:a0b:12f0::1]:5985/wsman")),
#         ((("FE80::0202:B3FF:FE1E:8329",), {"port": 5986}, "https://[fe80::202:b3ff:fe1e:8329]:5986/wsman")),
#     ],
# )
# def test_connection_info_uri(args, kwargs, expected):
#     actual = wsman.WSManConnectionData(*args, **kwargs)
#     assert actual.connection_uri == expected


# def test_connection_info_invalid_auth_value():
#     with pytest.raises(
#         ValueError, match="The auth value 'invalid' must be basic, certificate, credssp, kerberos, negotiate, or ntlm"
#     ):
#         wsman.WSManConnectionData("server", auth="invalid")


# def test_connection_info_invalid_encryption_value():
#     with pytest.raises(ValueError, match="The encryption value 'invalid' must be auto, always, or never"):
#         wsman.WSManConnectionData("server", encryption="invalid")


# def test_connection_info_invalid_credssp_auth_value():
#     with pytest.raises(
#         ValueError, match="The credssp_auth_mechanism value 'invalid' must be kerberos, negotiate, or ntlm"
#     ):
#         wsman.WSManConnectionData("server", auth="credssp", credssp_auth_mechanism="invalid")


# def test_connection_info_cert_with_http():
#     with pytest.raises(ValueError, match="scheme='https' must be used with auth='certificate'"):
#         wsman.WSManConnectionData("server", auth="certificate")


# def test_connection_info_cert_without_pem():
#     with pytest.raises(ValueError, match="certificate_pem must be set when using auth='certificate'"):
#         wsman.WSManConnectionData("server", scheme="https", auth="certificate")


# def test_connection_info_basic_invalid_encryption():
#     with pytest.raises(ValueError, match="Must set encryption='never' when using auth='basic' over HTTP"):
#         wsman.WSManConnectionData("server", auth="basic")


# def test_connection_info_encryption_always_with_invalid_auth():
#     with pytest.raises(ValueError, match="Cannot use auth encryption with auth='basic' or auth='certificate'"):
#         wsman.WSManConnectionData("server", auth="basic", encryption="always")


# @pytest.mark.parametrize(
#     "scheme, encryption, expected",
#     [
#         ("http", "always", True),
#         ("http", "auto", True),
#         ("http", "never", False),
#         ("https", "always", True),
#         ("https", "auto", False),
#         ("https", "never", False),
#     ],
# )
# def test_connection_info_message_encryption(
#     scheme: t.Literal["http", "https"],
#     encryption: t.Literal["always", "auto", "never"],
#     expected: bool,
# ) -> None:
#     actual = wsman.WSManConnectionData("server", scheme=scheme, auth="ntlm", encryption=encryption)
#     assert expected == actual.message_encryption


# def test_connection_with_cert_auth(keypair: pathlib.Path) -> None:
#     connection = wsman.WSManConnectionData(
#         "server",
#         scheme="https",
#         auth="certificate",
#         certificate_pem=str(keypair),
#     )
#     headers = connection._get_default_headers()

#     assert headers == {
#         "Accept-Encoding": "identity",
#         "Content-Type": "application/soap+xml;charset=UTF-8",
#         "User-Agent": "Python PSRP Client",
#         "Authorization": "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual",
#     }


# def test_connection_with_cert_auth_separate_key(keypair: pathlib.Path, tmpdir: pathlib.Path) -> None:
#     key_pem_path = tmpdir / "cert_key.pem"
#     cert_pem_path = tmpdir / "cert_cert.pem"

#     with open(keypair, mode="rb") as fd:
#         contents = fd.read()
#         split_idx = contents.index(b"-----BEGIN CERTIFICATE-----")
#         key = contents[: split_idx - 1]
#         cert = contents[split_idx:]

#     with open(key_pem_path, mode="wb") as fd:
#         fd.write(key)

#     with open(cert_pem_path, mode="wb") as fd:
#         fd.write(cert)

#     connection = wsman.WSManConnectionData(
#         "server",
#         scheme="https",
#         auth="certificate",
#         certificate_pem=str(cert_pem_path),
#         certificate_key_pem=str(key_pem_path),
#     )
#     headers = connection._get_default_headers()

#     assert headers == {
#         "Accept-Encoding": "identity",
#         "Content-Type": "application/soap+xml;charset=UTF-8",
#         "User-Agent": "Python PSRP Client",
#         "Authorization": "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual",
#     }


# def test_connection_with_cert_auth_separate_password_protected_key(
#     keypair: pathlib.Path,
#     tmpdir: pathlib.Path,
# ) -> None:
#     key_pem_path = tmpdir / "cert_key.pem"
#     cert_pem_path = tmpdir / "cert_cert.pem"
#     password = "Password123!"

#     with open(keypair, mode="rb") as fd:
#         contents = fd.read()
#         split_idx = contents.index(b"-----BEGIN CERTIFICATE-----")
#         key = contents[: split_idx - 1]
#         cert = contents[split_idx:]

#     private_key = load_pem_private_key(key, password=None)
#     key = private_key.private_bytes(
#         encoding=Encoding.PEM,
#         format=PrivateFormat.PKCS8,
#         encryption_algorithm=BestAvailableEncryption(password.encode()),
#     )

#     with open(key_pem_path, mode="wb") as fd:
#         fd.write(key)

#     with open(cert_pem_path, mode="wb") as fd:
#         fd.write(cert)

#     connection = wsman.WSManConnectionData(
#         "server",
#         scheme="https",
#         auth="certificate",
#         certificate_pem=str(cert_pem_path),
#         certificate_key_pem=str(key_pem_path),
#         certificate_key_password=password,
#     )
#     headers = connection._get_default_headers()

#     assert headers == {
#         "Accept-Encoding": "identity",
#         "Content-Type": "application/soap+xml;charset=UTF-8",
#         "User-Agent": "Python PSRP Client",
#         "Authorization": "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual",
#     }
