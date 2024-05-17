# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pathlib
import ssl
import tempfile

import httpcore
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from spnego.channel_bindings import GssChannelBindings

HAS_TRUSTSTORE = True
try:
    import truststore
except ImportError:  # pragma: nocover
    HAS_TRUSTSTORE = False


def create_ssl_context(
    verify: bool | str | None = None,
    certfile: str | None = None,
    keyfile: str | None = None,
    password: str | None = None,
) -> ssl.SSLContext:
    """Create new SSL Context.

    Creates a new SSLContext to use for TLS connections. Python 3.10 will use
    the truststore package to create the SSLContext so it trusts the system CA
    trust store. Otherwise, it will use the default SSL trust location
    behaviour that Python provides.

    When using client certificate authentication, the caller must provide:

    + The private key,
    + The certificate, and
    + Any certs that might be needed to verify the cert back to a CA

    Each certificate should be in the PEM format with the key being first, then
    the certificate sequence starting with the leaf certificate. The private
    key can be encrypted with a password which is specified by the password
    argument.

    The certfile argument can either be a path to a file that contains the
    PEM certificate and optionally the PEM private key. The keyfile argument
    can also be used when certfile is a path to provide the private key as a
    separate file.

    The certificate argument can also be a string that contains both the
    private key and certificate in PEM format. As Python does not support a way
    to load the certificate/key from memory it will be written to a temporary
    file using mkstemp(). This file will be deleted as soon as it is loaded by
    OpenSSL and while it is stored in a secure temporary file, the key should
    be password protected for added protection. The keyfile argument is ignored
    when certfile is set to the certificate string and not a path.

    Args:
        verify: When set to a bool defines whether to verify the cert or not.
            If set to a string, it is treated as a path to a CA trust store.
        certfile: Used for certificate authentication. This is the path to the
            client certificate PEM or the certificate as a string.
        keyfile: The certificate authentication key file.
        password: The password used to decrypt the certificate key if required.

    Returns:
        ssl.SSLContext: The configured SSLContext to use for the TLS connection.
    """
    context: ssl.SSLContext
    if HAS_TRUSTSTORE:
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    else:
        context = httpcore.default_ssl_context()

    if certfile:
        # Needed for certificate authentication with TLS 1.3 as WSMan does post
        # handshake cert authentication.
        context.post_handshake_auth = True

        # Python doesn't support loading from memory, this is a workaround
        # using a temporary file from mkstemp() which should be secure enough.
        # Users should be aware of this limitation and protect the keys with a
        # password. Setting delete_on_close=False is needed for Windows support
        # as the file is locked by the process and can't be read by the SSL. It
        # will still be deleted when the context manager is exited.
        # https://github.com/python/cpython/pull/2449
        if "-----BEGIN CERTIFICATE-----" in certfile:
            with tempfile.NamedTemporaryFile(mode="w+b", delete_on_close=False) as fd:
                fd.write(certfile.encode("utf-8"))
                fd.flush()
                fd.close()

                context.load_cert_chain(
                    certfile=fd.name,
                    password=password,
                )

        else:
            context.load_cert_chain(
                certfile=certfile,
                keyfile=keyfile,
                password=password,
            )

    if verify is None or verify is True:
        return context

    if verify is False:
        context.check_hostname = False
        context.verify_mode = ssl.VerifyMode.CERT_NONE
        return context

    verify_path = pathlib.Path(verify)
    if verify_path.is_dir():
        context.load_verify_locations(capath=str(verify_path.absolute()))

    elif verify_path.is_file():
        context.load_verify_locations(cafile=str(verify_path.absolute()))

    else:
        raise ValueError(f"Provided CA trust path '{verify}' does not exist")

    return context


def get_tls_server_end_point_bindings(
    ssl_object: ssl.SSLObject,
) -> GssChannelBindings | None:
    """Get Channel Binding Token.

    Get the channel binding tls-server-end-point token from the SSL object
    passed in.

    Args:
        ssl_object: The SSLObject to get the token for.

    Returns:
        Optional[GssChannelBindings]: The channel channel bindings if present.
    """
    certificate_der = ssl_object.getpeercert(True)
    if not certificate_der:
        return None

    backend = default_backend()
    cert = x509.load_der_x509_certificate(certificate_der, backend)

    alg_oid = cert.signature_algorithm_oid.dotted_string
    hash_algorithm: hashes.HashAlgorithm
    if alg_oid in (
        "1.2.840.10045.4.3.3",  # SHA384ECDSA
        "1.2.840.113549.1.1.12",  # SHA384RSA
        "2.16.840.1.101.3.4.2.2",  # SHA384
    ):
        hash_algorithm = hashes.SHA384()

    elif alg_oid in (
        "1.2.840.10045.4.3.4",  # SHA512ECDSA
        "1.2.840.113549.1.1.13",  # SHA512RSA
        "2.16.840.1.101.3.4.2.3",  # SHA512
    ):
        hash_algorithm = hashes.SHA512()

    else:
        # Older protocols default to SHA256, also used as a catch all in case
        # of a weird algorithm which will most likely also use SHA256.
        hash_algorithm = hashes.SHA256()

    digest = hashes.Hash(hash_algorithm, backend)

    digest.update(certificate_der)
    certificate_hash = digest.finalize()

    return GssChannelBindings(
        application_data=b"tls-server-end-point:" + certificate_hash,
    )
