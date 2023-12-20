# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pathlib
import ssl

import httpcore
import spnego
import spnego.channel_bindings
import spnego.tls
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

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

    Creates a new SSLContext to use for TLS connections.

    Args:
        verify:
        certfile:
        keyfile:
        password:

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
) -> spnego.channel_bindings.GssChannelBindings | None:
    """Get Channel Binding Token.

    Get the channel binding tls-server-end-point token from the SSL object
    passed in.

    Args:
        ssl_object: The SSLObject to get the token for.

    Returns:
        Optional[spngeo.channel_bindings.GssChannelBindings]: The channel
        channel bindings if present.
    """
    certificate_der = ssl_object.getpeercert(True)
    if not certificate_der:
        return None

    backend = default_backend()
    cert = x509.load_der_x509_certificate(certificate_der, backend)
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_algorithm = None

    # If the cert signature algorithm is unknown, md5, or sha1 then use sha256
    # otherwise use the signature algorithm of the cert itself.
    if not hash_algorithm or hash_algorithm.name in ["md5", "sha1"]:
        digest = hashes.Hash(hashes.SHA256(), backend)
    else:
        digest = hashes.Hash(hash_algorithm, backend)

    digest.update(certificate_der)
    certificate_hash = digest.finalize()

    return spnego.channel_bindings.GssChannelBindings(
        application_data=b"tls-server-end-point:" + certificate_hash,
    )
