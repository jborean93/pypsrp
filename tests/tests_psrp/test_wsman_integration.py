import os
import pathlib
import typing as t

import pytest
import spnego.tls
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    load_pem_private_key,
)

import psrp
from psrp._compat import Literal


def get_server() -> str:
    server = os.environ.get("PYPSRP_SERVER", None)

    if not server:
        pytest.skip("WSMan integration tests requires PYPSRP_SERVER to be defined")

    return server


def get_username_password() -> t.Tuple[str, str]:
    username = os.environ.get("PYPSRP_USERNAME", None)
    password = os.environ.get("PYPSRP_PASSWORD", None)

    if not username or not password:
        pytest.skip("WSMan integration test requires PYPSRP_USERNAME and PYPSRP_PASSWORD to be defined")

    return username, password


def get_certificate_credential() -> str:
    cred_path = os.environ.get("PYPSRP_CERT_PATH", None)
    if not cred_path:
        pytest.skip("WSMan certificate integration test requires PYPSRP_CERT_PATH to be defined")

    return cred_path


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_wsman_basic_sync(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    if "\\" in username:
        username = username.split("\\")[1]

    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="basic",
        username=username,
        password=password,
        encryption="never" if scheme == "http" else "auto",
    )

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_wsman_basic_async(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    if "\\" in username:
        username = username.split("\\")[1]

    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="basic",
        username=username,
        password=password,
        encryption="never" if scheme == "http" else "auto",
    )

    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = await ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.parametrize("input_type", ["single_file", "separate", "separate_password"])
def test_wsman_cert_sync(input_type: str, tmpdir: pathlib.Path) -> None:
    cert_path = get_certificate_credential()

    connection_kwargs: t.Dict[str, t.Any] = {}
    if input_type == "single_file":
        connection_kwargs["certificate_pem"] = cert_path

    else:
        key_pem_path = tmpdir / "cert_key.pem"
        cert_pem_path = tmpdir / "cert.pem"

        with open(cert_path, mode="rb") as fd:
            contents = fd.read()
            split_idx = contents.index(b"-----BEGIN CERTIFICATE-----")
            key = contents[: split_idx - 1]
            cert = contents[split_idx:]

        if input_type == "separate_password":
            private_key = load_pem_private_key(key, password=None)

            password = "Password123!"
            key = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(password.encode()),
            )
            connection_kwargs["certificate_key_password"] = password

        with open(key_pem_path, mode="wb") as fd:
            fd.write(key)

        with open(cert_pem_path, mode="wb") as fd:
            fd.write(cert)

        connection_kwargs["certificate_pem"] = str(cert_pem_path)
        connection_kwargs["certificate_key_pem"] = str(key_pem_path)

    connection = psrp.WSManInfo(
        server=get_server(),
        scheme="https",
        verify=False,
        auth="certificate",
        **connection_kwargs,
    )

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.asyncio
@pytest.mark.parametrize("input_type", ["single_file", "separate", "separate_password"])
async def test_wsman_cert_async(input_type: str, tmpdir: pathlib.Path) -> None:
    cert_path = get_certificate_credential()

    connection_kwargs: t.Dict[str, t.Any] = {}
    if input_type == "single_file":
        connection_kwargs["certificate_pem"] = cert_path

    else:
        key_pem_path = tmpdir / "cert_key.pem"
        cert_pem_path = tmpdir / "cert.pem"

        with open(cert_path, mode="rb") as fd:
            contents = fd.read()
            split_idx = contents.index(b"-----BEGIN CERTIFICATE-----")
            key = contents[: split_idx - 1]
            cert = contents[split_idx:]

        if input_type == "separate_password":
            private_key = load_pem_private_key(key, password=None)

            password = "Password123!"
            key = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(password.encode()),
            )
            connection_kwargs["certificate_key_password"] = password

        with open(key_pem_path, mode="wb") as fd:
            fd.write(key)

        with open(cert_pem_path, mode="wb") as fd:
            fd.write(cert)

        connection_kwargs["certificate_pem"] = str(cert_pem_path)
        connection_kwargs["certificate_key_pem"] = str(key_pem_path)

    connection = psrp.WSManInfo(
        server=get_server(),
        scheme="https",
        verify=False,
        auth="certificate",
        **connection_kwargs,
    )

    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = await ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_wsman_ntlm_sync(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="ntlm",
        username=username,
        password=password,
        negotiate_delegate=True,
    )

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_wsman_ntlm_async(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="ntlm",
        username=username,
        password=password,
        negotiate_delegate=True,
    )

    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = await ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_wsman_credssp_sync(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="credssp",
        username=username,
        password=password,
    )

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_wsman_credssp_async(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="credssp",
        username=username,
        password=password,
    )

    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = await ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_wsman_credssp__with_subauth_and_tls_sync(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="credssp",
        username=username,
        password=password,
        credssp_auth_mechanism="ntlm",
        credssp_minimum_version=2,
        credssp_ssl_context=spnego.tls.default_tls_context().context,
    )

    with psrp.SyncRunspacePool(connection) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = ps.invoke()

        assert actual == ["a" * 20480]


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_wsman_credssp_with_subauth_and_tls_async(scheme: Literal["http", "https"]) -> None:
    username, password = get_username_password()
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme=scheme,
        verify=False,
        auth="credssp",
        username=username,
        password=password,
        credssp_auth_mechanism="ntlm",
        credssp_minimum_version=2,
        credssp_ssl_context=spnego.tls.default_tls_context().context,
    )

    async with psrp.AsyncRunspacePool(connection) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"a" * 20KB')
        actual = await ps.invoke()

        assert actual == ["a" * 20480]


def test_wsman_invalid_credential_sync() -> None:
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme="http",
        auth="ntlm",
        username="invalid",
        password="invalid",
    )

    with pytest.raises(psrp.WSManAuthenticationError) as e:
        with psrp.SyncRunspacePool(connection):
            pass

    assert e.value.http_code == 401


@pytest.mark.asyncio
async def test_wsman_invalid_credential_async() -> None:
    connection = psrp.WSManInfo(
        server=get_server(),
        scheme="http",
        auth="ntlm",
        username="invalid",
        password="invalid",
    )

    with pytest.raises(psrp.WSManAuthenticationError) as e:
        async with psrp.AsyncRunspacePool(connection):
            pass

    assert e.value.http_code == 401
