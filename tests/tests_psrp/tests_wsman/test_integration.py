# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import collections.abc
import json
import os
import pathlib
import subprocess
import typing as t

import pytest

import psrp

WSMAN_ENV_DIR = os.environ.get("PYPSRP_WSMAN_ENV_DIR", "~/dev/wsman-environment")


@pytest.fixture(scope="module")
def wsman_env() -> collections.abc.Iterator[dict]:
    if not WSMAN_ENV_DIR:
        pytest.skip("PYPSRP_WSMAN_ENV_DIR is not set")

    inventory_file = pathlib.Path(WSMAN_ENV_DIR).expanduser() / "build" / "inventory.yml"
    inventory_out = subprocess.run(
        ["ansible-inventory", "--list", "-i", str(inventory_file.absolute())],
        capture_output=True,
        check=False,
    )
    if inventory_out.returncode != 0:
        pytest.skip(f"Failed to run ansible-inventory (RC {inventory_out.returncode}): {inventory_out.stderr.decode()}")

    yield json.loads(inventory_out.stdout)["_meta"]["hostvars"]


def get_connection_info(
    host: str,
    inventory: dict,
) -> psrp.WSManInfo:
    host_var = inventory[host]
    build_dir = pathlib.Path(WSMAN_ENV_DIR).expanduser() / "build"
    kwargs: dict[str, t.Any] = {}

    auth = host_var.get("ansible_psrp_auth", "negotiate")
    scheme = host_var["ansible_psrp_protocol"]

    if scheme == "https":
        if host_var.get("ansible_psrp_cert_validation", None) == "ignore":
            kwargs["verify"] = False

        elif ca_cert := host_var.get("ansible_psrp_ca_cert", None):
            kwargs["verify"] = str((build_dir / ca_cert).absolute())

    username = host_var.get("ansible_user", None)
    password = host_var.get("ansible_password", None)

    if hostname_override := host_var.get("ansible_psrp_negotiate_hostname_override", None):
        kwargs["negotiate_hostname"] = hostname_override

    if auth == "certificate":
        kwargs["certificate_pem"] = str((build_dir / "client_auth.pem").absolute())
        kwargs["certificate_key_pem"] = str((build_dir / "client_auth.key").absolute())

    if encryption := host_var.get("ansible_psrp_message_encryption", None):
        kwargs["encryption"] = encryption

    proxy_url = host_var.get("ansible_psrp_proxy", None)
    if proxy_url:
        kwargs["proxy_url"] = proxy_url

        proxy_user = host_var.get("ansible_psrp_proxy_user", None)
        if proxy_user:
            kwargs["proxy_username"] = proxy_user
            kwargs["proxy_password"] = host_var["ansible_psrp_proxy_password"]

        if proxy_auth := host_var.get("ansible_psrp_proxy_auth", None):
            kwargs["proxy_auth"] = proxy_auth

        if proxy_ca := host_var.get("ansible_psrp_proxy_ca_cert", None):
            kwargs["proxy_ssl_verify"] = str((build_dir / proxy_ca).absolute())

    return psrp.WSManInfo(
        server=host_var["ansible_host"],
        port=host_var["ansible_port"],
        scheme=host_var["ansible_psrp_protocol"],
        path="wsman",
        auth=auth,
        username=username,
        password=password,
        **kwargs,
    )


def run_sync_test(
    conn_info: psrp.WSManInfo,
) -> None:
    with psrp.SyncRunspacePool(conn_info) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"foo"')
        actual = ps.invoke()

        assert actual == ["foo"]


async def run_async_test(
    conn_info: psrp.WSManInfo,
) -> None:
    async with psrp.AsyncRunspacePool(conn_info) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"foo"')
        actual = await ps.invoke()

        assert actual == ["foo"]


# We cannot test HTTP target with CredSSP auth when using a proxy as Squid only
# supports multi hop auth with NTLM, Negotiate, or Kerberos. This can be
# revisited if we use a different proxy server.
# https://github.com/squid-cache/squid/blob/45eabfa1155451024d2f574551bc939cd3ee1876/src/client_side_reply.cc#L1310-L1317
INTEGRATION_SCENARIOS = [
    # HTTP No proxy
    "http_basic_none_none",
    "http_kerberos_none_none",
    "http_negotiate_none_none",
    "http_ntlm_none_none",
    "http_credssp_none_none",
    # HTTPS No Proxy
    "https_basic_none_none",
    "https_kerberos_none_none",
    "https_negotiate_none_none",
    "https_ntlm_none_none",
    "https_credssp_none_none",
    # CBT
    "https_cbt_cbt_sha1",
    "https_cbt_cbt_sha256_pss",
    "https_cbt_cbt_sha384",
    "https_cbt_cbt_sha512",
    "https_cbt_cbt_sha512_pss",
    # HTTP over HTTP Proxy - No Auth
    "http_basic_http_none",
    "http_kerberos_http_none",
    "http_negotiate_http_none",
    "http_ntlm_http_none",
    # "http_credssp_http_none",
    # HTTP over HTTP Proxy - Basic Auth
    "http_basic_http_basic",
    "http_kerberos_http_basic",
    "http_negotiate_http_basic",
    "http_ntlm_http_basic",
    # "http_credssp_http_basic",
    # HTTP over HTTP Proxy - Kerberos Auth
    "http_basic_http_kerb",
    "http_kerberos_http_kerb",
    "http_negotiate_http_kerb",
    "http_ntlm_http_kerb",
    # "http_credssp_http_kerb",
    # HTTP over HTTPS Proxy - No Auth
    "http_basic_https_none",
    "http_kerberos_https_none",
    "http_negotiate_https_none",
    "http_ntlm_https_none",
    # "http_credssp_https_none",
    # HTTP over HTTPS Proxy - Basic Auth
    "http_basic_https_basic",
    "http_kerberos_https_basic",
    "http_negotiate_https_basic",
    "http_ntlm_https_basic",
    # "http_credssp_https_basic",
    # HTTP over HTTPS Proxy - Kerberos Auth
    "http_basic_https_kerb",
    "http_kerberos_https_kerb",
    "http_negotiate_https_kerb",
    "http_ntlm_https_kerb",
    # "http_credssp_https_kerb",
    # HTTP over socks5 Proxy - No Auth
    "http_basic_socks5_none",
    "http_kerberos_socks5_none",
    "http_negotiate_socks5_none",
    "http_ntlm_socks5_none",
    "http_credssp_socks5_none",
    # HTTP over socks5 Proxy - Basic Auth
    "http_basic_socks5_basic",
    "http_kerberos_socks5_basic",
    "http_negotiate_socks5_basic",
    "http_ntlm_socks5_basic",
    "http_credssp_socks5_basic",
    # HTTP over socks5h Proxy - No Auth
    "http_basic_socks5h_none",
    "http_kerberos_socks5h_none",
    "http_negotiate_socks5h_none",
    "http_ntlm_socks5h_none",
    "http_credssp_socks5h_none",
    # HTTP over socks5h Proxy - Basic Auth
    "http_basic_socks5h_basic",
    "http_kerberos_socks5h_basic",
    "http_negotiate_socks5h_basic",
    "http_ntlm_socks5h_basic",
    "http_credssp_socks5h_basic",
    # HTTPS over HTTP Proxy - No Auth
    "https_basic_http_none",
    "https_certificate_http_none",
    "https_kerberos_http_none",
    "https_negotiate_http_none",
    "https_ntlm_http_none",
    "https_credssp_http_none",
    # HTTPS over HTTP Proxy - Basic Auth
    "https_basic_http_basic",
    "https_certificate_http_basic",
    "https_kerberos_http_basic",
    "https_negotiate_http_basic",
    "https_ntlm_http_basic",
    "https_credssp_http_basic",
    # HTTPS over HTTP Proxy - Kerberos Auth
    "https_basic_http_kerb",
    "https_certificate_http_kerb",
    "https_kerberos_http_kerb",
    "https_negotiate_http_kerb",
    "https_ntlm_http_kerb",
    "https_credssp_http_kerb",
    # HTTPS over HTTPS Proxy - No Auth
    "https_basic_https_none",
    "https_certificate_https_none",
    "https_kerberos_https_none",
    "https_negotiate_https_none",
    "https_ntlm_https_none",
    "https_credssp_https_none",
    # HTTPS over HTTPS Proxy - Basic Auth
    "https_basic_https_basic",
    "https_certificate_https_basic",
    "https_kerberos_https_basic",
    "https_negotiate_https_basic",
    "https_ntlm_https_basic",
    "https_credssp_https_basic",
    # HTTPS over HTTPS Proxy - Kerberos Auth
    "https_basic_https_kerb",
    "https_certificate_https_kerb",
    "https_kerberos_https_kerb",
    "https_negotiate_https_kerb",
    "https_ntlm_https_kerb",
    "https_credssp_https_kerb",
    # HTTPS over socks5 Proxy - No Auth
    "https_basic_socks5_none",
    "https_certificate_socks5_none",
    "https_kerberos_socks5_none",
    "https_negotiate_socks5_none",
    "https_ntlm_socks5_none",
    "https_credssp_socks5_none",
    # HTTPS over socks5 Proxy - Basic Auth
    "https_basic_socks5_basic",
    "https_certificate_socks5_basic",
    "https_kerberos_socks5_basic",
    "https_negotiate_socks5_basic",
    "https_ntlm_socks5_basic",
    "https_credssp_socks5_basic",
    # HTTPS over socks5h Proxy - No Auth
    "https_basic_socks5h_none",
    "https_certificate_socks5h_none",
    "https_kerberos_socks5h_none",
    "https_negotiate_socks5h_none",
    "https_ntlm_socks5h_none",
    "https_credssp_socks5h_none",
    # HTTPS over socks5h Proxy - Basic Auth
    "https_basic_socks5h_basic",
    "https_certificate_socks5h_basic",
    "https_kerberos_socks5h_basic",
    "https_negotiate_socks5h_basic",
    "https_ntlm_socks5h_basic",
    "https_credssp_socks5h_basic",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("host_id", INTEGRATION_SCENARIOS)
async def test_async_wsman(
    host_id: str,
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info(host_id, wsman_env)
    async with psrp.AsyncRunspacePool(conn_info) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('"foo"')
        actual = await ps.invoke()

        assert actual == ["foo"]


@pytest.mark.parametrize("host_id", INTEGRATION_SCENARIOS)
def test_sync_wsman(
    host_id: str,
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info(host_id, wsman_env)
    with psrp.SyncRunspacePool(conn_info) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('"foo"')
        actual = ps.invoke()

        assert actual == ["foo"]
