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

    inventory_file = pathlib.Path(WSMAN_ENV_DIR).expanduser() / "build" / "inventory.ini"
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
    **kwargs: t.Any,
) -> psrp.WSManInfo:
    host_var = inventory[host]
    build_dir = pathlib.Path(WSMAN_ENV_DIR).expanduser() / "build"

    auth = host_var.get("ansible_psrp_auth", "negotiate")
    scheme = host_var["ansible_psrp_protocol"]

    if scheme == "https" and "verify" not in kwargs:
        kwargs["verify"] = str((build_dir / "ca.pem").absolute())

    username = host_var.get("ansible_user", None)
    password = host_var.get("ansible_password", None)
    if auth == "certificate":
        kwargs["certificate_pem"] = str((build_dir / "client_auth.pem").absolute())
        kwargs["certificate_key_pem"] = str((build_dir / "client_auth.key").absolute())

    proxy_url = host_var.get("ansible_psrp_proxy", None)
    if proxy_url:
        kwargs["proxy"] = proxy_url

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


# region HTTP No Proxy


@pytest.mark.asyncio
async def test_async_wsman_http_basic_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_none_none", wsman_env, encryption="never")
    await run_async_test(conn_info)


def test_sync_wsman_http_basic_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_none_none", wsman_env, encryption="never")
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_http_nego_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_nego_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_http_nego_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_nego_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_http_ntlm_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_ntlm_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_http_ntlm_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_ntlm_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_http_kerb_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_kerb_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_http_kerb_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_kerb_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_http_credssp_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_credssp_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_http_credssp_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_credssp_none_none", wsman_env)
    run_sync_test(conn_info)


# endregion HTTP No Proxy

# region HTTPS No Proxy


@pytest.mark.asyncio
async def test_async_wsman_https_basic_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_basic_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_https_basic_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_basic_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_https_cert_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cert_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_https_cert_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cert_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_https_nego_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_nego_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_https_nego_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_nego_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_https_ntlm_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_ntlm_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_https_ntlm_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_ntlm_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_https_kerb_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_kerb_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_https_kerb_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_kerb_none_none", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_https_credssp_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_credssp_none_none", wsman_env)
    await run_async_test(conn_info)


def test_sync_wsman_https_credssp_none_none(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_credssp_none_none", wsman_env)
    run_sync_test(conn_info)


# endregion HTTPS No Proxy

# region HTTPS Channel Binding Token


@pytest.mark.asyncio
async def test_async_https_cbt_sha1(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha1", wsman_env, verify=False)
    await run_async_test(conn_info)


def test_sync_https_cbt_sha1(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha1", wsman_env, verify=False)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_https_cbt_sha256_pss(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha256_pss", wsman_env)
    await run_async_test(conn_info)


def test_sync_https_cbt_sha256_pss(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha256_pss", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_https_cbt_sha384(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha384", wsman_env)
    await run_async_test(conn_info)


def test_sync_https_cbt_sha384(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha384", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_https_cbt_sha512(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha512", wsman_env)
    await run_async_test(conn_info)


def test_sync_https_cbt_sha512(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha512", wsman_env)
    run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_https_cbt_sha512_pss(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha512_pss", wsman_env)
    await run_async_test(conn_info)


def test_sync_https_cbt_sha512_pss(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("https_cbt_cbt_sha512_pss", wsman_env)
    run_sync_test(conn_info)


# endregion HTTPS CHannel Binding Token

# region HTTP over HTTP Proxy


@pytest.mark.asyncio
async def test_async_wsman_http_basic_http_anon(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_http_anon", wsman_env, encryption="never")
    await run_async_test(conn_info)


def test_sync_wsman_http_basic_http_anon(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_http_anon", wsman_env, encryption="never")
    # run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_http_basic_http_basic(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_http_basic", wsman_env, encryption="never")
    # await run_async_test(conn_info)


def test_sync_wsman_http_basic_http_basic(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_http_basic", wsman_env, encryption="never")
    # run_sync_test(conn_info)


@pytest.mark.asyncio
async def test_async_wsman_http_basic_http_kerb(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_http_kerb", wsman_env, encryption="never")
    # await run_async_test(conn_info)


def test_sync_wsman_http_basic_http_kerb(
    wsman_env: dict,
) -> None:
    conn_info = get_connection_info("http_basic_http_kerb", wsman_env, encryption="never")
    # run_sync_test(conn_info)


# endregion HTTP over HTTP Proxy

# region HTTP over HTTPS Proxy

# endregion HTTP over HTTPS Proxy

# region HTTP over SOCKS Proxy

# endregion HTTP over SOCKS Proxy

# region HTTPS over HTTP Proxy

# endregion HTTPS over HTTP Proxy

# region HTTPS over HTTPS Proxy

# endregion HTTPS over HTTPS Proxy

# region HTTPS over SOCKS Proxy

# endregion HTTPS over SOCKS Proxy
