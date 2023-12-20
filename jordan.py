from __future__ import annotations

import asyncio

import psrp
from psrp import _wsman as wsman


async def main(use_tls: bool = False) -> None:
    info = psrp.WSManInfo(
        "server2022.domain.test",
        scheme="https" if use_tls else "http",
        verify=False,
        username="vagrant-domain@DOMAIN.TEST",
        password="VagrantPass1",
        auth="kerberos",
    )

    async with psrp.AsyncRunspacePool(info) as rp:
        a = ""

    # shell = wsman.WinRS(wsman.WSManClient(info.connection_uri))
    # shell.open()
    # create_msg = shell.data_to_send()

    # async with info._new_async_connection() as conn:
    #     resp = await conn.wsman_post(create_msg)

    #     shell.receive_data(resp)
    #     shell.close()
    #     delete_msg = shell.data_to_send()

    #     resp = await conn.wsman_post(delete_msg)
    #     shell.receive_data(resp)


if __name__ == "__main__":
    asyncio.run(main())
