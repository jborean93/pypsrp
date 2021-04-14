# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing
import xml.etree.ElementTree as ElementTree

from psrp.io.wsman import (
    AsyncWSManConnection,
)

from psrp.protocol.wsman import (
    OptionSet,
    SelectorSet,
    WSMan,
)


class AsyncWSMan:

    def __init__(
            self,
            connection_uri,
    ):
        self._io = AsyncWSManConnection(connection_uri)
        self._wsman = WSMan(connection_uri)

    async def __aenter__(self):
        await self._io.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._io.close()

    async def create(
            self,
            resource_uri: str,
            resource: ElementTree.Element,
            option_set: typing.Optional[OptionSet] = None,
            selector_set: typing.Optional[SelectorSet] = None,
            timeout: typing.Optional[int] = None,
    ):
        self._wsman.create(resource_uri, resource, option_set=option_set, selector_set=selector_set, timeout=timeout)
        return await self._exchange_data()

    async def delete(
            self,
            resource_uri: str,
            resource: typing.Optional[ElementTree.Element] = None,
            option_set: typing.Optional[OptionSet] = None,
            selector_set: typing.Optional[SelectorSet] = None,
            timeout: typing.Optional[int] = None,
    ):
        self._wsman.delete(resource_uri, resource, option_set=option_set, selector_set=selector_set, timeout=timeout)
        return await self._exchange_data()

    async def _exchange_data(self):
        content = self._wsman.data_to_send()
        response = await self._io.send(content)

        event = self._wsman.receive_data(response)
        return event.body
