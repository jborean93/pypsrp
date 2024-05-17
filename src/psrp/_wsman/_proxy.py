# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

import httpcore


class Proxy:
    """Base class for proxy implementations."""

    def __init__(
        self,
        url: str,
        connect_timeout: float | None,
    ) -> None:
        self.url = url
        self.parsed_url = httpcore.URL(url)
        self.connect_timeout = connect_timeout

    def copy(self) -> t.Self:
        """Creates a copy of the proxy for a new connection."""
        return self

    def wrap_stream_sync(
        self,
        stream: httpcore.NetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.NetworkStream:
        """Wraps the connection stream.

        Wraps the connection stream if required by the proxy. The returned
        stream is the one used for the connection interface to the target
        server.

        Args:
            stream: The stream to wrap.
            target: The target host the proxy should connect to.

        Returns:
            httpcore.NetworkStream: The wrapped network stream.
        """
        return stream

    async def wrap_stream_async(
        self,
        stream: httpcore.AsyncNetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.AsyncNetworkStream:
        """Wraps the connection stream.

        Wraps the connection stream if required by the proxy. The returned
        stream is the one used for the connection interface to the target
        server.

        Args:
            stream: The stream to wrap.
            target: The target host the proxy should connect to.

        Returns:
            httpcore.AsyncNetworkStream: The wrapped network stream.
        """
        return stream

    def create_connection_sync(
        self,
        stream: httpcore.NetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.ConnectionInterface:
        """Creates the proxy connection interface.

        Creates the underlying httpcore connection interface that the WSMan
        request writes to. The default implementation is to use the normal
        HTTP 1.1 connection interface.

        Args:
            stream: The stream connected to the proxy.
            target: The proxy target info.

        Returns:
            httpcore.ConnectionInterface: The proxied connection interface
        """
        return httpcore.HTTP11Connection(
            origin=target,
            stream=stream,
        )

    async def create_connection_async(
        self,
        stream: httpcore.AsyncNetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.AsyncConnectionInterface:
        """Creates the proxy connection interface.

        Creates the underlying httpcore connection interface that the WSMan
        request writes to. The default implementation is to use the normal
        HTTP 1.1 connection interface.

        Args:
            stream: The stream connected to the proxy.
            target: The proxy target info.

        Returns:
            httpcore.AsyncConnectionInterface: The proxied connection interface
        """
        return httpcore.AsyncHTTP11Connection(
            origin=target,
            stream=stream,
        )
