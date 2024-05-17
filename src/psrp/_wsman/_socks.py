# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import collections.abc
import socket

import anyio
import httpcore
from socksio import socks5

from ._auth import AuthProvider, BasicAuth
from ._exceptions import WSManAuthenticationError, WSManHTTPError
from ._proxy import Proxy

# https://datatracker.ietf.org/doc/html/rfc1928
AUTH_METHODS = {
    b"\x00": "NO AUTHENTICATION REQUIRED",
    b"\x01": "GSSAPI",
    b"\x02": "USERNAME/PASSWORD",
    b"\xff": "NO ACCEPTABLE METHODS",
}

REPLY_CODES = {
    b"\x00": "Succeeded",
    b"\x01": "General SOCKS server failure",
    b"\x02": "Connection not allowed by ruleset",
    b"\x03": "Network unreachable",
    b"\x04": "Host unreachable",
    b"\x05": "Connection refused",
    b"\x06": "TTL expired",
    b"\x07": "Command not supported",
    b"\x08": "Address type not supported",
}


def _validate_addr_response(
    hostname: str,
    infos: list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]],
) -> bytes:
    """Validates the response from getaddrinfo and returns the resolved address."""
    if not infos:
        raise OSError(f"Failed to resolve host for SOCKS5 target {hostname}")

    _, _, _, _, address = sorted(infos, key=lambda info: info[0])[0]
    return address[0].encode("ascii")


class SOCKS5Proxy(Proxy):
    """SOCKS5 Proxy.

    This is a SOCK5 proxy implementation. This implementation supports either
    no authentication or username/password authentication through the BasicAuth
    provider.

    Both the socks5:// and socks5h:// schemes are supported. The socks5h://
    scheme will have the SOCKS server resolve the target host, while the
    socks5:// scheme will resolve the target host IP locally.

    Args:
        url: The SOCKS5 URL.
        connect_timeout: The time, in seconds, to wait for the connection to
            complete.
        auth_provider: The authentication provider to use.
    """

    def __init__(
        self,
        url: str,
        connect_timeout: float | None = None,
        *,
        auth_provider: AuthProvider | None = None,
    ) -> None:
        self.resolve_target = True
        if url.lower().startswith("socks5h://"):
            url = f"socks5://{url[10:]}"
            self.resolve_target = False

        super().__init__(url, connect_timeout)

        if auth_provider is None:
            self.auth_method = socks5.SOCKS5AuthMethod.NO_AUTH_REQUIRED
            self.auth_data = None

        elif isinstance(auth_provider, BasicAuth):
            self.auth_method = socks5.SOCKS5AuthMethod.USERNAME_PASSWORD
            self.auth_data = socks5.SOCKS5UsernamePasswordRequest(
                username=auth_provider.username.encode(),
                password=auth_provider.password.encode(),
            )

        else:
            raise ValueError("Unsupported auth provider for SOCKS5 proxy, only BasicAuth is supported.")

    async def wrap_stream_async(
        self,
        stream: httpcore.AsyncNetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.AsyncNetworkStream:
        remote_target = target.host
        if self.resolve_target:
            infos = await anyio.getaddrinfo(
                host=target.host,
                port=target.port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            remote_target = _validate_addr_response(
                f"{target.host.decode()}:{target.port}",
                infos,
            )

        socks5_gen = self._socks5_generator(remote_target, target.port)
        outgoing_bytes = next(socks5_gen)
        while True:
            try:
                await stream.write(outgoing_bytes)
                incoming_bytes = await stream.read(max_bytes=4096)
                outgoing_bytes = socks5_gen.send(incoming_bytes)
            except StopIteration:
                break

        return stream

    def wrap_stream_sync(
        self,
        stream: httpcore.NetworkStream,
        target: httpcore.Origin,
    ) -> httpcore.NetworkStream:
        remote_target = target.host
        if self.resolve_target:
            infos = socket.getaddrinfo(
                host=target.host,
                port=target.port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            remote_target = _validate_addr_response(
                f"{target.host.decode()}:{target.port}",
                infos,  # type: ignore[arg-type]
            )

        socks5_gen = self._socks5_generator(remote_target, target.port)
        outgoing_bytes = next(socks5_gen)
        while True:
            try:
                stream.write(outgoing_bytes)
                incoming_bytes = stream.read(max_bytes=4096)
                outgoing_bytes = socks5_gen.send(incoming_bytes)
            except StopIteration:
                break

        return stream

    def _socks5_generator(
        self,
        target: str | bytes,
        port: int,
    ) -> collections.abc.Generator[bytes, bytes, None]:
        conn = socks5.SOCKS5Connection()

        target_info = socks5.SOCKS5CommandRequest.from_address(
            socks5.SOCKS5Command.CONNECT,
            (target, port),
        )

        conn.send(socks5.SOCKS5AuthMethodsRequest([self.auth_method]))
        incoming_bytes = yield conn.data_to_send()
        response = conn.receive_data(incoming_bytes)
        assert isinstance(response, socks5.SOCKS5AuthReply)
        if response.method != self.auth_method:
            requested = AUTH_METHODS.get(self.auth_method, "UNKNOWN")
            responded = AUTH_METHODS.get(response.method, "UNKNOWN")
            raise WSManHTTPError(500, msg=f"Requested auth method {requested} from SOCKS5 Server, but got {responded}.")

        if self.auth_data:
            conn.send(self.auth_data)
            incoming_bytes = yield conn.data_to_send()
            response = conn.receive_data(incoming_bytes)
            if not (isinstance(response, socks5.SOCKS5UsernamePasswordReply) and response.success):
                raise WSManAuthenticationError(401, msg="SOCKS5 Proxy authentication failed.")

        conn.send(target_info)
        incoming_bytes = yield conn.data_to_send()
        response = conn.receive_data(incoming_bytes)
        assert isinstance(response, socks5.SOCKS5Reply)
        if response.reply_code != socks5.SOCKS5ReplyCode.SUCCEEDED:
            reply_code = REPLY_CODES.get(response.reply_code, "UNKNOWN")
            raise WSManHTTPError(500, msg=f"SOCKS5 Proxy Server could not connect: {reply_code}.")
