from __future__ import annotations

import asyncio
import collections.abc
import datetime
import email.utils
import pathlib
import socket
import ssl
import traceback
import typing as t

import anyio.streams.tls
import h11

from psrp._wsman import WSManClient

TRes = t.TypeVar("TRes")


class EndOfStream(Exception): ...


class AsyncStream(t.Protocol):
    async def close(self) -> None: ...
    async def read(self) -> bytes: ...
    async def write(
        self,
        data: bytearray | bytes | memoryview,
    ) -> None: ...


class PlainStream(AsyncStream):

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.reader = reader
        self.writer = writer

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()

    async def read(self) -> bytes:
        data = await self.reader.read(16_348)
        if not data and self.reader.at_eof():
            raise EndOfStream()
        return data

    async def write(
        self,
        data: bytearray | bytes | memoryview,
    ) -> None:
        self.writer.write(data)
        await self.writer.drain()


class TLSStream(AsyncStream):
    def __init__(
        self,
        stream: AsyncStream,
        ssl_obj: ssl.SSLObject,
        ssl_in: ssl.MemoryBIO,
        ssl_out: ssl.MemoryBIO,
    ) -> None:
        self.stream = stream
        self.ssl_in = ssl_in
        self.ssl_out = ssl_out
        self.ssl_obj = ssl_obj

    @classmethod
    async def wrap_stream(
        cls,
        stream: AsyncStream,
        ssl_context: ssl.SSLContext,
    ) -> TLSStream:
        ssl_in = ssl.MemoryBIO()
        ssl_out = ssl.MemoryBIO()
        ssl_obj = ssl_context.wrap_bio(
            ssl_in,
            ssl_out,
            server_side=True,
        )

        new_stream = TLSStream(stream, ssl_obj, ssl_in, ssl_out)
        await new_stream._wrap_ssl_call(ssl_obj.do_handshake)

        return new_stream

    async def close(self) -> None:
        await self.stream.close()

    async def read(self) -> bytes:
        return await self._wrap_ssl_call(self.ssl_obj.read)

    async def write(
        self,
        data: bytearray | bytes | memoryview,
    ) -> None:
        await self._wrap_ssl_call(self.ssl_obj.write, data)

    async def verify_client_post_handshake(self) -> t.Any:
        self.ssl_obj.verify_client_post_handshake()
        try:
            self.ssl_obj.read()
        except ssl.SSLWantReadError:
            pass
        await self.stream.write(self.ssl_out.read())

        self.ssl_in.write(await self.stream.read())
        try:
            self.ssl_obj.read()
        except ssl.SSLWantReadError:
            pass
        await self.stream.write(self.ssl_out.read())

        return self.ssl_obj.getpeercert(binary_form=False)

    async def _wrap_ssl_call(
        self,
        func: collections.abc.Callable[..., TRes],
        *args: t.Any,
    ) -> TRes:
        while True:
            try:
                result = func(*args)
            except ssl.SSLWantReadError:
                if self.ssl_out.pending:
                    await self.stream.write(self.ssl_out.read())

                data = await self.stream.read()
                self.ssl_in.write(data)
            except ssl.SSLWantWriteError:
                await self.stream.write(self.ssl_out.read())

            else:
                # Flush any pending writes first
                if self.ssl_out.pending:
                    await self.stream.write(self.ssl_out.read())

                return result


class AsyncioHTTPServer:
    MAX_RECV = 16_348

    def __init__(
        self,
        stream: AsyncStream,
    ) -> None:
        self.stream = stream
        self.http = h11.Connection(h11.SERVER)

    async def send(
        self,
        event: h11.Event,
    ) -> None:
        data = self.http.send(event)
        if not data:
            return

        try:
            await self.stream.write(data)
        except BaseException:
            self.http.send_failed()
            raise

    async def _read_from_peer(self) -> None:
        if self.http.they_are_waiting_for_100_continue:
            go_ahead = h11.InformationalResponse(
                status_code=100,
                headers=self.basic_headers(),
            )
            await self.send(go_ahead)

        try:
            data = await self.stream.read()
        except ConnectionError:
            # They've stopped listening. Not much we can do about it here.
            data = b""
        self.http.receive_data(data)

    async def next_event(self) -> h11.Event:
        while True:
            event = self.http.next_event()
            if event is h11.NEED_DATA:
                await self._read_from_peer()
                continue
            return event

    def basic_headers(self) -> list[tuple[bytes, bytes]]:
        # HTTP requires these headers in all responses (client would do
        # something different here)
        dt = datetime.datetime.now(datetime.timezone.utc)
        formatted_date = email.utils.format_datetime(dt, usegmt=True)
        return [
            (b"Date", formatted_date.encode("ascii")),
            (b"Server", b"WEFServerTest"),
        ]


async def main() -> None:
    ssl_context = create_tls_context()

    server = await asyncio.start_server(
        lambda r, w: serve_client(r, w, ssl_context),
        host="",
        port=5986,
    )

    async with server:
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        print(f"Started server on {addrs}")
        await server.serve_forever()
        print("Stopping server")


def create_tls_context() -> ssl.SSLContext:
    ca_file = pathlib.Path(__file__).parent / "wef" / "ca.pem"
    cert_file = pathlib.Path(__file__).parent / "wef" / "server.pem"
    keyfile = pathlib.Path(__file__).parent / "wef" / "server.key"
    cert_pass = "password"

    tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    tls.load_verify_locations(cafile=str(ca_file.absolute()))
    tls.load_cert_chain(
        certfile=str(cert_file.absolute()),
        keyfile=str(keyfile.absolute()),
        password=cert_pass,
    )
    tls.verify_mode = ssl.CERT_OPTIONAL
    tls.post_handshake_auth = True
    tls.keylog_filename = "/tmp/ssl.log"

    return tls


async def serve_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_context: ssl.SSLContext | None,
) -> None:
    """
    <QueryList>
      <Query Id="0" Path="Application">
        <Select Path="Application">*[System[Provider[@Name='Ansible']]]</Select>
      </Query>
    </QueryList>

    # Server URL
    Server=https://jborean-laptop:5986/,Refresh=10,IssuerCA=8A37EA3B2AF0A287F1A77839C0CE985ACEF52357

    Server=https://win-server:5986/wsman/SubscriptionManager/WEC,Refresh=10,IssuerCA=8A37EA3B2AF0A287F1A77839C0CE985ACEF52357

    winrm get winrm/config -r:https://jborean-laptop:5986 -a:certificate -certificate:06921F26981F0E5D39C91A627874909AD5210EF0 -encoding:utf-8

    winrm get winrm/config -r:https://win-server:5986 -a:certificate -certificate:A29DCAEE666F2C059D33E344C91BFB626F522602 -encoding:utf-8
    """
    print("Client connected")
    asyncio.StreamReader
    try:
        stream: AsyncStream = PlainStream(reader, writer)
        if ssl_context:
            stream = await TLSStream.wrap_stream(stream, ssl_context)

        server = AsyncioHTTPServer(stream)
        while True:
            try:
                event = await server.next_event()

                if isinstance(event, h11.Request):
                    request_data = await server.next_event()
                    request_eof = await server.next_event()

                    if has_cert_auth_header(event) and isinstance(stream, TLSStream):
                        peer_cert = await stream.verify_client_post_handshake()

                    await send_http_response(
                        server,
                        status_code=401,
                        content_type=None,
                        body=b"",
                        extra_headers=[
                            (b"Connection", b"close"),
                            (
                                b"WWW-Authenticate",
                                b"http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual",
                            ),
                        ],
                    )
                    break

            except EndOfStream:
                raise

            except Exception as e:
                traceback.print_exc()
                await maybe_send_error_response(server, e)

            if server.http.our_state is h11.MUST_CLOSE:
                break

            try:
                server.http.start_next_cycle()
            except Exception as e:
                traceback.print_exc()
                await maybe_send_error_response(server, e)

        await stream.close()

    except EndOfStream:
        print("Client disconnected")
        return

    finally:
        writer.close()


def has_cert_auth_header(
    request: h11.Request,
) -> bool:
    for name, value in request.headers:
        if name == b"authorization":
            return value == b"http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

    return False


async def send_http_response(
    server: AsyncioHTTPServer,
    status_code: int,
    content_type: bytes | None,
    body: bytes,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    headers = server.basic_headers()
    if content_type:
        headers.append((b"Content-Type", content_type))
    headers.append((b"Content-Length", str(len(body)).encode()))
    if extra_headers:
        headers.extend(extra_headers)

    res = h11.Response(status_code=status_code, headers=headers)
    await server.send(res)
    await server.send(h11.Data(data=body))
    await server.send(h11.EndOfMessage())


async def maybe_send_error_response(
    server: AsyncioHTTPServer,
    exc: Exception,
) -> None:
    if server.http.our_state not in {h11.IDLE, h11.SEND_RESPONSE}:
        return

    try:
        if isinstance(exc, h11.RemoteProtocolError):
            status_code = exc.error_status_hint
        else:
            status_code = 500

        body = str(exc).encode("utf-8")
        await send_http_response(
            server,
            status_code,
            b"text/plain; charset=utf-8",
            body,
        )
    except Exception as exc:
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
