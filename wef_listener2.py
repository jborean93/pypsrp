from __future__ import annotations

import asyncio
import datetime
import email.utils
import pathlib
import socket
import ssl
import traceback
import typing as t

import anyio
import anyio.streams
import anyio.streams.tls
import h11

from psrp._wsman import WSManClient


class EmptyByteArray(bytearray):

    def __bool__(self) -> bool:
        return True


class HTTPProtocol(asyncio.Protocol):

    def __init__(self) -> None:
        self.transport = None
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._ssl = create_tls_context().wrap_bio(self._in, self._out, server_side=True)
        self._first = True
        self._doing_auth = False
        self._http = h11.Connection(h11.SERVER)

    def connection_lost(
        self,
        exc: Exception | None,
    ) -> None:
        print(f"connection_lost {exc!r}")
        return super().connection_lost(exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        print("connection_made")
        self.transport = transport
        return super().connection_made(transport)

    def data_received(self, data: bytes) -> None:
        print(f"data_received: {data!r}")
        # ssl_obj: ssl.SSLObject = self.transport.get_extra_info("ssl_object")

        self._in.write(data)

        if self._first:
            try:
                self._ssl.do_handshake()
            except ssl.SSLWantReadError:
                pass
            else:
                self._first = False

            out_data = self._out.read()
            self.transport.write(out_data)

        elif self._doing_auth:
            self._doing_auth = False

            try:
                self._ssl.read()
            except ssl.SSLWantReadError:
                pass

            out_data = self._out.read()
            self.transport.write(out_data)

            # Need to send HTTP response here.
            client_cert = self._ssl.getpeercert(binary_form=False)
            print(f"Client Cert: {client_cert}")

            body = b""
            dt = datetime.datetime.now(datetime.timezone.utc)
            formatted_date = email.utils.format_datetime(dt, usegmt=True)
            headers = [
                (b"Date", formatted_date.encode("ascii")),
                (b"Server", b"WEFServerTest"),
                (b"Content-Type", b"application/soap+xml;charset=UTF-8"),
                (b"Content-Length", str(len(body)).encode()),
            ]
            res = h11.Response(status_code=401, headers=headers)
            data_to_send = b"".join(
                [
                    self._http.send(res) or b"",
                    self._http.send(h11.Data(data=body)) or b"",
                    self._http.send(h11.EndOfMessage()) or b"",
                ]
            )
            self.transport.write(data_to_send)
            self.transport.close()

        else:
            buffer = []
            while True:
                try:
                    dec_data = self._ssl.read()
                except ssl.SSLWantReadError:
                    break
                else:
                    buffer.append(dec_data)

            dec_data = b"".join(buffer)
            print(f"dec data: {dec_data!r}")
            self._http.receive_data(dec_data)

            while (http_event := self._http.next_event()) != h11.NEED_DATA:
                print(http_event)

            self._doing_auth = True
            self._ssl.verify_client_post_handshake()
            # Needed to populate the output buffer
            try:
                self._ssl.read()
            except ssl.SSLWantReadError:
                pass

            handshake_req = self._out.read()
            self.transport.write(handshake_req)

    def eof_received(self) -> bool | None:
        print(f"eof_received")
        return super().eof_received()

    async def _process_out(self):
        buf = self._out.read()
        self.transport.write(buf)
        # await self.writer.drain()

    async def _process_in(self):
        buf = await self.reader.read(self.MAX_RECV)
        if buf:
            self._ssl_in.write(buf)
        else:
            self._ssl_in.write_eof()

    async def _process(self, read, func, *args, **kwargs):
        while True:
            try:
                return func(*args, **kwargs)
            except ssl.SSLWantReadError:
                await self._process_out()
                await self._process_in()
            except ssl.SSLWantWriteError:
                await self._process_in()
                await self._process_out()


async def main() -> None:
    loop = asyncio.get_event_loop()

    server = await loop.create_server(
        lambda: HTTPProtocol(),
        host="",
        port=5986,
        # ssl=create_tls_context(),
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


if __name__ == "__main__":
    asyncio.run(main())
