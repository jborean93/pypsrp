from __future__ import annotations

import pathlib
import socket
import ssl


def create_tls_context() -> ssl.SSLContext:
    ca_file = pathlib.Path(__file__).parent / "wef" / "ca.pem"
    cert_file = pathlib.Path(__file__).parent / "wef" / "client.pem"
    keyfile = pathlib.Path(__file__).parent / "wef" / "client.key"
    cert_pass = "password"

    tls = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    tls.load_verify_locations(cafile=str(ca_file.absolute()))
    tls.load_cert_chain(
        certfile=str(cert_file.absolute()),
        keyfile=str(keyfile.absolute()),
        password=cert_pass,
    )
    tls.verify_mode = ssl.CERT_OPTIONAL
    tls.post_handshake_auth = True
    # tls.keylog_filename = "/tmp/ssl.log"

    return tls


def main() -> None:
    with open("/tmp/sock", mode="rb") as fd:
        port = int(fd.read().decode())

    tls = create_tls_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))

        with tls.wrap_socket(s, server_hostname="jborean-laptop") as tls_s:
            tls_s.sendall(b"Hello, world")
            data = tls_s.recv(1024)
            print(data)
            tls_s.recv()
            tls_s.write(b"")


class MyBA(bytearray):
    def __bool__(self) -> bool:
        return True


if __name__ == "__main__":
    main()
