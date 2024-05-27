from __future__ import annotations

import pathlib
import socket
import ssl


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


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen()
        sock_name = s.getsockname()
        with open("/tmp/sock", mode="wb") as fd:
            fd.write(str(sock_name[1]).encode())

        print(f"Listening on {sock_name}")

        tls = create_tls_context()
        with tls.wrap_socket(s, server_side=True) as tls_sock:
            conn, addr = tls_sock.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024)
                print(data)
                conn.sendall(data)

                conn.verify_client_post_handshake()
                conn.write(b"")
                conn.read()
                client_cert = conn.getpeercert()

                print(f"Client cert - {client_cert}")


if __name__ == "__main__":
    main()
