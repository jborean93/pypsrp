import logging
import re
import struct
import typing

from pypsrp._utils import to_bytes
from pypsrp.exceptions import WinRMError

log = logging.getLogger(__name__)


class WinRMEncryption(object):

    SIXTEEN_KB = 16384
    MIME_BOUNDARY = "--Encrypted Boundary"
    CREDSSP = "application/HTTP-CredSSP-session-encrypted"
    KERBEROS = "application/HTTP-Kerberos-session-encrypted"
    SPNEGO = "application/HTTP-SPNEGO-session-encrypted"

    def __init__(self, context: typing.Any, protocol: str) -> None:
        log.debug("Initialising WinRMEncryption helper for protocol %s" % protocol)
        self.context = context
        self.protocol = protocol

        self._wrap: typing.Callable[[bytes], typing.Tuple[bytes, int]]
        self._unwrap: typing.Callable[[bytes], bytes]
        if protocol == self.CREDSSP:
            self._wrap = self._wrap_credssp
            self._unwrap = self._unwrap_credssp
        else:
            self._wrap = self._wrap_spnego
            self._unwrap = self._unwrap_spnego

    def wrap_message(self, message: bytes) -> typing.Tuple[str, bytes]:
        log.debug("Wrapping message")
        if self.protocol == self.CREDSSP and len(message) > self.SIXTEEN_KB:
            content_type = "multipart/x-multi-encrypted"
            encrypted_msg = b""
            chunks = [message[i : i + self.SIXTEEN_KB] for i in range(0, len(message), self.SIXTEEN_KB)]
            for chunk in chunks:
                encrypted_chunk = self._wrap_message(chunk)
                encrypted_msg += encrypted_chunk
        else:
            content_type = "multipart/encrypted"
            encrypted_msg = self._wrap_message(message)

        encrypted_msg += to_bytes("%s--\r\n" % self.MIME_BOUNDARY)

        log.debug("Created wrapped message of content type %s" % content_type)
        return content_type, encrypted_msg

    def unwrap_message(self, message: bytes, boundary: str) -> bytes:
        log.debug("Unwrapped message")

        # Talking to Exchange endpoints gives a non-compliant boundary that has a space between the -- {boundary}, not
        # ideal but we just need to handle it.
        parts = re.compile(to_bytes(r"--\s*%s\r\n" % re.escape(boundary))).split(message)
        parts = list(filter(None, parts))

        message = b""
        for i in range(0, len(parts), 2):
            header = parts[i].strip()
            payload = parts[i + 1]

            expected_length = int(header.split(b"Length=")[1])

            # remove the end MIME block if it exists
            payload = re.sub(to_bytes(r"--\s*%s--\r\n$") % to_bytes(boundary), b"", payload)

            wrapped_data = payload.replace(b"\tContent-Type: application/octet-stream\r\n", b"")
            unwrapped_data = self._unwrap(wrapped_data)
            actual_length = len(unwrapped_data)

            log.debug("Actual unwrapped length: %d, expected unwrapped length: %d" % (actual_length, expected_length))
            if actual_length != expected_length:
                raise WinRMError(
                    "The encrypted length from the server does "
                    "not match the expected length, decryption "
                    "failed, actual: %d != expected: %d" % (actual_length, expected_length)
                )
            message += unwrapped_data

        return message

    def _wrap_message(self, message: bytes) -> bytes:
        wrapped_data, padding_length = self._wrap(message)
        msg_length = str(len(message) + padding_length)

        payload = "\r\n".join(
            [
                self.MIME_BOUNDARY,
                "\tContent-Type: %s" % self.protocol,
                "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%s" % msg_length,
                self.MIME_BOUNDARY,
                "\tContent-Type: application/octet-stream",
                "",
            ]
        )
        return to_bytes(payload) + wrapped_data

    def _wrap_spnego(self, data: bytes) -> typing.Tuple[bytes, int]:
        header, wrapped_data, padding_length = self.context.wrap_winrm(data)

        return struct.pack("<i", len(header)) + header + wrapped_data, padding_length

    def _wrap_credssp(self, data: bytes) -> typing.Tuple[bytes, int]:
        wrapped_data = self.context.wrap(data)
        cipher_negotiated = self.context.tls_connection.get_cipher_name()
        trailer_length = self._credssp_trailer(len(data), cipher_negotiated)

        return struct.pack("<i", trailer_length) + wrapped_data, 0

    def _unwrap_spnego(self, data: bytes) -> bytes:
        header_length = struct.unpack("<i", data[:4])[0]
        header = data[4 : 4 + header_length]
        wrapped_data = data[4 + header_length :]

        data = self.context.unwrap_winrm(header, wrapped_data)

        return data

    def _unwrap_credssp(self, data: bytes) -> bytes:
        wrapped_data = data[4:]
        data = self.context.unwrap(wrapped_data)

        return data

    def _credssp_trailer(
        self,
        msg_len: int,
        cipher_suite: str,
    ) -> int:
        # On Windows this is derived from SecPkgContext_StreamSizes, this is
        # not available on other platforms so we need to calculate it manually
        log.debug(
            "Attempting to get CredSSP trailer length for msg of length %d with cipher %s" % (msg_len, cipher_suite)
        )

        if re.match(r"^.*-GCM-[\w\d]*$", cipher_suite):
            # GCM has a fixed length of 16 bytes
            trailer_length = 16
        else:
            # For other cipher suites, trailer size == len(hmac) + len(padding)
            # the padding it the length required by the chosen block cipher
            hash_algorithm = cipher_suite.split("-")[-1]

            # while there are other algorithms, SChannel doesn't support them
            # as of yet so we just keep to this list
            hash_length = {"MD5": 16, "SHA": 20, "SHA256": 32, "SHA384": 48}.get(hash_algorithm, 0)

            pre_pad_length = msg_len + hash_length
            if "RC4" in cipher_suite:
                # RC4 is a stream cipher so no padding would be added
                padding_length = 0
            elif "DES" in cipher_suite or "3DES" in cipher_suite:
                # 3DES is a 64 bit block cipher
                padding_length = 8 - (pre_pad_length % 8)
            else:
                # AES is a 128 bit block cipher
                padding_length = 16 - (pre_pad_length % 16)

            trailer_length = (pre_pad_length + padding_length) - msg_len

        return trailer_length
