# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re
import struct
import typing

BOUNDARY_PATTERN = re.compile('boundary=[''|\\"](.*)[''|\\"]')


def decrypt_wsman(
        data: bytearray,
        content_type: str,
        context,
) -> typing.Tuple[bytes, str]:
    boundary = BOUNDARY_PATTERN.search(content_type).group(1)
    # Talking to Exchange endpoints gives a non-compliant boundary that has a space between the --boundary.
    # not ideal but we just need to handle it.
    parts = re.compile((r'--\s*%s\r\n' % re.escape(boundary)).encode()).split(data)
    parts = list(filter(None, parts))
    content_type = ''

    content = []
    for i in range(0, len(parts), 2):
        header = parts[i].strip()
        payload = parts[i + 1]

        expected_length = int(header.split(b'Length=')[1])

        # remove the end MIME block if it exists
        payload = re.sub((r'--\s*%s--\r\n$' % boundary).encode(), b'', payload)

        wrapped_data = payload.replace(b'\tContent-Type: application/octet-stream\r\n', b'')

        header_length = struct.unpack('<i', wrapped_data[:4])[0]
        b_header = wrapped_data[4:4 + header_length]
        b_enc_data = wrapped_data[4 + header_length:]
        unwrapped_data = context.unwrap_winrm(b_header, b_enc_data)
        actual_length = len(unwrapped_data)

        if actual_length != expected_length:
            raise Exception(f'The encrypted length from the server does not match the expected length, '
                            f'decryption failed, actual: {actual_length} != expected: {expected_length}')
        content.append(unwrapped_data)

    return b''.join(content), content_type


def encrypt_wsman(
        data: bytearray,
        content_type: str,
        encryption_type: str,
        context,
) -> typing.Tuple[bytes, str]:
    boundary = 'Encrypted Boundary'

    # If using CredSSP we must encrypt in 16KiB chunks.
    max_size = 16384 if 'CredSSP' in encryption_type else len(data)
    chunks = [data[i:i + max_size] for i in range(0, len(data), max_size)]

    encrypted_chunks = []
    for chunk in chunks:
        enc_details = context.wrap_winrm(bytes(chunk))
        padding_length = enc_details.padding_length
        wrapped_data = struct.pack('<i', len(enc_details.header)) + enc_details.header + enc_details.data
        chunk_length = str(len(chunk) + padding_length)

        content = "\r\n".join([
            f'--{boundary}',
            f'\tContent-Type: {encryption_type}',
            f'\tOriginalContent: type={content_type};Length={chunk_length}',
            f'--{boundary}',
            '\tContent-Type: application/octet-stream',
            '',
        ])
        encrypted_chunks.append(content.encode() + wrapped_data)

    content_sub_type = 'multipart/encrypted' if len(encrypted_chunks) == 1 else 'multipart/x-multi-encrypted'
    content_type = f'{content_sub_type};protocol="{encryption_type}";boundary="{boundary}"'
    data = b"".join(encrypted_chunks) + f'--{boundary}--\r\n'.encode()

    return data, content_type
