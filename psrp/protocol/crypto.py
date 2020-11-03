# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import abc
import struct
import typing

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding,
)

from cryptography.hazmat.primitives.ciphers import (
    algorithms,
    Cipher,
    modes,
)

from cryptography.hazmat.primitives.padding import (
    PKCS7,
)


def create_keypair() -> typing.Tuple[rsa.RSAPrivateKey, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_numbers = private_key.public_key().public_numbers()
    exponent = struct.pack("<I", public_numbers.e)

    b_modulus = bytearray()
    modulus = public_numbers.n
    while modulus:
        val = modulus & 0xFF
        b_modulus.append(val)
        modulus >>= 8

    # The public key bytes follow a set structure defined in MS-PSRP.
    public_key_bytes = b'\x06\x02\x00\x00\x00\xa4\x00\x00' \
                       b'\x52\x53\x41\x31\x00\x08\x00\x00' + \
                       exponent + bytes(b_modulus)

    return private_key, public_key_bytes


def encrypt_session_key(
        exchange_key: bytes,
        session_key: bytes,
) -> bytes:
    # Exchange key contains header information used by MS Crypto but we don't use them here.
    exponent = struct.unpack("<I", exchange_key[16:20])[0]
    b_modulus = exchange_key[20:]
    shift = 0
    modulus = 0
    for b in b_modulus:
        modulus += b << (8 * shift)
        shift += 1

    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())

    encrypted_key = public_key.encrypt(
        session_key,
        padding.PKCS1v15(),
    )[::-1]
    encrypted_key_bytes = b'\x01\x02\x00\x00\x10\x66\x00\x00' \
                          b'\x00\xa4\x00\x00' + \
                          encrypted_key

    return encrypted_key_bytes


def decrypt_session_key(
        exchange_key: rsa.RSAPrivateKey,
        encrypted_session_key: bytes,
):
    # Strip off Win32 Crypto Blob Header and reverse the bytes.
    encrypted_key = encrypted_session_key[12:][::-1]
    decrypted_key = exchange_key.decrypt(encrypted_key, padding.PKCS1v15())
    
    return decrypted_key


class CryptoProvider(metaclass=abc.ABCMeta):
    """Base class for a CryptoProvider.

    The CryptoProvider implementation must provide a way to encrypt and decrypt bytes using the key provided.

    Args:
        key: The session key negotiated between the client and server.
    """

    def __init__(
            self,
            key: bytes,
    ):
        self.key = key

    @abc.abstractmethod
    def decrypt(
            self,
            value: bytes
    ) -> bytes:
        """Decrypts the encrypted bytes.

        Decrypts the encrypted bytes passed in.

        Args:
            value: The encrypted bytes to decrypt.

        Returns:
            (bytes): The decrypted bytes.
        """
        pass  # pragma: no cover

    @abc.abstractmethod
    def encrypt(
            self,
            value: bytes,
    ) -> bytes:
        """Encrypted the bytes.

        Encrypted the bytes passed in.

        Args:
            value: The bytes to encrypt.

        Returns:
            (bytes): The encrypted bytes.
        """
        pass  # pragma: no cover


class PSRemotingCrypto(CryptoProvider):

    def __init__(
            self,
            key: bytes,
    ):
        super().__init__(key)

        algorithm = algorithms.AES(key)
        mode = modes.CBC(b"\x00" * 16)  # PSRP doesn't use an IV
        self._cipher = Cipher(algorithm, mode, default_backend())
        self._padding = PKCS7(algorithm.block_size)

    def decrypt(
            self,
            value: bytes
    ) -> bytes:
        decryptor = self._cipher.decryptor()
        b_dec = decryptor.update(value) + decryptor.finalize()

        unpadder = self._padding.unpadder()
        plaintext = unpadder.update(b_dec) + unpadder.finalize()

        return plaintext

    def encrypt(
            self,
            value: bytes
    ) -> bytes:
        padder = self._padding.padder()
        b_padded = padder.update(value) + padder.finalize()

        encryptor = self._cipher.encryptor()
        b_enc = encryptor.update(b_padded) + encryptor.finalize()

        return b_enc
