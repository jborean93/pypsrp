# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import threading
import typing

HAS_SSH = True
try:
    import asyncssh
except ImportError:
    HAS_SSH = False


if HAS_SSH:
    class _ClientSession(asyncssh.SSHClientSession):

        def __init__(self):
            self.data = asyncio.Queue()
            self._buffer = bytearray()

        def data_received(self, data, datatype):
            start_idx = len(self._buffer)
            self._buffer += data

            try:
                idx = data.index(b'\r\n')
            except ValueError:
                return

            entry = self._buffer[:start_idx + idx]
            self.data.put_nowait(entry)
            self._buffer = self._buffer[start_idx + idx + 2:]
            
else:
    class _ClientSession:
        pass


class SSH:

    def __init__(
            self,
    ):
        if not HAS_SSH:
            raise ImportError('Requires ssh library')

        self._write_lock = threading.Lock()
        self._ssh = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        pass

    def open(self):
        pass

    def read(self):
        pass

    def write(self, data):
        with self._write_lock:
            pass


class AsyncSSH(SSH):

    def __init__(
            self,
            hostname: str,
            port: int = 22,
            username: typing.Optional[str] = None,
            password: typing.Optional[str] = None,
            subsystem: str = 'powershell',
    ):
        super().__init__()
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._subsystem = subsystem

        self._channel = None
        self._session = None

        self._write_lock = asyncio.Lock()

    async def __aenter__(self):
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self._channel:
            self._channel.kill()
            self._channel = None

        if self._ssh:
            self._ssh.close()
            self._ssh = None

        self._session.data.put_nowait(None)

    async def open(self):
        if self._ssh:
            return

        conn_options = asyncssh.SSHClientConnectionOptions(
            known_hosts=None,
            username=self._username,
            password=self._password,
        )
        self._ssh = await asyncssh.connect(
            self._hostname,
            port=self._port,
            options=conn_options,
        )
        self._channel, self._session = await self._ssh.create_session(
            _ClientSession, subsystem=self._subsystem, encoding=None,
        )

    async def read(self) -> typing.Optional[bytes]:
        data = await self._session.data.get()
        if data:
            print("Read\t" + data.decode().strip())
        return data

    async def write(
            self,
            data: bytes,
    ):
        async with self._write_lock:
            print("Write\t" + data.decode().strip())
            self._channel.write(data)
