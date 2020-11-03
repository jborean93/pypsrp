# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import typing


class PowerShellProcess:
    
    def __init__(
            self,
            executable: str = 'pwsh',
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        self.executable = executable
        self.arguments = arguments if arguments is not None else ['-s', '-NoProfile', '-NoLogo']
        self._process = None

    @property
    def running(self):
        return self._process is not None

    async def __aenter__(self):
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self._process:
            self._process.kill()
            await self._process.wait()
            self._process = None

    async def open(self):
        pipe = asyncio.subprocess.PIPE
        self._process = await asyncio.create_subprocess_exec(self.executable, *self.arguments, stdin=pipe,
                                                             stdout=pipe, stderr=pipe)

    async def read(self) -> typing.Optional[bytes]:
        async def read_pipe(name):
            pipe = getattr(self._process, name)
            output = await pipe.readline()
            return name, output

        tasks = [read_pipe(n) for n in ['stdout', 'stderr']]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        output = None

        for coro in done:
            name, output = await coro

            if output:
                if name == 'stderr':
                    raise Exception(output.decode())

            else:
                return

        for coro in pending:
            coro.cancel()

        return output

    async def write(
            self,
            data: bytes,
    ):
        self._process.stdin.write(data)
        await self._process.stdin.drain()
