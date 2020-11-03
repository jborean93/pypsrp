# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import typing

from psrp.exceptions import (
    OperationTimedOut,
)

from psrp.io.wsman import (
    AsyncWSManConnection,
)

from psrp.protocol.winrs import (
    SignalCode,
    WinRS,
)

from psrp.protocol.wsman import (
    CommandState,
    WSMan,
)


class AsyncWinRS:
    """A Windows Remote Shell - Async.
    
    Represents an opened Shell that is managed over WinRM/WSMan. This is the async variant that is designed to run with
    asyncio for faster concurrent operations.
    """

    def __init__(
            self,
            connection_uri: str,
            codepage: typing.Optional[int] = None,
            environment: typing.Optional[typing.Dict[str, str]] = None,
            idle_time_out: typing.Optional[int] = None,
            lifetime: typing.Optional[int] = None,
            no_profile: typing.Optional[bool] = None,
            working_directory: typing.Optional[str] = None,
    ):
        wsman = WSMan(connection_uri)
        self.winrs = WinRS(wsman, codepage=codepage, environment=environment, idle_time_out=idle_time_out,
                           lifetime=lifetime, no_profile=no_profile, working_directory=working_directory)
        self._io = AsyncWSManConnection(connection_uri)

    async def __aenter__(self):
        await self._io.open()
        await self.create()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        await self._io.close()

    async def close(self):
        """ Closes the WinRS shell. """
        self.winrs.close()
        await self._exchange_data()

    async def create(self):
        """ Opens the WinRS shell. """
        self.winrs.open()
        await self._exchange_data()
        
    async def execute(
            self,
            executable: str,
            args: typing.Optional[typing.List[str]] = None,
            no_shell: bool = False,
    ) -> 'AsyncWinRSProcess':
        """ Starts a new process on the WinRS shell. """
        return AsyncWinRSProcess(self, executable, args=args, no_shell=no_shell)

    async def _exchange_data(self, io=None):
        """ Sends the pending messages from the WinRS shell over the IO object and returns the response. """
        if not io:
            io = self._io

        content = self.winrs.data_to_send()
        response = await io.send(content)

        event = self.winrs.receive_data(response)
        return event


class AsyncWinRSProcess:
    
    def __init__(
            self,
            winrs: AsyncWinRS,
            executable: str,
            args: typing.Optional[typing.List[str]] = None,
            no_shell: bool = False,
    ):
        self.executable = executable
        self.args = args
        self.no_sell = no_shell
        self._stdin_r = self._stdout_w = self._stderr_w = self.stdin = self.stdout = self.stdin = None
        # self.pid = None
        self.returncode = None

        self._command_id = None
        self._state = CommandState.pending
        self._winrs = winrs
        self._receive_task = None
        
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.terminate()
        await self._receive_task
        self._receive_task = None
        
    async def poll(
            self,
    ) -> typing.Optional[int]:        
        a = ''
        
    async def wait(
            self,
            timeout: typing.Optional[int] = None,
    ) -> int:
        await self._receive_task
        
    async def communicate(
            self,
            input_data: typing.Optional[bytes] = None,
            timeout: typing.Optional[int] = None,
    ) -> typing.Tuple[bytes, bytes]:
        self.stdin.write(input_data)
        await self.stdin.drain()
        
    async def send_signal(
            self,
            signal: SignalCode,
    ):
        self._winrs.winrs.signal(signal, self._command_id)
        await self._winrs._exchange_data()
        
    async def start(
            self,
    ):
        loop = asyncio.get_event_loop()
        self.stdout = asyncio.StreamReader(loop=loop)
        self.stderr = asyncio.StreamReader(loop=loop)

        r = asyncio.StreamReader(loop=loop)
        p = asyncio.StreamReaderProtocol(r, loop=loop)
        t = None

        self.stdin = asyncio.StreamWriter(transport=t, protocol=p, reader=r, loop=loop)

        self._winrs.winrs.command(self.executable, args=self.args, no_shell=self.no_sell)
        command_event = await self._winrs._exchange_data()
        self._state = CommandState.running
        self._command_id = command_event.command_id
        self._receive_task = asyncio.create_task(self._receive())

    async def terminate(
            self,
    ):
        await self.send_signal(SignalCode.terminate)
        
    async def kill(
            self,
    ):
        await self.send_signal(SignalCode.ctrl_c)
        
    async def _receive(
            self,
    ):
        # Use a new WSMan connection so we can send the Receive requests in parallel to the main shell connection.
        async with AsyncWSManConnection(self._winrs.winrs.wsman.connection_uri) as io:
            while self._state != CommandState.done:
                self._winrs.winrs.receive(command_id=self._command_id)

                try:
                    receive_response = await self._winrs._exchange_data(io=io)
                except OperationTimedOut:
                    # Expected if no data was available in the WSMan operational_timeout time. Just send the receive
                    # request again until there is data available.
                    continue

                if receive_response.exit_code is not None:
                    self.returncode = receive_response.exit_code
                self._state = receive_response.command_state

                buffer = receive_response.get_streams()
                pipe_map = [('stdout', self.stdout), ('stderr', self.stderr)]
                for name, pipe in pipe_map:
                    for data in buffer.get(name, []):
                        pipe.feed_data(data)

        self.stdout.feed_eof()
        self.stderr.feed_eof()


class StdinTransport(asyncio.transports.WriteTransport):

    def __init__(self, loop, protocol):
        super().__init__()
        self._loop = loop
        self._protocol = protocol

    def write(self, data):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        self._protocol.data_received(data)

    def writelines(self, list_of_data):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and
        calls write() on the result.
        """
        data = b''.join(list_of_data)
        self.write(data)

    def write_eof(self):
        """Close the write end after flushing buffered data.

        (This is like typing ^D into a UNIX program reading from stdin.)

        Data may still be received.
        """
        self._protocol.eof_received()

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        return True

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        raise NotImplementedError

            
def _create_inmemory_stream():
    loop = asyncio.events.get_event_loop()

    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = StdinTransport(loop, protocol)
    # transport.set_write_buffer_limits(0)  # Make sure .drain() actually sends all the data.
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    
    return reader, writer
