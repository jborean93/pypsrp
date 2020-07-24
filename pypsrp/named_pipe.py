# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import logging
import os
import subprocess

from pypsrp._utils import (
    to_bytes,
)

log = logging.getLogger(__name__)


class OutOfProcBase:
    """The base class for out of process remoting transport mechnanisms.

    This provides a simple interface for communicating with a PowerShell instance over a pipe.

    Args:
        command: The commands to run when starting the process.
    """

    def __init__(self, command):  # type: (List[str]) -> None
        self.command = command
        self._process = None  # type: Optional[subprocess.Popen]

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return

    def open(self):
        """ Open the new process. """
        if self._process:
            return

        log.info("Staring OutOfProc process with command '%s'" % (' '.join(self.command),))
        self._process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE, shell=False)
        log.debug("OutOfProc process started with pid %s" % self._process.pid)

    def close(self):
        """ Close the running process. """
        if self._process:
            log.info("Killing OutOfProc process %s" % self._process.pid)
            self._process.kill()
            self._process.wait()
            self._process = None

    def readline(self, pipe):  # type: (str) -> bytes
        """ Read bytes by line from the process' stdout or stderr pipe. """
        if pipe not in ['stdout', 'stderr']:
            raise ValueError('The pipe to read must be stdout or stderr')

        log.debug("Reading from OutOfProc %d %s pipe" % (self._process.pid, pipe))
        pipe_fd = getattr(self._process, pipe)
        return pipe_fd.readline()

    def write(self, data):  # type: (bytes) -> None
        """ Write data to the process' stdin. """
        log.debug("Writing to OutOfProc %d stdin pipe" % self._process.pid)
        self._process.stdin.write(data)

    @staticmethod
    def data_packet(data, stream_type='Default', ps_guid=None):  # type: (bytes, str, Optional[str]) -> bytes
        """Data packet for PSRP fragments

        This creates a data packet that is used to encode PSRP fragments when sending to the server.

        Args:
            data: The PSRP fragments to encode.
            stream_type: The stream type to target, Default or PromptResponse.
            ps_guid: Set to `None` or a 0'd UUID to target the runspace, otherwise this should be the pipeline UUID.

        Returns:
            bytes: The encoded data XML packet.
        """
        if stream_type not in ['Default', 'PromptResponse']:
            raise ValueError('The stream_type must be Default or PromptResponse not %s' % stream_type)

        ps_guid = ps_guid or b'00000000-0000-0000-0000-000000000000'
        return b"<Data Stream='%s' PSGuid='%s'>%s</Data>" % (to_bytes(stream_type), to_bytes(ps_guid),
                                                             base64.b64encode(data))

    @staticmethod
    def ps_guid_packet(element, ps_guid=None):  # type: (str, Optional[str]) -> bytes
        """Common PSGuid packet for PSRP message.

        This creates a PSGuid packet that is used to signal events and stages in the PSRP exchange. Unlike the data
        packet this does not contain any PSRP fragments.

        Args:
            element: The element type, can be DataAck, Command, CommandAck, Close, CloseAck, Signal, and SignalAck.
            ps_guid: Set to `None` or a 0'd UUID to target the runspace, otherwise this should be the pipeline UUID.

        Returns:
            bytes: The encoded PSGuid packet.
        """
        ps_guid = ps_guid or b'00000000-0000-0000-0000-000000000000'
        return b"<%s PSGuid='%s' />" % (to_bytes(element), to_bytes(ps_guid))


class PowerShellProcess(OutOfProcBase):
    """Connection to the local PowerShell process.

    This represents a connection to the local PowerShell process on the host. This will start a new PowerShell process
    using the args `-NoProfile -NoLogo -s` that can be used to exchange PSRP data.

    Args:
        executable: Defaults to `powershell.exe` on Windows and `pwsh` on other OS'.
    """

    def __init__(self, executable=None):  # type: (Optional[str]) -> None
        executable = executable or ('powershell.exe' if os.name == 'nt' else 'pwsh')
        command = [executable, '-NoProfile', '-NoLogo', '-s']
        super(PowerShellProcess, self).__init__(command)
