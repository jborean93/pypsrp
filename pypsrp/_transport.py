# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import abc
import collections
import base64
import logging
import subprocess
import six
import sys
import threading
import uuid
import xml.etree.ElementTree as ET

try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty

try:
    from typing import (
        Dict,
        Tuple,
        Union,
    )
except ImportError:
    Dict = None
    Tuple = None
    Union = None


from pypsrp._utils import (
    to_bytes,
    to_unicode,
    version_equal_or_newer,
)

from pypsrp.complex_objects import (
    ApartmentState,
    Command,
    HostInfo,
    Pipeline,
    PSInvocationState,
    PSThreadOptions,
    RemoteStreamOptions,
    RunspacePoolState,
)

from pypsrp.exceptions import (
    WSManFaultError,
)

from pypsrp.out_of_proc import (
    OutOfProcBase,
)

from pypsrp.shell import (
    SignalCode,
    WinRS,
)

from pypsrp.wsman import (
    OptionSet,
    SelectorSet,
    WSMan,
)

log = logging.getLogger(__name__)

NULL_UUID = '00000000-0000-0000-0000-000000000000'

PSRPResponse = collections.namedtuple('PSRPResponse', ['data', 'stream_type', 'ps_guid'])


def select_connection(runspace, connection, configuration_name):
    # type: (RunspacePool, Union[OutOfProcBase, WSMan], str) -> ConnectionBase
    if isinstance(connection, OutOfProcBase):
        conn = OutOfProcConnection(runspace, connection)

    elif isinstance(connection, WSMan):
        conn = WSManConnection(runspace, connection, configuration_name)

    else:
        raise ValueError("Unsupported connection type %s" % type(connection).__name__)

    return conn


@six.add_metaclass(abc.ABCMeta)
class ConnectionBase:

    def __init__(self, runspace, powershell=None):  # type: (Runspace, Optional[PowerShell]) -> None
        self.msg_queue = Queue()
        self.runspace = runspace
        self._powershell = powershell
        self._runspace_queue = Queue()
        self._pipeline_queue = Queue()
        self._t_runspace = threading.Thread(target=self._process_queue, name='runspace-%s' % runspace.id,
                                            args=(self._runspace_queue,))
        self._t_pipeline = threading.Thread(target=self._process_queue, name='pipeline-%s' % runspace.id,
                                            args=(self._pipeline_queue,))

    @property
    @abc.abstractmethod
    def max_fragment_size(self):  # type: () -> int
        """ The maximum fragment size for each PSRP fragments. """
        pass

    @abc.abstractmethod
    def close(self):  # type: () -> None
        pass

    @abc.abstractmethod
    def command(self, ps_guid):  # type: (str) -> None
        pass

    @abc.abstractmethod
    def connect(self):  # type: () -> None
        pass

    @abc.abstractmethod
    def create(self):  # type: () -> None
        self._t_runspace.start()
        self._t_pipeline.start()

    @abc.abstractmethod
    def disconnect(self):  # type: () -> None
        pass

    @abc.abstractmethod
    def dispose(self):  # type: () -> None
        if self._t_runspace.is_alive():
            self._runspace_queue.put(None)
            self._t_runspace.join()

        if self._t_pipeline.is_alive():
            self._pipeline_queue.put(None)
            self._t_pipeline.join()

    @abc.abstractmethod
    def send(self):  # type: () -> None
        pass

    @abc.abstractmethod
    def signal(self, ps_guid):  # type: () -> None
        pass

    def _process_queue(self, queue):  # type: (Queue) -> None
        while True:
            data = queue.get()

            if data is None:
                break

            pipeline = None
            if data.ps_guid:
                pipeline = self.runspace.pipelines[data.ps_guid.upper()]

            self.runspace._parse_responses(data.data, pipeline=pipeline)


class WSManConnection(ConnectionBase):

    def __init__(self, runspace, wsman, configuration_name):  # type (RunspacePool, WSMan, str) -> None
        super(WSManConnection, self).__init__(runspace)

        resource_uri = 'http://schemas.microsoft.com/powershell/%s' % configuration_name
        self._wsman = wsman
        self._shell = WinRS(self._wsman, resource_uri=resource_uri, id=runspace.id, input_streams='stdin pr',
                            output_streams='stdout')

        self._t_receive = threading.Thread(target=self._receive, name='shell-receive-%s' % runspace.id)
        self._t_pipelines = []

    @property
    def max_fragment_size(self):
        version = self.runspace.protocol_version

        # If the default envelope size was set but PowerShell has reported it's on 2.2 or newer then we are dealing
        # with Windows 8 or newer which has a higher developer envelope size. Update the defaults so we can send
        # larger fragments.
        if self._wsman.max_envelope_size == 153600 and version and version_equal_or_newer(version, '2.2'):
            self._wsman.update_max_payload_size(512000)

        return self._wsman.max_payload_size

    def close(self):
        super(WSManConnection, self).close()
        self._shell.close()

    def command(self, ps_guid):
        super(WSManConnection, self).command(ps_guid)
        data = self.msg_queue.get(block=False)[0]
        frag = to_unicode(base64.b64encode(data))
        self._shell.command('', arguments=[frag], command_id=ps_guid)
        self._t_pipelines.append(threading.Thread(target=self._receive, name='pipeline-receive-%s' % ps_guid,
                                                  args=(ps_guid,)))
        self._t_pipelines[-1].start()
        self.send()

    def connect(self):
        super(WSManConnection, self).connect()

    def create(self):
        super(WSManConnection, self).create()
        data = self.msg_queue.get(block=False)

        open_context = ET.Element('creationXml', xmlns='http://schemas.microsoft.com/powershell')
        open_context.text = to_unicode(base64.b64encode(data))

        options = OptionSet()
        options.add_option('protocolversion', '2.3', {'MustComply': 'true'})
        self._shell.open(options, open_context)
        self._t_receive.start()

    def disconnect(self):
        super(WSManConnection, self).disconnect()

    def dispose(self):
        super(WSManConnection, self).dispose()

    def send(self):
        super(WSManConnection, self).send()

        while True:
            try:
                msg = self.msg_queue.get(block=False)
                command_id = None
                if isinstance(msg, tuple):
                    msg, command_id = msg

                # TODO: Figure out how to get the stream name.
                self._shell.send(msg, 'stdin', command_id=command_id)

            except Empty:
                break

    def signal(self, ps_guid):
        super(WSManConnection, self).signal(ps_guid)
        self._shell.signal(SignalCode.PS_CTRL_C, ps_guid)

    def _receive(self, command_id=None):
        while True:
            try:
                response = self._shell.receive('stdout', command_id=command_id)[2]['stdout']
            except WSManFaultError as exc:
                # If a command exceeds the OperationTimeout set, we will get a WSManFaultError with the code
                # 2150858793. We ignore this as it just meant no output during that operation.
                if exc.code == 2150858793:
                    continue

                raise

            process_queue = self._runspace_queue
            if command_id:
                process_queue = self._pipeline_queue

            psrp_response = PSRPResponse(response, 'Default', command_id)
            process_queue.put(psrp_response)


class OutOfProcConnection(ConnectionBase):

    def __init__(self, runspace, process):  # type: (RunspacePool, OutOfProcBase) -> None
        super(OutOfProcConnection, self).__init__(runspace)

        self._process = process
        self._t_stdout = threading.Thread(target=self._process_output, name='stdout-%s' % runspace.id,
                                          args=('stdout',))
        self._t_stderr = threading.Thread(target=self._process_output, name='stderr-%s' % runspace.id,
                                          args=('stderr',))

    @property
    def max_fragment_size(self):
        # fragment size is based on the named pipe buffer size of 32KiB
        # https://github.com/PowerShell/PowerShell/blob/0d5d017f0f1d89a7de58d217fa9f4a37ad62cc94/src/System.Management.Automation/engine/remoting/common/RemoteSessionNamedPipe.cs#L355
        return 32768

    def close(self, ps_guid=None):
        super(OutOfProcConnection, self).close()

        self._process.write(self._process.ps_guid_packet("Close", ps_guid))

    def command(self, ps_guid):
        super(OutOfProcConnection, self).command(ps_guid)
        self._process.write(self._process.ps_guid_packet('Command', ps_guid))
        self.send()

    def connect(self):
        raise NotImplementedError('OutOfProcConnections do not support disconnections and connections')

    def create(self):
        super(OutOfProcConnection, self).create()

        self._process.open()
        self._t_stdout.start()
        self._t_stderr.start()

        self.send_one()

    def disconnect(self):
        raise NotImplementedError('OutOfProcConnections do not support disconnections and connections')

    def dispose(self):
        super(OutOfProcConnection, self).dispose()

        self._process.close()
        [getattr(self, '_t_%s' % n).join() for n in ['stdout', 'stderr']]

    def send(self):
        super(OutOfProcConnection, self).send()

        while self.send_one():
            pass

    def send_one(self):
        try:
            msg = self.msg_queue.get(block=False)
            ps_guid = None
            if isinstance(msg, tuple):
                msg, ps_guid = msg

            # TODO: Figure out how to get this info.
            data_packet = self._process.data_packet(msg, 'Default', ps_guid)
            self._process.write(data_packet)
            return True

        except Empty:
            return False

    def signal(self, ps_guid):
        super(OutOfProcConnection, self).signal(ps_guid)
        self._process.write(self._process.ps_guid_packet('Signal', ps_guid))

    def _process_output(self, name):  # type: (str) -> None
        while True:
            b_data = self._process.readline(name)

            if not b_data:
                break

            b_data = b_data.strip()
            log.info("Received %s output: %s" % (name, b_data))

            try:
                element = ET.fromstring(b_data)

            except ET.ParseError:
                raise Exception(b_data.decode())

            ps_guid = element.attrib.get('PSGuid', None)
            if not ps_guid:
                raise Exception("Invalid data, no PSGuid")

            process_queue = self._runspace_queue
            if ps_guid != NULL_UUID:
                process_queue = self._pipeline_queue

            else:
                ps_guid = None

            if element.tag == 'Data':
                psrp_response = PSRPResponse(base64.b64decode(element.text), element.attrib['Stream'], ps_guid)
                process_queue.put(psrp_response)

            elif element.tag == 'DataAck':
                print("Received data ack for %s" % ps_guid)

            elif element.tag == 'Command':
                raise Exception('Client should not receive a Command packet')

            elif element.tag == 'CommandAck':
                if not ps_guid:
                    raise Exception('A runspace should not receive a CommandAck')
                self.send_one()

            elif element.tag == 'Close':
                raise Exception('Client should not receive a Close packet')

            elif element.tag == 'CloseAck':
                print("Received close ack for %s" % ps_guid)

            elif element.tag == 'Signal':
                raise Exception('Client should not receive a Signal packet')

            elif element.tag == 'SignalAck':
                if not ps_guid:
                    raise Exception('A runspace should not receive a SignalAck')

            else:
                raise Exception("Unknown element tag: %s" % element.tag)


class Base:

    def create(self):
        pass

    def on_create(self):
        a = ''