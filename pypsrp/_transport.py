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
    from queue import Queue
except ImportError:
    from Queue import Queue

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

from pypsrp.named_pipe import (
    OutOfProcBase,
)

from pypsrp.shell import (
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

    def __init__(self, runspace):  # type: (Runspace) -> None
        self.runspace = runspace
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
    def connect(self):  # type: () -> None
        pass

    @abc.abstractmethod
    def disconnect(self):
        pass

    @abc.abstractmethod
    def create(self, data):  # type: (bytes) -> None
        self._start_workers()

    @abc.abstractmethod
    def close(self):  # type: () -> None
        self._end_workers()

    @abc.abstractmethod
    def send(self, data, priority_type, ps_guid=None):
        pass

    def _start_workers(self):
        self._t_runspace.start()
        self._t_pipeline.start()

    def _end_workers(self):
        if self._t_runspace.is_alive():
            self._runspace_queue.put(None)
            self._t_runspace.join()

        if self._t_pipeline.is_alive():
            self._pipeline_queue.put(None)
            self._t_pipeline.join()

    def _process_queue(self, queue):  # type: (Queue) -> None
        while True:
            data = queue.get()

            if data is None:
                break

            pipeline = None
            if data.ps_guid:
                pipeline = self.runspace.pipelines[data.ps_guid]

            # TODO: process the PSRP messages.
            messages = self.runspace._fragmenter.defragment(data.data)
            for msg in messages:
                log.info("Received message %s" % msg.message_type)


class WSManConnection(ConnectionBase):

    def __init__(self, runspace, wsman, configuration_name):  # type (RunspacePool, WSMan, str) -> None
        super(WSManConnection, self).__init__(runspace)

        resource_uri = 'http://schemas.microsoft.com/powershell/%s' % configuration_name
        self._wsman = wsman
        self._shell = WinRS(self.wsman, resource_uri=resource_uri, id=runspace.id, input_streams='stdin pr',
                            output_streams='stdout')

    @property
    def max_fragment_size(self):
        return self._wsman.max_payload_size

    def connect(self):
        pass

    def disconnect(self):
        pass

    def create(self, data):
        super(WSManConnection, self).create(data)

        open_context = ET.Element('creationXml', xmlns='http://schemas.microsoft.com/powershell')
        open_context.text = to_unicode(base64.b64encode(data))

        options = OptionSet()
        options.add_option('protocolversion', '2.3', {'MustComply': 'true'})
        self._shell.open(options, open_context)
        self.runspace.state = RunspacePoolState.NEGOTIATION_SENT

    def close(self):
        super(WSManConnection, self).close()

    def send(self, data, priority_type, ps_guid=None):
        pass


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

    def connect(self):
        raise NotImplementedError('OutOfProcConnections do not support disconnections and connections')

    def disconnect(self):
        raise NotImplementedError('OutOfProcConnections do not support disconnections and connections')

    def create(self, data):
        super(OutOfProcConnection, self).create(data)
        self._process.open()
        self._t_stdout.start()
        self._t_stderr.start()

        shell_create = self._process.data_packet(data)
        self._process.write(shell_create + b"\n")

    def close(self):
        super(OutOfProcConnection, self).close()

        self._process.close()

        for thread_type in ['stdout', 'stderr']:
            thread = getattr(self, '_t_%s' % thread_type)
            if thread and thread.is_alive():
                thread.join()

            setattr(self, '_t_%s' % thread_type, None)

    def send(self, data, priority_type, ps_guid=None):
        pass

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
                print("Received command ack for %s" % ps_guid)

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
