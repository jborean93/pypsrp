# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import json
import subprocess
import threading
import uuid
import xml.etree.ElementTree as ET

try:
    from queue import Queue
except ImportError:
    from Queue import Queue

from pypsrp.complex_objects import (
    ApartmentState,
    HostInfo,
    PSThreadOptions,
    RunspacePoolState,
)

from pypsrp.messages import (
    InitRunspacePool,
    MessageType,
    SessionCapability,
)

from pypsrp.powershell import (
    Fragmenter,
)

from pypsrp.serializer import (
    Serializer,
)


class DataPriorityType:
    Default = 0
    PromptResponse = 1


def data_msg(data, stream_type, guid):  # type: (bytes, int, uuid.UUID) -> bytes
    stream_type_str = b'Default' if stream_type == 0 else b'PromptResponse'
    return b"<Data Stream='%s' PSGuid='%s'>%s</Data>" % (stream_type_str, str(guid).upper().encode(),
                                                         base64.b64encode(data))


def data_ack_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"DataAck", guid)


def command_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"Command", guid)


def command_ack_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"CommandAck", guid)


def close_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"Close", guid)


def close_ack_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"CloseAck", guid)


def signal_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"Signal", guid)


def signal_ack_msg(guid):  # type: (uuid.UUID) -> bytes
    return _psguid_msg(b"SignalAck", guid)


def _psguid_msg(element, guid):  # type: (bytes, uuid.UUID) -> bytes
    return b"<%s PSGuid='%s' />" % (element, str(guid).upper().encode())


class OutOfProcTransport:

    def __init__(self, command):
        self.command = command
        self.runspace_queue = Queue()
        self.pipeline_queue = Queue()
        self._process = None
        self._t_stdout = None
        self._t_stderr = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return

    def open(self):  # type: () -> None
        self._process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE, shell=False, bufsize=0)

        self._t_stdout = threading.Thread(target=self._process_output, name='stdout-%s' % self._process.pid,
                                          args=('stdout',))
        self._t_stdout.start()
        self._t_stderr = threading.Thread(target=self._process_output, name='stderr-%s' % self._process.pid,
                                          args=('stderr',))
        self._t_stderr.start()

    def close(self):  # type: () -> None
        if self._process:
            self._process.kill()
            self._process.wait()
            self._process = None

        for thread_type in ['stdout', 'stderr']:
            thread = getattr(self, '_t_%s' % thread_type)
            if thread:
                thread.join()
                setattr(self, '_t_%s' % thread_type, None)

    def send(self, b_data):  # type: (bytes) -> None
        self._process.stdin.write(b_data + b"\n")

    def _process_output(self, name):  # type: (str) -> None
        pipe = getattr(self._process, name)

        while True:
            b_data = pipe.readline()

            if b_data:
                b_data = b_data.strip()

                print("Received %s output: %s" % (name, b_data))
                if b"PSGuid='00000000-0000-0000-0000-000000000000'" in b_data:
                    self.runspace_queue.put(b_data)

                else:
                    self.pipeline_queue.put(b_data)

            else:
                break


NULL_UUID = uuid.UUID('00000000-0000-0000-0000-000000000000')


class RunspacePool:

    def __init__(self, transport):  # type: (OutOfProcTransport) -> None
        self.transport = transport
        self.rid = uuid.uuid4()
        self.pipelines = {}
        self.state = RunspacePoolState.BEFORE_OPEN
        self._serializer = Serializer()
        self._fragmenter = Fragmenter(1024 * 1024 * 1024, self._serializer)

        self._t_runspace = threading.Thread(target=self._process_queue, name='runspace-%s' % str(self.rid),
                                            args=(self.transport.runspace_queue,))
        self._t_pipeline = threading.Thread(target=self._process_queue, name='pipeline-%s' % str(self.rid),
                                            args=(self.transport.pipeline_queue,))

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        self._t_runspace.start()
        self._t_pipeline.start()
        session_capability = SessionCapability('2.3', '2.0', '1.1.0.1')
        init_runspace = InitRunspacePool(min_runspaces=1, max_runspaces=1,
                                         thread_options=PSThreadOptions(value=PSThreadOptions.DEFAULT),
                                         apartment_state=ApartmentState(value=ApartmentState.UNKNOWN),
                                         host_info=HostInfo(host=None))

        data = self._fragmenter.fragment_multiple([session_capability, init_runspace], str(self.rid).upper())[0]
        data_packet = data_msg(data, DataPriorityType.Default, NULL_UUID)
        self.transport.send(data_packet)

    def _process_queue(self, queue):  # type: (Queue) -> None
        while True:
            b_data = queue.get()

            if b_data is None:
                break

            try:
                element = ET.fromstring(b_data)

            except ET.ParseError:
                raise Exception(b_data.decode())

            else:
                ps_guid = element.attrib.get('PSGuid', None)
                if not ps_guid:
                    raise Exception("Invalid data, no PSGuid")

                pipeline = None
                if ps_guid != str(NULL_UUID):
                    pipeline = self.pipelines[ps_guid]

                if element.tag == 'Data':
                    self._parse_responses(base64.b64decode(element.text), pipeline=pipeline)

                elif element.tag == 'DataAck':
                    print("Received data ack for %s" % ps_guid)

                elif element.tag == 'Command':
                    raise Exception('Client should not receive a Command packet')

                elif element.tag == 'CommandAck':
                    if not pipeline:
                        raise Exception('A runspace should not receive a CommandAck')
                    print("Received command ack for %s" % ps_guid)

                elif element.tag == 'Close':
                    raise Exception('Client should not receive a Close packet')

                elif element.tag == 'CloseAck':
                    print("Received close ack for %s" % ps_guid)

                elif element.tag == 'Signal':
                    raise Exception('Client should not receive a Signal packet')

                elif element.tag == 'SignalAck':
                    if not pipeline:
                        raise Exception('A runspace should not receive a SignalAck')

                else:
                    raise Exception("Unknown element tag: %s" % element.tag)

    def _parse_responses(self, responses, pipeline=None):
        messages = self._fragmenter.defragment(responses)

        response_functions = {
            # While the docs say we should verify, they are out of date with
            # the possible responses and so we will just ignore for now
            MessageType.SESSION_CAPABILITY: self._process_session_capability,
            #MessageType.ENCRYPTED_SESSION_KEY: self._process_encrypted_session_key,
            #MessageType.PUBLIC_KEY_REQUEST: self.exchange_keys,
            MessageType.RUNSPACEPOOL_INIT_DATA: self._process_runspacepool_init_data,
            #MessageType.RUNSPACE_AVAILABILITY: self._process_runspacepool_availability,
            MessageType.RUNSPACEPOOL_STATE: self._process_runspacepool_state,
            #MessageType.USER_EVENT: self._process_user_event,
            #MessageType.APPLICATION_PRIVATE_DATA: self._process_application_private_data,
            ##MessageType.RUNSPACEPOOL_HOST_CALL: self._process_runspacepool_host_call,
            #MessageType.WARNING_RECORD: self._process_runspacepool_warning,
        }

        if pipeline is not None:
            pipeline_response_functions = {
                # The Pipeline Output isn't processes and just returned back to
                # the receive caller
                MessageType.PIPELINE_OUTPUT: None,
                MessageType.ERROR_RECORD: pipeline._process_error_record,
                MessageType.PIPELINE_STATE: pipeline._process_pipeline_state,
                MessageType.DEBUG_RECORD: pipeline._process_debug_record,
                MessageType.VERBOSE_RECORD: pipeline._process_verbose_record,
                MessageType.WARNING_RECORD: pipeline._process_warning_record,
                MessageType.PROGRESS_RECORD: pipeline._process_progress_record,
                MessageType.INFORMATION_RECORD: pipeline._process_information_record,
                MessageType.PIPELINE_HOST_CALL: pipeline._process_pipeline_host_call,
            }
            response_functions.update(pipeline_response_functions)

        return_values = []
        for message in messages:
            if message.message_type not in response_functions:
                response_function = None

            else:
                response_function = response_functions[message.message_type]

            if response_function is not None:
                return_value = response_function(message)
                return_values.append((message.message_type, return_value))
            else:
                return_values.append((message.message_type, message))

        return return_values

    def _process_session_capability(self, message):
        print("Received SessionCapability with protocol version: %s, ps version: %s, serialization version: %s"
              % (message.data.protocol_version, message.data.ps_version, message.data.serialization_version))
        self.protocol_version = message.data.protocol_version
        self.ps_version = message.data.ps_version
        self.serialization_version = message.data.serialization_version

    def _process_runspacepool_init_data(self, message):
        print("Received RunspacePoolInitData with min runspaces: %d and max runspaces: %d"
              % (message.data.min_runspaces, message.data.max_runspaces))
        self._min_runspaces = message.data.min_runspaces
        self._max_runspaces = message.data.max_runspaces

    def _process_runspacepool_state(self, message):
        print("Received RunspacePoolState with state: %d" % message.data.state)
        self.state = message.data.state
        if self.state == RunspacePoolState.BROKEN:
            raise Exception("Received a broken RunspacePoolState message: %s" % str(message.data.error_record))
        return message.data

    def close(self):
        self.transport.send(close_msg(NULL_UUID))
        self.transport.pipeline_queue.put(None)
        self.transport.runspace_queue.put(None)
        self._t_runspace.join()
        self._t_pipeline.join()


def func1(event):
    while True:
        a = ''
        event.wait()
        a = ''


e = threading.Condition()
t1 = threading.Thread(target=func1, name='t1', args=(e,))
t1.start()
t2 = threading.Thread(target=func1, name='t2', args=(e,))
t2.start()
t3 = threading.Thread(target=func1, name='t3', args=(e,))
t3.start()


#with OutOfProcTransport(['pwsh', '-s', '-NoProfile', '-NoLogo']) as proc, RunspacePool(proc) as rp:
#    a = ''
