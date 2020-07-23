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

from pypsrp.complex_objects import (
    ApartmentState,
    HostInfo,
    PSThreadOptions,
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
    stream_type_str = 'Default' if stream_type == 0 else 'PromptResponse'
    return b"<Data Stream='%s' PSGuid='%s'>%s</Data>" % (stream_type_str, str(guid).upper(), base64.b64encode(data))


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
    return b"<%s PSGuid='%s' />" % (element, str(guid).upper())


class OutOfProcTransport:

    def __init__(self, command):
        self.command = command
        self.process = None
        self._t_stdout = None
        self._t_stderr = None
        self.results = []
        self.on_receive = threading.Event()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return

    def open(self):
        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE, shell=False, bufsize=0)
        self._t_stdout = threading.Thread(target=self._process_output, name='stdout', args=(self.process.stdout, 'stdout'))
        self._t_stdout.start()
        self._t_stderr = threading.Thread(target=self._process_output, name='stderr', args=(self.process.stderr, 'stderr'))
        self._t_stderr.start()

        return

    def close(self):
        if self.process:
            self.process.kill()
            self.process.wait()
            self.process = None

        for thread_type in ['stdout', 'stderr']:
            thread = getattr(self, '_t_%s' % thread_type)
            if thread:
                thread.join()
                setattr(self, '_t_%s' % thread_type, None)

    def send(self, data):
        self.process.stdin.write(data + b"\n")
        self.process.stdin.flush()

    def _process_output(self, pipe, name):
        while True:
            data = pipe.readline()

            if data:
                print("Received %s output: %s" % (name, data))
                self.results.append(data)
                self.on_receive.set()

            if self.process is None:
                break


with OutOfProcTransport(['pwsh', '-s', '-NoProfile', '-NoLogo']) as proc:
    empty_uuid = uuid.UUID('00000000-0000-0000-0000-000000000000')
    runspace_id = uuid.uuid4()

    # Create the runspace pool
    fragmenter = Fragmenter(1024 * 1024 * 1024, Serializer())
    session_capability = SessionCapability('2.3', '2.0', '1.1.0.1')
    init_runspace = InitRunspacePool(min_runspaces=1, max_runspaces=1,
                                     thread_options=PSThreadOptions(value=PSThreadOptions.DEFAULT),
                                     apartment_state=ApartmentState(value=ApartmentState.UNKNOWN),
                                     host_info=HostInfo(host=None))

    data = fragmenter.fragment_multiple([session_capability, init_runspace], str(runspace_id).upper())[0]
    data_packet = data_msg(data, DataPriorityType.Default, empty_uuid)
    proc.send(data_packet)

    try:
        proc.on_receive.wait()
        proc.on_receive.clear()

        while proc.results:
            open_resp = ET.fromstring(proc.results.pop(0))
            if open_resp.tag == 'DataAck':
                continue

            responses = fragmenter.defragment(base64.b64decode(open_resp.text))

            for response in responses:
                if response.message_type == MessageType.SESSION_CAPABILITY:
                    print("Received SessionCapability:\nProtocol Version: %s\nPSVersion: %s\nSerializationVersion: %s"
                          % (response.data.protocol_version, response.data.ps_version,
                             response.data.serialization_version))

                elif response.message_type == MessageType.APPLICATION_PRIVATE_DATA:
                    print("Received ApplicationPrivateData: %s" % json.dumps(response.data.data))

                elif response.message_type == MessageType.RUNSPACEPOOL_STATE:
                    print("Received RunspacePoolState: %s" % response.data.state)

                else:
                    raise Exception("Unknown runspace init data message %s" % response.message_type)

        # Create the pipeline
        ps_id = uuid.uuid4()
        proc.send(command_msg(ps_id))
        proc.on_receive.wait()
        proc.on_receive.clear()

        resp = ET.fromstring(proc.results.pop(0))
        if resp.tag != 'CommandAck':
            raise Exception("Expecting Ack of creating new pipeline but got '%s'" % resp.tag)

        try:
            a = ''

        finally:
            proc.send(close_msg(ps_id))
            proc.on_receive.wait()
            proc.on_receive.clear()

    finally:
        proc.send(close_msg(empty_uuid))
        proc.on_receive.wait()
        proc.on_receive.clear()
