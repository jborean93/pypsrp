# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import struct
import sys
import uuid

from pypsrp.exceptions import WinRMError
from pypsrp.messages import ApartmentState, Color, Coordinates, HostInfo, \
    InitRunspacePool, Message, MessageType, RunspacePoolStateMessage, \
    SessionCapability, Size, PSThreadOptions
from pypsrp.shell import WinRS
from pypsrp.wsman import NAMESPACES, OptionSet, SelectorSet

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET


class RunspacePoolState(object):
    """
    [MS-WSMV] 2.2.3.4 RunspacePoolState
    https://msdn.microsoft.com/en-us/library/dd341723.aspx

    Represents the state of the RunspacePool.
    """
    BEFORE_OPEN = 0
    OPENING = 1
    OPENED = 2
    CLOSED = 3
    CLOSING = 4
    BROKEN = 5
    NEGOTIATION_SENT = 6
    NEGOTIATION_SUCCEEDED = 7
    CONNECTING = 8
    DISCONNECTED = 9


class PSRP(object):

    def __init__(self, wsman):
        self.wsman = wsman

        self.guid = uuid.uuid4()
        self.state = RunspacePoolState.BEFORE_OPEN
        self.fragmenter = Fragmenter()
        self.shell = WinRS(self.wsman)
        self.shell.resource_uri = "http://schemas.microsoft.com/powershell/" \
                                  "Microsoft.PowerShell"
        self.max_runspaces = None
        self.min_runspaces = None
        self.available_runspaces = None
        self.information_ci_table = None
        self.pipeline_table = []
        self.session_key = None
        self.session_key_transfer_timeout = None

    def open(self):
        self.state = RunspacePoolState.OPENING

        # create SESSION_CAPABILITY and INIT_RUNSPACEPOOL message, fragment and
        # send under creationXml for the create message
        fragment_data = b""
        for fragment in self.fragmenter.fragment(self._session_capability()):
            fragment_data += fragment.pack()
        for fragment in self.fragmenter.fragment(self._init_runspacepool()):
            fragment_data += fragment.pack()
        open_content = ET.Element(
            "creationXml",
            xmlns="http://schemas.microsoft.com/powershell"
        )
        open_content.text = base64.b64encode(fragment_data).decode('utf-8')

        options = OptionSet()
        options.add_option("protocolversion", "2.3", {"MustComply": "true"})
        self.shell.open(input_streams='stdin pr', output_streams='stdout',
                        open_content=open_content, base_options=options)
        self.state = RunspacePoolState.NEGOTIATION_SENT

        while self.state != RunspacePoolState.OPENED:
            response = self.shell._get_receive_response("stdout")[2]['stdout']
            fragments = self.fragmenter.defragment(response)
            for fragment in fragments:
                message = Message.unpack(fragment.data)
                if message.message_type == MessageType.SESSION_CAPABILITY:
                    continue
                elif message.message_type == MessageType.RUNSPACEPOOL_STATE:
                    self.state = self._get_runspace_state(message.data)
                    if self.state in [RunspacePoolState.BROKEN,
                                      RunspacePoolState.CLOSED]:
                        raise WinRMError("Failed to initialise PSRP Runspace "
                                         "Pool")
                elif message.message_type == \
                        MessageType.APPLICATION_PRIVATE_DATA:
                    continue
                else:
                    continue

    def close(self):
        self.shell.close()
        self.state = RunspacePoolState.CLOSED

    def _session_capability(self):
        sess_cap = SessionCapability("2.3", "2.0", "1.1.0.1")
        message = Message(2, sess_cap.MESSAGE_TYPE, self.guid, None,
                          sess_cap)
        return message.pack()

    def _init_runspacepool(self):
        host_info = HostInfo(Color.DARK_YELLOW, Color.DARK_MAGENTA,
                             Coordinates(0, 18), Coordinates(0, 0), 25,
                             Size(120, 3000), Size(120, 50), Size(120, 104),
                             Size(219, 104), "Python PSRP")
        init_runspace = InitRunspacePool(1, 1, PSThreadOptions.DEFAULT,
                                         ApartmentState.UNKNOWN, host_info)
        message = Message(2, init_runspace.MESSAGE_TYPE, self.guid, None,
                          init_runspace)
        return message.pack()

    def _get_runspace_state(self, runspace_state):
        runspace_state = RunspacePoolStateMessage.unpack(runspace_state)
        return runspace_state.state


class Fragment(object):

    def __init__(self, object_id, fragment_id, data, start=False, end=False):
        self.object_id = object_id
        self.fragment_id = fragment_id
        self.start = start
        self.end = end
        self.data = data

    def pack(self):
        start_end_byte = 0
        if self.start:
            start_end_byte |= 0x1
        if self.end:
            start_end_byte |= 0x2

        data = struct.pack(">Q", self.object_id)
        data += struct.pack(">Q", self.fragment_id)
        data += struct.pack("B", start_end_byte)
        data += struct.pack(">I", len(self.data))
        data += self.data

        return data

    @staticmethod
    def unpack(data):
        object_id = struct.unpack(">Q", data[0:8])[0]
        fragment_id = struct.unpack(">Q", data[8:16])[0]

        start_end_byte = struct.unpack("B", data[16:17])[0]
        start = start_end_byte & 0x1 == 0x1
        end = start_end_byte & 0x2 == 0x2

        length = struct.unpack(">I", data[17:21])[0]
        fragment_data = data[21:length + 21]

        fragment = Fragment(object_id, fragment_id, fragment_data, start, end)
        return fragment, data[21 + length:]


class Fragmenter(object):

    def __init__(self):
        self.outgoing_object_id = 1
        self.outgoing_fragment_id = 0
        self.outgoing_buffer = b""
        self.incoming_object_id = 0
        self.incoming_fragment_id = 0
        self.incoming_buffer = b""

    def fragment(self, data):
        self.outgoing_fragment_id = 0
        message_fragment = Fragment(self.outgoing_object_id, 0, data, True,
                                    True)
        self.outgoing_object_id += 1
        self.outgoing_fragment_id += 1
        yield message_fragment

    def defragment(self, data):
        fragments = []
        while data != b"":
            fragment, data = Fragment.unpack(data)
            fragments.append(fragment)

        return fragments
