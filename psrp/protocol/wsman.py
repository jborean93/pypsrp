# -*- coding: utf-8 -*-2020
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import enum
import ipaddress
import logging
import typing
import uuid
import xml.etree.ElementTree as ElementTree

from urllib.parse import urlparse, ParseResult

from psrp.exceptions import (
    WSManFault,
)

log = logging.getLogger(__name__)


# [MS-WSMV] 2.2.1 Namespaces
# https://msdn.microsoft.com/en-us/library/ee878420.aspx
NAMESPACES = {
    's': 'http://www.w3.org/2003/05/soap-envelope',
    'xs': 'http://www.w3.org/2001/XMLSchema',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'wsman': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
    'wsmid': 'http://schemas.dmtf.org/wbem/wsman/identify/1/wsmanidentity.xsd',
    'wsmanfault': 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault',
    'cim': 'http://schemas.dmtf.org/wbem/wscim/1/common',
    'wsmv': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
    'cfg': 'http://schemas.microsoft.com/wbem/wsman/1/config',
    'sub': 'http://schemas.microsoft.com/wbem/wsman/1/subscription',
    'rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
    'm': 'http://schemas.microsoft.com/wbem/wsman/1/machineid',
    'cert': 'http://schemas.microsoft.com/wbem/wsman/1/config/service/certmapping',
    'plugin': 'http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration',
    'wsen': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration',
    'wsdl': 'http://schemas.xmlsoap.org/wsdl',
    'wst': 'http://schemas.xmlsoap.org/ws/2004/09/transfer',
    'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
    'wse': 'http://schemas.xmlsoap.org/ws/2004/08/eventing',
    'i': 'http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd',
    'xml': 'http://www.w3.org/XML/1998/namespace',
    'pwsh': 'http://schemas.microsoft.com/powershell',
}
# Register well known namespace prefixes so ElementTree doesn't randomly generate them, saving packet space.
[ElementTree.register_namespace(k, v) for k, v in NAMESPACES.items()]


class CommandState(enum.Enum):
    done = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"
    pending = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Pending"
    running = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"


class SignalCode(enum.Enum):
    """
    [MS-WSMV] 2.2.4.38 Signal - Code
    https://msdn.microsoft.com/en-us/library/cc251558.aspx

    The control code to send in a Signal message to the server
    """
    ctrl_c = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c"
    ctrl_break = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_break"
    terminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/Terminate"
    ps_ctrl_c = "powershell/signal/ctrl_c"


class _WSManEventRegistry(type):
    __registry = {}

    def __init__(cls, *args, **kwargs):
        super().__init__(*args, **kwargs)

        uri = getattr(cls, 'URI', None)
        if uri is None:
            return

        if uri not in cls.__registry:
            cls.__registry[uri] = cls

    def __call__(
            cls,
            data: typing.Union[bytes, ElementTree.Element],
    ):
        if isinstance(data, bytes):
            data = ElementTree.fromstring(data)

        action = data.find('s:Header/wsa:Action', namespaces=NAMESPACES).text
        new_cls = cls.__registry.get(action, cls)
        return super(_WSManEventRegistry, new_cls).__call__(data)

    @staticmethod
    def registry_entries() -> typing.List[typing.Tuple[str, str]]:
        return [(cls.__name__, uri) for uri, cls in _WSManEventRegistry.__registry.items()]


class WSManEvent(metaclass=_WSManEventRegistry):

    def __init__(
            self,
            data: ElementTree.Element,
    ):
        self._raw = data

    @property
    def header(self) -> ElementTree.Element:
        return self._raw.find('s:Header', namespaces=NAMESPACES)

    @property
    def body(self) -> ElementTree.Element:
        return self._raw.find('s:Body', namespaces=NAMESPACES)

    @property
    def message_id(self) -> str:
        # The XML element text starts with uuid: which we want to remove
        return self._raw.find('s:Header/wsa:MessageID', namespaces=NAMESPACES).text[5:].upper()


class WSManEventResponse(WSManEvent):
    pass


class GetEvent(WSManEvent):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'


class GetResponseEvent(WSManEventResponse):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse'


class PutEvent(WSManEvent):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Put'


class PutResponseEvent(WSManEventResponse):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse'


class CreateEvent(WSManEvent):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create'


class CreateResponseEvent(WSManEventResponse):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse'


class DeleteEvent(WSManEvent):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete'


class DeleteResponseEvent(WSManEventResponse):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse'


class EnumerateEvent(WSManEvent):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate'


class EnumerateResponseEvent(WSManEventResponse):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse'


class FaultEvent(WSManEventResponse):
    URI = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/fault'

    def __init__(
            self,
            data: ElementTree.Element,
    ):
        super().__init__(data)
        self.error = _parse_wsman_fault(data)


class PullEvent(WSManEvent):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull'


class PullResponseEvent(WSManEventResponse):
    URI = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse'


class CommandEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command'


class CommandResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse'

    @property
    def command_id(self) -> str:
        return self._raw.find('s:Body/rsp:CommandResponse/rsp:CommandId', namespaces=NAMESPACES).text


class ConnectEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect'


class ConnectResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ConnectResponse'


class DisconnectEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect'


class DisconnectResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/DisconnectResponse'


class ReceiveEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive'


class ReceiveResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse'

    @property
    def exit_code(self) -> typing.Optional[int]:
        rc = self._raw.find('s:Body/rsp:ReceiveResponse/rsp:CommandState/rsp:ExitCode', namespaces=NAMESPACES)
        if rc is not None:
            return int(rc.text)

    @property
    def command_state(self) -> typing.Optional[CommandState]:
        command_state = self._raw.find('s:Body/rsp:ReceiveResponse/rsp:CommandState', namespaces=NAMESPACES)
        if command_state is not None:
            return CommandState(command_state.attrib['State'])

    def get_streams(self) -> typing.Dict[str, typing.List[bytes]]:
        buffer = {}
        streams = self._raw.findall('s:Body/rsp:ReceiveResponse/rsp:Stream', namespaces=NAMESPACES)
        for stream in streams:
            stream_name = stream.attrib['Name']
            if stream_name not in buffer:
                buffer[stream_name] = []

            if stream.text is not None:
                stream_value = base64.b64decode(stream.text.encode('utf-8'))
                buffer[stream_name].append(stream_value)

        return buffer


class ReconnectEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect'


class ReconnectResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReconnectResponse'


class SendEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send'


class SendResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse'


class SignalEvent(WSManEvent):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal'


class SignalResponseEvent(WSManEventResponse):
    URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse'


# Build the WSManAction enum from the registered event types.
WSManAction = enum.Enum('WSManAction', _WSManEventRegistry.registry_entries(), module=__name__)
_WSManActionMap = {a.name.lower()[:-5]: a for a in WSManAction if not a.name.endswith('Response')}


class _WSManSet:
    """ Selector or OptionSet class for WSMan requests. """

    def __init__(self, element_name, child_element_name, must_understand):
        self.element_name = element_name
        self.child_element_name = child_element_name
        self.must_understand = must_understand
        self.values = []

    def __str__(self):
        # can't just str({}) as the ordering is important
        entry_values = []
        for value in self.values:
            entry_values.append("'%s': '%s'" % (value[0], value[1]))

        string_value = "{%s}" % ", ".join(entry_values)
        return string_value

    def add_option(self, name, value, attributes=None):
        attributes = attributes if attributes is not None else {}
        self.values.append((name, value, attributes))

    def pack(self):
        s = NAMESPACES['s']
        wsman = NAMESPACES['wsman']
        element = ElementTree.Element("{%s}%s" % (wsman, self.element_name))
        if self.must_understand:
            element.attrib['{%s}mustUnderstand' % s] = "true"

        for key, value, attributes in self.values:
            ElementTree.SubElement(
                element, "{%s}%s" % (wsman, self.child_element_name), Name=key, attrib=attributes
            ).text = str(value)

        return element


class OptionSet(_WSManSet):

    def __init__(self):
        super().__init__("OptionSet", "Option", True)


class SelectorSet(_WSManSet):

    def __init__(self):
        super().__init__("SelectorSet", "Selector", False)


class WSMan:
    """WSMan connection object.

    This handles creating and processing WSMan envelopes in an IO-less way. Based on the `hyper-h2`_ project in which
    this focuses exclusively on the WSMan protocol.

    Parameters:
        connection_uri:
        max_envelope_size:
        operation_timeout:
        locale:
        data_locale:

    .. _hyper-h2:
        https://github.com/python-hyper/hyper-h2
    """

    def __init__(
            self,
            connection_uri: str,
            max_envelope_size: int = 153600,
            operation_timeout: int = 20,
            locale: str = 'en-US',
            data_locale: typing.Optional[str] = None,
    ):
        self.connection_uri = connection_uri
        self.session_id = str(uuid.uuid4())
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout
        self.locale = locale
        self.data_locale = data_locale
        if self.data_locale is None:
            self.data_locale = self.locale

        self._data_to_send = bytearray()
        self._outstanding_requests = set()

    def __getattr__(self, item):
        if item not in _WSManActionMap:
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, item))

        def invoke_action(*args, **kwargs):
            return self._invoke(_WSManActionMap[item], *args, **kwargs)
        return invoke_action

    def data_to_send(
            self,
            amount: typing.Optional[int] = None,
    ) -> bytes:
        if amount is None:
            amount = len(self._data_to_send)

        data = bytes(self._data_to_send[:amount])
        self._data_to_send = self._data_to_send[amount:]
        return data

    def receive_data(
            self,
            data: bytes,
    ) -> WSManEvent:
        event = WSManEvent(data)

        # TODO: Handle this
        # if isinstance(event, WSManEventResponse):
        #     if event.message_id not in self._outstanding_requests:
        #         raise Exception("Unknown response from server")
        #     self._outstanding_requests.remove(event.message_id)
        # else:
        #     self._outstanding_requests.add(event.message_id)

        if isinstance(event, FaultEvent):
            raise event.error

        return event

    def _create_header(
            self,
            action: WSManAction,
            resource_uri: str,
            option_set: typing.Optional[OptionSet] = None,
            selector_set: typing.Optional[SelectorSet] = None,
            timeout: typing.Optional[int] = None,
    ) -> typing.Tuple[ElementTree.Element, str]:
        """ Creates a WSMan envelope header based on the configured setup. """
        log.debug("Creating WSMan header (Action: %s, Resource URI: %s, Option Set: %s, Selector Set: %s"
                  % (action, resource_uri, option_set, selector_set))
        s = NAMESPACES['s']
        wsa = NAMESPACES['wsa']
        wsman = NAMESPACES['wsman']
        wsmv = NAMESPACES['wsmv']
        xml = NAMESPACES['xml']

        header = ElementTree.Element("{%s}Header" % s)

        ElementTree.SubElement(
            header,
            "{%s}Action" % wsa,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = action.value

        ElementTree.SubElement(
            header,
            "{%s}DataLocale" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false", "{%s}lang" % xml: self.data_locale}
        )

        ElementTree.SubElement(
            header,
            "{%s}Locale" % wsman,
            attrib={"{%s}mustUnderstand" % s: "false", "{%s}lang" % xml: self.locale}
        )

        ElementTree.SubElement(
            header,
            "{%s}MaxEnvelopeSize" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = str(self.max_envelope_size)

        message_id = str(uuid.uuid4()).upper()
        ElementTree.SubElement(header, "{%s}MessageID" % wsa).text = "uuid:%s" % message_id

        ElementTree.SubElement(
            header,
            "{%s}OperationTimeout" % wsman
        ).text = "PT%sS" % str(timeout or self.operation_timeout)

        reply_to = ElementTree.SubElement(header, "{%s}ReplyTo" % wsa)
        ElementTree.SubElement(
            reply_to,
            "{%s}Address" % wsa,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

        ElementTree.SubElement(
            header,
            "{%s}ResourceURI" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = resource_uri

        ElementTree.SubElement(
            header,
            "{%s}SessionId" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false"}
        ).text = "uuid:%s" % str(self.session_id).upper()

        ElementTree.SubElement(header, "{%s}To" % wsa).text = self.connection_uri

        if option_set is not None:
            header.append(option_set.pack())

        if selector_set is not None:
            header.append(selector_set.pack())

        return header, message_id

    def _invoke(
            self,
            action: WSManAction,
            resource_uri: str,
            resource: typing.Optional[ElementTree.Element] = None,
            option_set: typing.Optional[OptionSet] = None,
            selector_set: typing.Optional[SelectorSet] = None,
            timeout: typing.Optional[int] = None
    ):
        s = NAMESPACES['s']
        envelope = ElementTree.Element("{%s}Envelope" % s)

        header, message_id = self._create_header(action, resource_uri, option_set, selector_set, timeout)
        envelope.append(header)
        body = ElementTree.SubElement(envelope, "{%s}Body" % s)
        if resource is not None:
            body.append(resource)

        content = ElementTree.tostring(envelope, encoding='utf-8', method='xml')
        self._data_to_send += content


def _build_connection_uri(
        server: str,
        ssl: bool = False,
        port: typing.Optional[int] = None,
        path: typing.Optional[int] = None,
) -> ParseResult:
    """ Builds the connection URI for WSMan. """
    parsed_server = urlparse(server)

    # If the scheme (http:|https:) was specified then we use the URL literally.
    if parsed_server.scheme:
        return parsed_server

    scheme = 'https' if ssl else 'http'

    if port is None:
        port = 5985 if scheme == 'http' else 5986

    # Check if the server is an IPv6 Address, enclose in [] if it is
    try:
        address = ipaddress.IPv6Address(server)
    except ipaddress.AddressValueError:
        pass
    else:
        server = '[%s]' % address.compressed

    if not path:
        path = 'wsman'

    return urlparse('%s://%s:%s/%s' % (scheme, server, port, path))


def _parse_wsman_fault(
        envelope: ElementTree.Element
) -> WSManFault:
    """ Processes a WSManFault response into a structure exception object. """
    xml = envelope
    code = None
    reason = None
    machine = None
    provider = None
    provider_path = None
    provider_fault = None

    fault = xml.find("s:Body/s:Fault", namespaces=NAMESPACES)
    if fault is not None:
        code_info = fault.find("s:Code/s:Subcode/s:Value", namespaces=NAMESPACES)

        if code_info is not None:
            code = code_info.text

        else:
            code_info = fault.find("s:Code/s:Value", namespaces=NAMESPACES)
            if code_info is not None:
                code = code_info.text

        reason_info = fault.find("s:Reason/s:Text", namespaces=NAMESPACES)
        if reason_info is not None:
            reason = reason_info.text

    wsman_fault = fault.find("s:Detail/wsmanfault:WSManFault", namespaces=NAMESPACES)
    if wsman_fault is not None:
        code = wsman_fault.attrib.get('Code', code)
        machine = wsman_fault.attrib.get('Machine')

        message_info = wsman_fault.find("wsmanfault:Message", namespaces=NAMESPACES)
        if message_info is not None:
            # Message may still not be set, fall back to the existing reason value from the base soap Fault element.
            reason = message_info.text if message_info.text else reason

        provider_info = wsman_fault.find("wsmanfault:Message/wsmanfault:ProviderFault", namespaces=NAMESPACES)
        if provider_info is not None:
            provider = provider_info.attrib.get('provider')
            provider_path = provider_info.attrib.get('path')
            provider_fault = [provider_info.text]
            for fault_entry in provider_info:
                fault_info = ElementTree.tostring(fault_entry, encoding='utf-8', method='xml').decode('utf-8')
                provider_fault.append(fault_info)

            provider_fault = ", ".join([f.strip() for f in provider_fault if f.strip()])

    # Lastly try and cleanup the value of the parameters.
    try:
        code = int(code)
    except (TypeError, ValueError):
        pass

    if reason:
        reason = reason.strip()

    if provider_fault:
        provider_fault = provider_fault.strip()

    return WSManFault(code=code, machine=machine, reason=reason, provider=provider, provider_path=provider_path,
                      provider_fault=provider_fault)
