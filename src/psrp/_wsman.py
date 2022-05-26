# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import enum
import logging
import typing as t
import uuid
from xml.etree import ElementTree

from ._exceptions import WSManFault

log = logging.getLogger(__name__)


# [MS-WSMV] 2.2.1 Namespaces
# https://msdn.microsoft.com/en-us/library/ee878420.aspx
NAMESPACES = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "xs": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsman": "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "wsmid": "http://schemas.dmtf.org/wbem/wsman/identify/1/wsmanidentity.xsd",
    "wsmanfault": "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault",
    "cim": "http://schemas.dmtf.org/wbem/wscim/1/common",
    "wsmv": "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
    "cfg": "http://schemas.microsoft.com/wbem/wsman/1/config",
    "sub": "http://schemas.microsoft.com/wbem/wsman/1/subscription",
    "rsp": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "m": "http://schemas.microsoft.com/wbem/wsman/1/machineid",
    "cert": "http://schemas.microsoft.com/wbem/wsman/1/config/service/certmapping",
    "plugin": "http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wsdl": "http://schemas.xmlsoap.org/wsdl",
    "wst": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
    "wsp": "http://schemas.xmlsoap.org/ws/2004/09/policy",
    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "i": "http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd",
    "xml": "http://www.w3.org/XML/1998/namespace",
    "pwsh": "http://schemas.microsoft.com/powershell",
}
# Register well known namespace prefixes so ElementTree doesn't randomly generate them, saving packet space.
for k, v in NAMESPACES.items():
    ElementTree.register_namespace(k, v)


class CommandState(enum.Enum):
    DONE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"
    PENDING = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Pending"
    RUNNING = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"


class SignalCode(enum.Enum):
    """
    [MS-WSMV] 2.2.4.38 Signal - Code
    https://msdn.microsoft.com/en-us/library/cc251558.aspx

    The control code to send in a Signal message to the server
    """

    CTRL_C = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c"
    CTRL_BREAK = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_break"
    TERMINATE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/Terminate"
    PS_CRTL_C = "powershell/signal/crtl_c"


class WSManAction(enum.Enum):
    GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
    GET_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
    PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
    PUT_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse"
    CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
    CREATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse"
    DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
    DELETE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"
    ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
    ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
    FAULT = "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault"
    FAULT_ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault"
    PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
    PULL_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse"
    COMMAND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
    COMMAND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse"
    CONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect"
    CONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ConnectResponse"
    DISCONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect"
    DISCONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/DisconnectResponse"
    RECEIVE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
    RECEIVE_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse"
    RECONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect"
    RECONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReconnectResponse"
    SEND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
    SEND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse"
    SIGNAL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
    SIGNAL_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse"


class _WSManEventRegistry(type):
    __registry: t.Dict[str, "_WSManEventRegistry"] = {}

    def __init__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        action: t.Optional[WSManAction] = getattr(cls, "ACTION", None)
        if action is None:
            return

        if action.value not in cls.__registry:
            cls.__registry[action.value] = cls

    def __call__(  # type: ignore[override]
        cls,
        data: ElementTree.Element,
    ) -> t.Any:
        action = data.find("s:Header/wsa:Action", namespaces=NAMESPACES)
        new_cls = cls.__registry.get(getattr(action, "text", None) or "", cls)
        return super(_WSManEventRegistry, new_cls).__call__(data)


class WSManEvent(metaclass=_WSManEventRegistry):
    def __init__(
        self,
        data: ElementTree.Element,
    ):
        self._raw = data

    @property
    def header(self) -> ElementTree.Element:
        """The WSMan header XML Element."""
        return self._raw.find("s:Header", namespaces=NAMESPACES)  # type: ignore[return-value]

    @property
    def body(self) -> ElementTree.Element:
        """The WSMan body XML Element."""
        return self._raw.find("s:Body", namespaces=NAMESPACES)  # type: ignore[return-value]

    @property
    def message_id(self) -> uuid.UUID:
        """The unique message identifier of the message."""
        message_id = t.cast(ElementTree.Element, self._raw.find("s:Header/wsa:MessageID", namespaces=NAMESPACES))

        # The XML element text starts with uuid: which should be removed
        return uuid.UUID(t.cast(str, message_id.text)[5:])


class GetEvent(WSManEvent):
    ACTION = WSManAction.GET


class GetResponseEvent(WSManEvent):
    ACTION = WSManAction.GET_RESPONSE


class PutEvent(WSManEvent):
    ACTION = WSManAction.PUT


class PutResponseEvent(WSManEvent):
    ACTION = WSManAction.PUT_RESPONSE


class CreateEvent(WSManEvent):
    ACTION = WSManAction.CREATE


class CreateResponseEvent(WSManEvent):
    ACTION = WSManAction.CREATE_RESPONSE


class DeleteEvent(WSManEvent):
    ACTION = WSManAction.DELETE


class DeleteResponseEvent(WSManEvent):
    ACTION = WSManAction.DELETE_RESPONSE


class EnumerateEvent(WSManEvent):
    ACTION = WSManAction.ENUMERATE


class EnumerateResponseEvent(WSManEvent):
    ACTION = WSManAction.ENUMERATE_RESPONSE


class FaultEvent(WSManEvent):
    ACTION = WSManAction.FAULT

    def __init__(
        self,
        data: ElementTree.Element,
    ):
        super().__init__(data)
        self.error = _parse_wsman_fault(data)


class FaultAddressingEvent(FaultEvent):
    ACTION = WSManAction.FAULT_ADDRESSING


class PullEvent(WSManEvent):
    ACTION = WSManAction.PULL


class PullResponseEvent(WSManEvent):
    ACTION = WSManAction.PULL_RESPONSE


class CommandEvent(WSManEvent):
    ACTION = WSManAction.COMMAND


class CommandResponseEvent(WSManEvent):
    ACTION = WSManAction.COMMAND_RESPONSE

    @property
    def command_id(self) -> uuid.UUID:
        """The unique command identifier of the command that was created."""
        command_id = t.cast(
            ElementTree.Element, self._raw.find("s:Body/rsp:CommandResponse/rsp:CommandId", namespaces=NAMESPACES)
        )
        return uuid.UUID(command_id.text or "")


class ConnectEvent(WSManEvent):
    ACTION = WSManAction.CONNECT


class ConnectResponseEvent(WSManEvent):
    ACTION = WSManAction.CONNECT_RESPONSE


class DisconnectEvent(WSManEvent):
    ACTION = WSManAction.DISCONNECT


class DisconnectResponseEvent(WSManEvent):
    ACTION = WSManAction.DISCONNECT_RESPONSE


class ReceiveEvent(WSManEvent):
    ACTION = WSManAction.RECEIVE


class ReceiveResponseEvent(WSManEvent):
    ACTION = WSManAction.RECEIVE_RESPONSE

    @property
    def command_state(self) -> t.Optional[CommandState]:
        """Describes the current state of the command."""
        command_state = self._raw.find("s:Body/rsp:ReceiveResponse/rsp:CommandState", namespaces=NAMESPACES)
        return CommandState(command_state.attrib["State"]) if command_state is not None else None

    @property
    def streams(self) -> t.Dict[str, t.List[bytes]]:
        """Returns the raw command output separated by each stream it was written to."""
        buffer: t.Dict[str, t.List[bytes]] = {}
        streams = self._raw.findall("s:Body/rsp:ReceiveResponse/rsp:Stream", namespaces=NAMESPACES)
        for stream in streams:
            stream_name = stream.attrib["Name"]
            if stream_name not in buffer:
                buffer[stream_name] = []

            if stream.text is not None:
                stream_value = base64.b64decode(stream.text.encode("utf-8"))
                buffer[stream_name].append(stream_value)

        return buffer


class ReconnectEvent(WSManEvent):
    ACTION = WSManAction.RECONNECT


class ReconnectResponseEvent(WSManEvent):
    ACTION = WSManAction.RECONNECT_RESPONSE


class SendEvent(WSManEvent):
    ACTION = WSManAction.SEND


class SendResponseEvent(WSManEvent):
    ACTION = WSManAction.SEND_RESPONSE


class SignalEvent(WSManEvent):
    ACTION = WSManAction.SIGNAL


class SignalResponseEvent(WSManEvent):
    ACTION = WSManAction.SIGNAL_RESPONSE


class _WSManSet:
    """Selector or OptionSet class for WSMan requests."""

    def __init__(
        self,
        element_name: str,
        child_element_name: str,
        must_understand: bool,
    ) -> None:
        self.element_name = element_name
        self.child_element_name = child_element_name
        self.must_understand = must_understand
        self.values: t.List[t.Tuple[str, str, t.Dict[str, str]]] = []

    def __str__(self) -> str:
        # can't just str({}) as the ordering is important
        entry_values = []
        for value in self.values:
            entry_values.append("'%s': '%s'" % (value[0], value[1]))

        string_value = "{%s}" % ", ".join(entry_values)
        return string_value

    def add_option(
        self,
        name: str,
        value: str,
        attributes: t.Optional[t.Dict[str, str]] = None,
    ) -> None:
        attributes = attributes if attributes is not None else {}
        self.values.append((name, value, attributes))

    def pack(self) -> ElementTree.Element:
        s = NAMESPACES["s"]
        wsman = NAMESPACES["wsman"]
        element = ElementTree.Element("{%s}%s" % (wsman, self.element_name))
        if self.must_understand:
            element.attrib["{%s}mustUnderstand" % s] = "true"

        for key, value, attributes in self.values:
            ElementTree.SubElement(
                element, "{%s}%s" % (wsman, self.child_element_name), Name=key, attrib=attributes
            ).text = value

        return element


class OptionSet(_WSManSet):
    def __init__(self) -> None:
        super().__init__("OptionSet", "Option", True)


class SelectorSet(_WSManSet):
    def __init__(self) -> None:
        super().__init__("SelectorSet", "Selector", False)


class WSMan:
    """WSMan Message Processor.

    This handles creating and processing WSMan envelopes in an IO-less way. New
    messages are queued through the various action functions like
    :meth:`command`, :meth:`create`, :meth:`signal`, etc. The
    :meth:`data_to_send` function is used to get the data to send to the peer
    and :meth:`receive_data` is used to process data from the peer into WSMan
    events.

    Parameters:
        connection_uri: The connection URI used as the target.
        max_envelope_size: The maximum WSMan envelope size allowed.
        operation_timeout: The timeout in seconds that each WSMan operation
            can take on the peer before timing out.
        locale: The locale language string.
        data_locale: The data locale language string.
    """

    def __init__(
        self,
        connection_uri: str,
        max_envelope_size: int = 153600,
        operation_timeout: int = 20,
        locale: str = "en-US",
        data_locale: t.Optional[str] = None,
    ) -> None:
        self.connection_uri = connection_uri
        self.session_id = str(uuid.uuid4())
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout
        self.locale = locale
        self.data_locale = data_locale if data_locale else locale

        self._data_to_send = bytearray()

    def command(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.COMMAND,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def connect(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.CONNECT,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def create(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.CREATE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def delete(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.DELETE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def disconnect(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.DISCONNECT,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def enumerate(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.ENUMERATE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def receive(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.RECEIVE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def reconnect(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.RECONNECT,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def send(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.SEND,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def signal(
        self,
        resource_uri: str,
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        return self._invoke(
            WSManAction.SIGNAL,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def data_to_send(
        self,
        amount: t.Optional[int] = None,
    ) -> bytes:
        """Get a set amount of data to send.

        Gets the data in the queue waiting to be sent to the peer.

        Args:
            amount: The maximum length of data that can be sent.

        Returns:
            bytes: The data to send.
        """
        if amount is None:
            amount = len(self._data_to_send)

        data = bytes(self._data_to_send[:amount])
        self._data_to_send = self._data_to_send[amount:]
        return data

    def receive_data(
        self,
        data: bytes,
    ) -> WSManEvent:
        """Receive raw WSMan payload.

        Receives the raw WSMan payloads and converts it to a WSMan event
        representing the type of response received.

        Args:
            data: The raw bytes to process.

        Returns:
            WSManEvent: The processed WSMan event.

        Raises:
            WSManFault: Raised when a WSMan Fault message is processed and
                contains the fault information.
        """
        wsman_data = ElementTree.fromstring(data)
        event = WSManEvent(wsman_data)

        if isinstance(event, FaultEvent):
            raise event.error

        return event

    def _create_header(
        self,
        action: WSManAction,
        resource_uri: str,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> t.Tuple[ElementTree.Element, str]:
        """Creates a WSMan envelope header based on the configured setup."""
        log.debug(
            "Creating WSMan header (Action: %s, Resource URI: %s, Option Set: %s, Selector Set: %s"
            % (action, resource_uri, option_set, selector_set)
        )
        s = NAMESPACES["s"]
        wsa = NAMESPACES["wsa"]
        wsman = NAMESPACES["wsman"]
        wsmv = NAMESPACES["wsmv"]
        xml = NAMESPACES["xml"]

        header = ElementTree.Element("{%s}Header" % s)

        ElementTree.SubElement(
            header, "{%s}Action" % wsa, attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = action.value

        ElementTree.SubElement(
            header,
            "{%s}DataLocale" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false", "{%s}lang" % xml: self.data_locale},
        )

        ElementTree.SubElement(
            header, "{%s}Locale" % wsman, attrib={"{%s}mustUnderstand" % s: "false", "{%s}lang" % xml: self.locale}
        )

        ElementTree.SubElement(
            header, "{%s}MaxEnvelopeSize" % wsman, attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = str(self.max_envelope_size)

        message_id = str(uuid.uuid4()).upper()
        ElementTree.SubElement(header, "{%s}MessageID" % wsa).text = "uuid:%s" % message_id

        ElementTree.SubElement(header, "{%s}OperationTimeout" % wsman).text = "PT%sS" % str(
            timeout or self.operation_timeout
        )

        reply_to = ElementTree.SubElement(header, "{%s}ReplyTo" % wsa)
        ElementTree.SubElement(
            reply_to, "{%s}Address" % wsa, attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

        ElementTree.SubElement(
            header, "{%s}ResourceURI" % wsman, attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = resource_uri

        ElementTree.SubElement(header, "{%s}SessionId" % wsmv, attrib={"{%s}mustUnderstand" % s: "false"}).text = (
            "uuid:%s" % str(self.session_id).upper()
        )

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
        resource: t.Optional[ElementTree.Element] = None,
        option_set: t.Optional[OptionSet] = None,
        selector_set: t.Optional[SelectorSet] = None,
        timeout: t.Optional[int] = None,
    ) -> str:
        s = NAMESPACES["s"]
        envelope = ElementTree.Element("{%s}Envelope" % s)

        header, message_id = self._create_header(action, resource_uri, option_set, selector_set, timeout)
        envelope.append(header)
        body = ElementTree.SubElement(envelope, "{%s}Body" % s)
        if resource is not None:
            body.append(resource)

        content = ElementTree.tostring(envelope, encoding="utf-8", method="xml")
        self._data_to_send += content

        return message_id


def _parse_wsman_fault(
    envelope: ElementTree.Element,
) -> WSManFault:
    """Processes a WSManFault response into a structure exception object."""
    xml = envelope
    code_str: t.Optional[str] = None
    reason = None
    machine = None
    provider = None
    provider_path = None
    provider_fault: t.Optional[str] = None

    fault = xml.find("s:Body/s:Fault", namespaces=NAMESPACES)
    if fault is not None:
        code_info = fault.find("s:Code/s:Subcode/s:Value", namespaces=NAMESPACES)

        if code_info is not None:
            code_str = code_info.text

        else:
            code_info = fault.find("s:Code/s:Value", namespaces=NAMESPACES)
            if code_info is not None:
                code_str = code_info.text

        reason_info = fault.find("s:Reason/s:Text", namespaces=NAMESPACES)
        if reason_info is not None:
            reason = reason_info.text

        wsman_fault = fault.find("s:Detail/wsmanfault:WSManFault", namespaces=NAMESPACES)
        if wsman_fault is not None:
            code_str = wsman_fault.attrib.get("Code", code_str)
            machine = wsman_fault.attrib.get("Machine")

            message_info = wsman_fault.find("wsmanfault:Message", namespaces=NAMESPACES)
            if message_info is not None:
                # Message may still not be set, fall back to the existing reason value from the base soap Fault element.
                reason = message_info.text if message_info.text else reason

            provider_info = wsman_fault.find("wsmanfault:Message/wsmanfault:ProviderFault", namespaces=NAMESPACES)
            if provider_info is not None:
                provider = provider_info.attrib.get("provider")
                provider_path = provider_info.attrib.get("path")
                faults = [provider_info.text or ""]
                for fault_entry in provider_info:
                    fault_info = ElementTree.tostring(fault_entry, encoding="utf-8", method="xml").decode("utf-8")
                    faults.append(fault_info)

                provider_fault = ", ".join([f.strip() for f in faults if f.strip()])

    # Lastly try and cleanup the value of the parameters.
    code: t.Optional[int] = None
    if code_str:
        try:
            code = int(code_str)
        except ValueError:
            pass

    if reason:
        reason = reason.strip()

    if provider_fault:
        provider_fault = provider_fault.strip()

    return WSManFault(
        code=code,
        machine=machine,
        reason=reason,
        provider=provider,
        provider_path=provider_path,
        provider_fault=provider_fault,
    )
