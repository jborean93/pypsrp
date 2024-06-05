# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import typing as t
import uuid
from xml.etree import ElementTree

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
    # MS-PSRP
    "pwsh": "http://schemas.microsoft.com/powershell",
    # WMI/CIM
    "b": "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd",
    "p": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/MSFT_WmiError",
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
        self.values: list[tuple[str, str, dict[str, str]]] = []

    def __str__(self) -> str:
        # can't just str({}) as the ordering is important
        entry_values = []
        for value in self.values:
            entry_values.append(f"'{value[0]}': '{value[1]}'")

        string_value = f"{{{', '.join(entry_values)}}}"
        return string_value

    def add_option(
        self,
        name: str,
        value: str,
        attributes: dict[str, str] | None = None,
    ) -> None:
        attributes = attributes if attributes is not None else {}
        self.values.append((name, value, attributes))

    def pack(self) -> ElementTree.Element:
        s = NAMESPACES["s"]
        wsman = NAMESPACES["wsman"]
        element = ElementTree.Element(f"{{{wsman}}}{self.element_name}")
        if self.must_understand:
            element.attrib[f"{{{s}}}mustUnderstand"] = "true"

        for key, value, attributes in self.values:
            ElementTree.SubElement(
                element,
                f"{{{wsman}}}{self.child_element_name}",
                Name=key,
                attrib=attributes,
            ).text = value

        return element


class OptionSet(_WSManSet):
    def __init__(self) -> None:
        super().__init__("OptionSet", "Option", True)


class SelectorSet(_WSManSet):
    def __init__(self) -> None:
        super().__init__("SelectorSet", "Selector", False)


def create_header(
    action: WSManAction,
    connection_uri: str,
    data_locale: str,
    locale: str,
    max_envelope_size: int,
    operation_timeout: int,
    resource_uri: str,
    session_id: str,
    option_set: OptionSet | None = None,
    selector_set: SelectorSet | None = None,
) -> tuple[ElementTree.Element, str]:
    """Creates a WSMan envelope header based on the configured setup."""
    s = NAMESPACES["s"]
    wsa = NAMESPACES["wsa"]
    wsman = NAMESPACES["wsman"]
    wsmv = NAMESPACES["wsmv"]
    xml = NAMESPACES["xml"]

    header = ElementTree.Element(f"{{{s}}}Header")

    ElementTree.SubElement(
        header,
        f"{{{wsa}}}Action",
        attrib={f"{{{s}}}mustUnderstand": "true"},
    ).text = action.value

    ElementTree.SubElement(
        header,
        f"{{{wsmv}}}DataLocale",
        attrib={
            f"{{{s}}}mustUnderstand": "false",
            f"{{{xml}}}lang": data_locale,
        },
    )

    ElementTree.SubElement(
        header,
        f"{{{wsman}}}Locale",
        attrib={
            f"{{{s}}}mustUnderstand": "false",
            f"{{{xml}}}lang": locale,
        },
    )

    ElementTree.SubElement(
        header,
        f"{{{wsman}}}MaxEnvelopeSize",
        attrib={f"{{{s}}}mustUnderstand": "true"},
    ).text = str(max_envelope_size)

    message_id = str(uuid.uuid4()).upper()
    ElementTree.SubElement(
        header,
        f"{{{wsa}}}MessageID",
    ).text = f"uuid:{message_id}"

    ElementTree.SubElement(
        header,
        f"{{{wsman}}}OperationTimeout",
    ).text = f"PT{operation_timeout}S"

    reply_to = ElementTree.SubElement(
        header,
        f"{{{wsa}}}ReplyTo",
    )
    ElementTree.SubElement(
        reply_to,
        f"{{{wsa}}}Address",
        attrib={f"{{{s}}}mustUnderstand": "true"},
    ).text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

    ElementTree.SubElement(
        header,
        f"{{{wsman}}}ResourceURI",
        attrib={f"{{{s}}}mustUnderstand": "true"},
    ).text = resource_uri

    ElementTree.SubElement(
        header,
        f"{{{wsmv}}}SessionId",
        attrib={f"{{{s}}}mustUnderstand": "false"},
    ).text = f"uuid:{session_id}"

    ElementTree.SubElement(header, f"{{{wsa}}}To").text = connection_uri

    if option_set is not None:
        header.append(option_set.pack())

    if selector_set is not None:
        header.append(selector_set.pack())

    return header, message_id


def create_envelope(
    header: ElementTree.Element,
    resource: ElementTree.Element | None = None,
) -> bytes:
    s = NAMESPACES["s"]

    envelope = ElementTree.Element(f"{{{s}}}Envelope")
    envelope.append(header)

    body = ElementTree.SubElement(envelope, f"{{{s}}}Body")
    if resource is not None:
        body.append(resource)

    return t.cast(bytes, ElementTree.tostring(envelope, encoding="utf-8", method="xml"))
