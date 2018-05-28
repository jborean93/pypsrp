# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import sys
import uuid

from pypsrp.exceptions import WinRMError, WinRMTransportError, WSManFaultError

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET

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
    "cert": "http://schemas.microsoft.com/wbem/wsman/1/config/service/"
            "certmapping",
    "plugin": "http://schemas.microsoft.com/wbem/wsman/1/config/"
              "PluginConfiguration",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wsdl": "http://schemas.xmlsoap.org/wsdl",
    "wst": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
    "wsp": "http://schemas.xmlsoap.org/ws/2004/09/policy",
    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "i": "http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd",
    "xml": "http://www.w3.org/XML/1998/namespace",
    "pwsh": "http://schemas.microsoft.com/powershell",
}


class WSManAction(object):
    # WS-Management URIs
    GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
    GET_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
    PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
    PUT_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse"
    CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
    CREATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/" \
                      "CreateResponse"
    DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
    DELETE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/" \
                      "DeleteResponse"
    ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
    ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/" \
                         "EnumerateResponse"

    # MS-WSMV URIs
    COMMAND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
    COMMAND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/CommandResponse"
    CONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect"
    CONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/ConnectResponse"
    DISCONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
                 "Disconnect"
    DISCONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/" \
                          "windows/shell/DisconnectResponse"
    RECEIVE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
    RECEIVE_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/ReceiveResponse"
    RECONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
                "Reconnect"
    RECONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                         "shell/ReconnectResponse"
    SEND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
    SEND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                    "shell/SendResponse"
    SIGNAL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
    SIGNAL_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                      "shell/SignalResponse"


class WSMan(object):

    def __init__(self, transport, max_envelope_size=153600,
                 operation_timeout=60):
        """
        Class that handles the WS-Man actions that are required. This is a
        fairly thin wrapper that exposes a method per action that takes in a
        resource and the header metadata required by that resource.

        https://msdn.microsoft.com/en-us/library/cc251598.aspx

        :param transport: The transport to send the SOAP messages over
        :param max_envelope_size: The maximum size of the envelope that can be
            sent to the server. Use update_max_envelope_size() to query the
            server for the true value
        :param locale: Specifies the language in which the client wants the
            response text to be translated.
        :param data_locale: Language in which the response text should be
            formatted.
        :param operation_timeout: Indicates that the client expects a response
            or a fault within the specified time.
        """
        log.info("Initialising WSMan class with maximum envelope size of %d "
                 "and operation timeout of %s"
                 % (max_envelope_size, operation_timeout))
        self.session_id = str(uuid.uuid4())
        self.transport = transport
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout

        # register well known namespace prefixes so ElementTree doesn't
        # randomly generate them
        for key, value in NAMESPACES.items():
            ET.register_namespace(key, value)

        # This is the approx max size of a Base64 string that can be sent in a
        # SOAP message payload (PSRP fragment or send input data) to the
        # server. This value is dependent on the server's MaxEnvelopSizekb
        # value set on the WinRM service and the default is different depending
        # on the Windows version. Server 2008 (R2) detaults to 150KiB while
        # newer hosts are 500 KiB and this can be configured manually. Because
        # we don't know the OS version before we connect, we set the default to
        # 150KiB to ensure we are compatible with older hosts. This can be
        # manually adjusted with the max_envelope_size param which is the
        # MaxEnvelopeSizekb value * 1024. Otherwise the
        # update_max_envelope_size() function can be called and it will gather
        # this information for you.
        self._max_payload_size = self._calc_envelope_size(max_envelope_size)

    def command(self, resource_uri, resource, option_set=None,
                selector_set=None):
        header = self._create_header(WSManAction.COMMAND, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def connect(self, resource_uri, resource, option_set=None,
                selector_set=None):
        header = self._create_header(WSManAction.CONNECT, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def create(self, resource_uri, resource, option_set=None,
               selector_set=None):
        header = self._create_header(WSManAction.CREATE, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def disconnect(self, resource_uri, resource, option_set=None,
                   selector_set=None):
        header = self._create_header(WSManAction.DISCONNECT, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def delete(self, resource_uri, resource=None, option_set=None,
               selector_set=None):
        header = self._create_header(WSManAction.DELETE, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def enumerate(self, resource_uri, resource=None, option_set=None,
                  selector_set=None):
        header = self._create_header(WSManAction.ENUMERATE, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def get(self, resource_uri, resource=None, option_set=None,
            selector_set=None):
        header = self._create_header(WSManAction.GET, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def receive(self, resource_uri, resource, option_set=None,
                selector_set=None):
        header = self._create_header(WSManAction.RECEIVE, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def reconnect(self, resource_uri, resource=None, option_set=None,
                  selector_set=None):
        header = self._create_header(WSManAction.RECONNECT, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def send(self, resource_uri, resource, option_set=None,
             selector_set=None):
        header = self._create_header(WSManAction.SEND, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def signal(self, resource_uri, resource, option_set=None,
               selector_set=None):
        header = self._create_header(WSManAction.SIGNAL, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def get_server_config(self, uri="config"):
        resource_uri = "http://schemas.microsoft.com/wbem/wsman/1/%s" % uri
        log.info("Getting server config with URI %s" % resource_uri)
        return self.get(resource_uri)

    def update_max_payload_size(self):
        config = self.get_server_config()
        max_size_kb = config.find("cfg:Config/"
                                  "cfg:MaxEnvelopeSizekb",
                                  namespaces=NAMESPACES).text

        server_max_size = int(max_size_kb) * 1024
        max_envelope_size = self._calc_envelope_size(server_max_size)
        self.max_envelope_size = server_max_size
        self._max_payload_size = max_envelope_size

    def _invoke(self, header, resource):
        s = NAMESPACES['s']
        envelope = ET.Element("{%s}Envelope" % s)
        envelope.append(header)

        body = ET.SubElement(envelope, "{%s}Body" % s)
        if resource is not None:
            body.append(resource)

        message_id = header.find("wsa:MessageID", namespaces=NAMESPACES).text
        xml = ET.tostring(envelope, encoding='utf-8', method='xml')

        try:
            response = self.transport.send(xml)
        except WinRMTransportError as err:
            try:
                # try and parse the XML and get the WSManFault
                raise self._parse_wsman_fault(err.response_text)
            except ET.ParseError:
                # no XML message is present so not a WSManFault error
                log.warning("Failed to parse WSManFault message on WinRM error"
                            " response, raising original WinRMTransportError")
                raise err

        response_xml = ET.fromstring(response)
        relates_to = response_xml.find("s:Header/wsa:RelatesTo",
                                       namespaces=NAMESPACES).text

        if message_id != relates_to:
            raise WinRMError("Received related id does not match related "
                             "expected message id: Sent: %s, Received: %s"
                             % (message_id, relates_to))

        response_body = response_xml.find("s:Body", namespaces=NAMESPACES)
        return response_body

    def _calc_envelope_size(self, max_envelope_size):
        # get a mock Header which should cover most cases where large fragments
        # are used
        empty_uuid = "00000000-0000-0000-0000-000000000000"

        selector_set = SelectorSet()
        selector_set.add_option("ShellId", empty_uuid)
        header = self._create_header(
            WSManAction.SEND,
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            selector_set=selector_set
        )

        # get a skeleton Body to calculate the size without the payload
        rsp = NAMESPACES['rsp']
        send = ET.Element("{%s}Send" % rsp)
        ET.SubElement(send, "{%s}Stream" % rsp, Name="stdin",
                      CommandId=empty_uuid).text = ""

        envelope = ET.Element("{%s}Envelope" % NAMESPACES['s'])
        envelope.append(header)
        envelope.append(send)
        envelope = ET.tostring(envelope, encoding='utf-8', method='xml')

        # add the Header and Envelope and pad some extra bytes to cover
        # slightly different scenarios, multiple options, different body types
        # while this isn't perfect it's better than wasting CPU cycles
        # calculating it per message and a few bytes don't make too much of a
        # difference
        envelope_size = len(envelope) + 256
        max_bytes_size = max_envelope_size - envelope_size

        # Data is sent as Base64 encoded which inflates the size, we need to
        # calculate how large that can be
        base64_size = int(max_bytes_size / 4 * 3)
        return base64_size

    def _create_header(self, action, resource_uri, option_set=None,
                       selector_set=None):
        log.debug("Creating WSMan header (Action: %s, Resource URI: %s, "
                  "Option Set: %s, Selector Set: %s"
                  % (action, resource_uri, option_set, selector_set))
        s = NAMESPACES['s']
        wsa = NAMESPACES['wsa']
        wsman = NAMESPACES['wsman']
        wsmv = NAMESPACES['wsmv']
        xml = NAMESPACES['xml']

        header = ET.Element("{%s}Header" % s)

        ET.SubElement(
            header,
            "{%s}Action" % wsa,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = action

        ET.SubElement(
            header,
            "{%s}DataLocale" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false",
                    "{%s}lang" % xml: "en-US"}
        )

        ET.SubElement(
            header,
            "{%s}Locale" % wsman,
            attrib={"{%s}mustUnderstand" % s: "false",
                    "{%s}lang" % xml: "en-US"}
        )

        ET.SubElement(
            header,
            "{%s}MaxEnvelopeSize" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = str(self.max_envelope_size)

        ET.SubElement(header, "{%s}MessageID" % wsa).text = \
            "uuid:%s" % str(uuid.uuid4()).upper()

        ET.SubElement(
            header,
            "{%s}OperationTimeout" % wsman
        ).text = "PT%sS" % str(self.operation_timeout)

        reply_to = ET.SubElement(header, "{%s}ReplyTo" % wsa)
        ET.SubElement(
            reply_to,
            "{%s}Address" % wsa,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/" \
                 "anonymous"

        ET.SubElement(
            header,
            "{%s}ResourceURI" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = resource_uri

        ET.SubElement(
            header,
            "{%s}SessionId" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false"}
        ).text = "uuid:%s" % str(self.session_id).upper()

        ET.SubElement(header, "{%s}To" % wsa).text = self.transport.endpoint

        if option_set is not None:
            header.append(option_set.pack())

        if selector_set is not None:
            header.append(selector_set.pack())

        return header

    @staticmethod
    def _parse_wsman_fault(xml_text):
        xml = ET.fromstring(xml_text)
        code = None
        reason = None
        machine = None
        provider = None
        provider_path = None
        provider_fault = None

        fault = xml.find("s:Body/s:Fault", namespaces=NAMESPACES)
        if fault is not None:
            code_info = fault.find("s:Code/s:Subcode/s:Value",
                                   namespaces=NAMESPACES)
            if code_info is not None:
                code = code_info.text
            else:
                code_info = fault.find("s:Code/s:Value",
                                       namespaces=NAMESPACES)
                if code_info is not None:
                    code = code_info.text

            reason_info = fault.find("s:Reason/s:Text",
                                     namespaces=NAMESPACES)
            if reason_info is not None:
                reason = reason_info.text

        wsman_fault = fault.find("s:Detail/wsmanfault:WSManFault",
                                 namespaces=NAMESPACES)
        if wsman_fault is not None:
            code = wsman_fault.attrib.get('Code', code)
            machine = wsman_fault.attrib.get('Machine')

            message_info = wsman_fault.find("wsmanfault:Message",
                                            namespaces=NAMESPACES)
            if message_info is not None:
                # message may still not be set, fall back to the existing
                # reason value from the base soap Fault element
                reason = message_info.text if message_info.text else reason

            provider_info = wsman_fault.find("wsmanfault:Message/"
                                             "wsmanfault:ProviderFault",
                                             namespaces=NAMESPACES)
            if provider_info is not None:
                provider = provider_info.attrib.get('provider')
                provider_path = provider_info.attrib.get('path')
                provider_fault = provider_info.text

        # lastly try and cleanup the value of the parameters
        try:
            code = int(code)
        except (TypeError, ValueError):
            pass

        try:
            reason = reason.strip()
        except AttributeError:
            pass

        try:
            provider_fault = provider_fault.strip()
        except AttributeError:
            pass

        return WSManFaultError(code, machine, reason, provider,
                               provider_path,
                               provider_fault)


class _WSManSet(object):

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
        element = ET.Element("{%s}%s" % (wsman, self.element_name))
        if self.must_understand:
            element.attrib['{%s}mustUnderstand' % s] = "true"

        for key, value, attributes in self.values:
            ET.SubElement(element, "{%s}%s" % (wsman, self.child_element_name),
                          Name=key,
                          attrib=attributes).text = str(value)

        return element


class OptionSet(_WSManSet):

    def __init__(self):
        super(OptionSet, self).__init__("OptionSet", "Option", True)


class SelectorSet(_WSManSet):

    def __init__(self):
        super(SelectorSet, self).__init__("SelectorSet", "Selector", False)
