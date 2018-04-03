# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import re
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
    "i": "http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd"
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

    # MS-WSMV URIs
    COMMAND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
    COMMAND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/CommandResponse"
    RECEIVE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
    RECEIVE_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/ReceiveResponse"
    SEND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
    SEND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                    "shell/SendResponse"
    SIGNAL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
    SIGNAL_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                      "shell/SignalResponse"


def _duration_to_float(duration):
    pattern = re.compile('P(?:(?P<years>\d+)Y)'
                         '?(?:(?P<months>\d+)M)'
                         '?(?:(?P<days>\d+)D)'
                         '?(?:T(?:(?P<hours>\d+)H)'
                         '?(?:(?P<minutes>\d+)M)'
                         '?(?:(?P<seconds>\d+[.]?\d*)S)?)')
    duration_value = 0
    groups = re.match(pattern, duration)
    if groups:
        info = groups.groupdict()
        seconds = float(info['seconds'] if info['seconds'] else 0)
        minutes = float(info['minutes'] if info['minutes'] else 0)
        hours = float(info['hours'] if info['hours'] else 0)
        days = float(info['days'] if info['days'] else 0)
        months = float(info['months'] if info['months'] else 0)
        years = float(info['years'] if info['years'] else 0)

        duration_value += seconds
        duration_value += minutes * 60
        duration_value += hours * 3600
        duration_value += days * 86400
        duration_value += months * 2592000
        duration_value += years * 31536000
    else:
        raise ValueError("Expecting XML duration string but value did "
                         "not match pattern: %s" % duration)

    return duration_value


def _float_to_duration(value):
    # https://tools.ietf.org/html/rfc2445#section-4.3.6
    if isinstance(value, str):
        if value.startswith('P'):
            return value
        value = float(value)

    duration = "P"
    if value > 86400:
        days = int(value / 86400)
        value -= 86400 * days
        duration += "%dD" % days
    if value > 0:
        duration += "T"
        if value > 3600:
            hours = int(value / 3600)
            value -= 3600 * hours
            duration += "%dH" % hours
        if value > 60:
            minutes = int(value / 60)
            value -= 60 * minutes
            duration += "%dM" % minutes
        if value > 0:
            duration += "%sS" % value

    return duration


class WSMan(object):

    def __init__(self, transport, max_envelope_size=4294967295,
                 operation_timeout=60):
        """
        Class that handles the WS-Man actions that are required. This is a
        fairly thin wrapper that exposes a method per action that takes in a
        resource and the header metadata required by that resource.

        https://msdn.microsoft.com/en-us/library/cc251598.aspx

        :param transport: The transport to send the SOAP messages over
        :param max_envelope_size: The maximum size the envelope response that
            the server can send.
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

    def command(self, resource_uri, resource, option_set=None,
                selector_set=None):
        header = self._create_header(WSManAction.COMMAND, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def create(self, resource_uri, resource, option_set=None,
               selector_set=None):
        header = self._create_header(WSManAction.CREATE, resource_uri,
                                     option_set, selector_set)
        return self._invoke(header, resource)

    def delete(self, resource_uri, resource=None, option_set=None,
               selector_set=None):
        header = self._create_header(WSManAction.DELETE, resource_uri,
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

    def _create_header(self, action, resource_uri, option_set=None,
                       selector_set=None):
        log.debug("Creating WSMan header (Action: %s, Resource URI: %s, "
                  "Option Set: %s, Selector Set: %s"
                  % (action, resource_uri, option_set, selector_set))
        s = NAMESPACES['s']
        wsa = NAMESPACES['wsa']
        wsman = NAMESPACES['wsman']
        wsmv = NAMESPACES['wsmv']

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
                    "xml:lang": "en-US"}
        )

        ET.SubElement(
            header,
            "{%s}Locale" % wsman,
            attrib={"{%s}mustUnderstand" % s: "false",
                    "xml:lang": "en-US"}
        )

        ET.SubElement(
            header,
            "{%s}MaxEnvelopeSize" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = str(self.max_envelope_size)

        ET.SubElement(header, "{%s}MessageID" % wsa).text = \
            "uuid:%s" % str(uuid.uuid4()).upper()

        # ET.SubElement(
        #     header,
        #     "{%s}OperationID" % wsmv,
        #     attrib={"{%s}mustUnderstand" % s: "false"}
        # ).text = "uuid:%s" % str(uuid.uuid4()).upper()

        ET.SubElement(
            header,
            "{%s}OperationTimeout" % wsman
        ).text = _float_to_duration(self.operation_timeout)

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

        # ET.SubElement(
        #     header,
        #     "{%s}SequenceId" % wsmv,
        #     attrib={"{%s}mustUnderstand" % s: "false"}
        # ).text = "1"

        ET.SubElement(
            header,
            "{%s}SessionID" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false"}
        ).text = "uuid:%s" % str(self.session_id).upper()

        ET.SubElement(header, "{%s}To" % wsa).text = self.transport.endpoint

        if option_set is not None:
            header.append(option_set.pack())

        if selector_set is not None:
            header.append(selector_set.pack())

        return header

    def _parse_wsman_fault(self, xml_text):
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

    def _unpack(self, data):
        raise NotImplementedError()


class OptionSet(_WSManSet):

    def __init__(self):
        super(OptionSet, self).__init__("OptionSet", "Option", True)

    @staticmethod
    def unpack(data):
        option_set = OptionSet()
        option_set._unpack(data)
        return option_set


class SelectorSet(_WSManSet):

    def __init__(self):
        super(SelectorSet, self).__init__("SelectorSet", "Selector", False)

    @staticmethod
    def unpack(data):
        selector_set = SelectorSet()
        selector_set._unpack(data)
        return selector_set