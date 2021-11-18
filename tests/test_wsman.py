import os
import requests
import uuid
import xml.etree.ElementTree as ET

import pytest

from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import AuthenticationError, WinRMError, \
    WinRMTransportError, WSManFaultError
from pypsrp.negotiate import HTTPNegotiateAuth
from pypsrp.wsman import OptionSet, SelectorSet, WSMan, WSManAction, \
    NAMESPACES, _TransportHTTP

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

try:
    import requests_credssp
except ImportError:
    requests_credssp = None


class _TransportTest(object):

    def __init__(self, expected_action=None):
        self.endpoint = "testendpoint"
        self.expected_action = expected_action

    def send(self, xml):
        # ensure wsman is always sending a byte string
        assert isinstance(xml, bytes)

        if self.expected_action is None:
            # see what happens if the text is XML but not a WSManFault message
            raise WinRMTransportError("http", 401, "not an XML response")

        req = ET.fromstring(xml)
        action = req.find("s:Header/wsa:Action", NAMESPACES).text
        if action == self.expected_action:
            return '''<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
                <s:Header>
                    <wsa:RelatesTo>uuid:00000000-0000-0000-0000-000000000000</wsa:RelatesTo>
                </s:Header>
                <s:Body>body</s:Body>
            </s:Envelope>'''
        else:
            # we want to set a non XML message as the response text to verify
            # the parsing failure is checked and the original exception is
            # raised
            error_msg = '''<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action><a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo><s:NotUnderstood qname="wsman:ResourceUri" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" />
                </s:Header>
                <s:Body>
                    <s:Fault>
                        <s:Code>
                            <s:Value>IllegalAction</s:Value>
                        </s:Code>
                        <s:Reason>
                            <s:Text xml:lang="">Illegal action '%s', expecting '%s'</s:Text>
                        </s:Reason>
                    </s:Fault>
                </s:Body>
            </s:Envelope>''' % (action, self.expected_action)
            raise WinRMTransportError("http", 500, error_msg)


class TestWSMan(object):

    def test_wsman_defaults(self):
        actual = WSMan("")
        assert actual.max_envelope_size == 153600
        assert actual.max_payload_size < actual.max_envelope_size
        assert actual.operation_timeout == 20
        assert isinstance(actual.session_id, str)

        # verify we get a unique session id each time this is initialised
        new_wsman = WSMan("")
        assert actual.session_id != new_wsman.session_id

    def test_override_default(self):
        actual = WSMan("", 8192, 30)
        assert actual.max_envelope_size == 8192
        assert actual.max_payload_size < actual.max_envelope_size
        assert actual.operation_timeout == 30

    def test_invoke_command(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.COMMAND)
        actual = wsman.command("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_connect(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.CONNECT)
        actual = wsman.connect("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_create(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.CREATE)
        actual = wsman.create("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_disconnect(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.DISCONNECT)
        actual = wsman.disconnect("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_enumerate(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.ENUMERATE)
        actual = wsman.enumerate("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_delete(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.DELETE)
        actual = wsman.delete("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_get(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.GET)
        actual = wsman.get("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_pull(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.PULL)
        actual = wsman.pull("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_put(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.PUT)
        actual = wsman.put("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_receive(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.RECEIVE)
        actual = wsman.receive("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_reconnect(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.RECONNECT)
        actual = wsman.reconnect("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_send(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.SEND)
        actual = wsman.send("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_signal(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.SIGNAL)
        actual = wsman.signal("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_get_header_no_locale(self):
        wsman = WSMan("")
        actual = wsman._create_header("action", "resource", None, None, None)
        actual_data_locale = actual.find("wsmv:DataLocale", NAMESPACES)
        actual_locale = actual.find("wsman:Locale", NAMESPACES)

        xml = NAMESPACES['xml']
        assert actual_data_locale.attrib["{%s}lang" % xml] == "en-US"
        assert actual_locale.attrib["{%s}lang" % xml] == "en-US"

    def test_get_header_explicit_locale(self):
        wsman = WSMan("", locale="en-GB")
        actual = wsman._create_header("action", "resource", None, None, None)
        actual_data_locale = actual.find("wsmv:DataLocale", NAMESPACES)
        actual_locale = actual.find("wsman:Locale", NAMESPACES)

        xml = NAMESPACES['xml']
        assert actual_data_locale.attrib["{%s}lang" % xml] == "en-GB"
        assert actual_locale.attrib["{%s}lang" % xml] == "en-GB"

    def test_get_header_explicit_data_locale(self):
        wsman = WSMan("", data_locale="en-GB")
        actual = wsman._create_header("action", "resource", None, None, None)
        actual_data_locale = actual.find("wsmv:DataLocale", NAMESPACES)
        actual_locale = actual.find("wsman:Locale", NAMESPACES)

        xml = NAMESPACES['xml']
        assert actual_data_locale.attrib["{%s}lang" % xml] == "en-GB"
        assert actual_locale.attrib["{%s}lang" % xml] == "en-US"

    def test_get_header_explicit_both_locale(self):
        wsman = WSMan("", locale="en-AU", data_locale="en-GB")
        actual = wsman._create_header("action", "resource", None, None, None)
        actual_data_locale = actual.find("wsmv:DataLocale", NAMESPACES)
        actual_locale = actual.find("wsman:Locale", NAMESPACES)

        xml = NAMESPACES['xml']
        assert actual_data_locale.attrib["{%s}lang" % xml] == "en-GB"
        assert actual_locale.attrib["{%s}lang" % xml] == "en-AU"

    def test_invoke_mismatch_id(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000001")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.SEND)
        with pytest.raises(WinRMError) as exc:
            wsman.send("", None)
        assert str(exc.value) == \
            "Received related id does not match related expected message " \
            "id: Sent: uuid:00000000-0000-0000-0000-000000000001, Received: " \
            "uuid:00000000-0000-0000-0000-000000000000"

    def test_invoke_transport_error(self):
        wsman = WSMan("")
        wsman.transport = _TransportTest()
        with pytest.raises(WinRMTransportError) as exc:
            wsman.send("", None)
        error_msg = "Bad HTTP response returned from the server. Code: 401, " \
                    "Content: 'not an XML response'"
        assert str(exc.value) == error_msg
        assert exc.value.code == 401
        assert exc.value.protocol == "http"
        assert exc.value.message == error_msg
        assert exc.value.response_text == "not an XML response"

    def test_invoke_wsman_fault(self):
        # we set Create and send Send to cause the test transport to fire the
        # error we want
        wsman = WSMan("")
        wsman.transport = _TransportTest(WSManAction.CREATE)
        with pytest.raises(WSManFaultError) as exc:
            wsman.send("", None)
        error_msg = \
            "Received a WSManFault message. (Code: IllegalAction, Reason: " \
            "Illegal action '%s', expecting '%s')" \
            % (WSManAction.SEND, WSManAction.CREATE)
        assert str(exc.value) == error_msg
        assert exc.value.code == "IllegalAction"
        assert exc.value.machine is None
        assert exc.value.message == error_msg
        assert exc.value.provider is None
        assert exc.value.provider_fault is None
        assert exc.value.reason == "Illegal action '%s', expecting '%s'" \
            % (WSManAction.SEND, WSManAction.CREATE)

    def test_raise_native_wsman_fault(self):
        xml_text = '''
        <s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action><a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo><s:NotUnderstood qname="wsman:ResourceUri" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" />
            </s:Header>
            <s:Body>
                <s:Fault>
                    <s:Code>
                        <s:Value>s:MustUnderstand</s:Value>
                    </s:Code>
                    <s:Reason>
                        <s:Text xml:lang="">The WS-Management service cannot process a SOAP header in the request that is marked as mustUnderstand by the client.  This could be caused by the use of a version of the protocol which is not supported, or may be an incompatibility  between the client and server implementations. </s:Text>
                    </s:Reason>
                </s:Fault>
            </s:Body>
        </s:Envelope>'''
        with pytest.raises(WSManFaultError) as exc:
            raise WSMan._parse_wsman_fault(xml_text)
        assert exc.value.code == "s:MustUnderstand"
        assert exc.value.machine is None
        assert exc.value.message == \
            "Received a WSManFault message. (Code: s:MustUnderstand, " \
            "Reason: The WS-Management service cannot process a SOAP header " \
            "in the request that is marked as mustUnderstand by the client. " \
            " This could be caused by the use of a version of the protocol " \
            "which is not supported, or may be an incompatibility  between " \
            "the client and server implementations.)"
        assert exc.value.provider is None
        assert exc.value.provider_fault is None
        assert exc.value.provider_path is None
        assert exc.value.reason == \
            "The WS-Management service cannot process a SOAP header in the " \
            "request that is marked as mustUnderstand by the client.  This " \
            "could be caused by the use of a version of the protocol which " \
            "is not supported, or may be an incompatibility  between the " \
            "client and server implementations."

    def test_raise_native_wsman_fault_no_reason(self):
        xml_text = '''
        <s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action><a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo><s:NotUnderstood qname="wsman:ResourceUri" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" />
            </s:Header>
            <s:Body>
                <s:Fault>
                    <s:Code>
                        <s:Value>s:Unknown</s:Value>
                    </s:Code>
                </s:Fault>
            </s:Body>
        </s:Envelope>'''
        with pytest.raises(WSManFaultError) as exc:
            raise WSMan._parse_wsman_fault(xml_text)
        assert exc.value.code == "s:Unknown"
        assert exc.value.machine is None
        assert exc.value.message == "Received a WSManFault message. " \
                                    "(Code: s:Unknown)"
        assert exc.value.provider is None
        assert exc.value.provider_fault is None
        assert exc.value.provider_path is None
        assert exc.value.reason is None

    def test_raise_wsman_fault_with_wsman_fault(self):
        xml_text = r'''
        <s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
            <s:Header>
                <a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action>
                <a:MessageID>uuid:348D9DCE-B99B-4EBD-A90B-624854B032BB</a:MessageID>
                <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
                <a:RelatesTo>uuid:a82b5f24-7a6c-4170-8cd1-d2031b1203fd</a:RelatesTo>
            </s:Header>
            <s:Body>
                <s:Fault>
                    <s:Code>
                        <s:Value>s:Sender</s:Value>
                        <s:Subcode>
                            <s:Value>w:InvalidParameter</s:Value>
                        </s:Subcode>
                    </s:Code>
                    <s:Reason>
                        <s:Text xml:lang="">The parameter is incorrect. </s:Text>
                    </s:Reason>
                    <s:Detail>
                        <w:FaultDetail>http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/InvalidValue</w:FaultDetail>
                        <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="87" Machine="SERVER2016.domain.local">
                            <f:Message><f:ProviderFault provider="Shell cmd plugin" path="%systemroot%\system32\winrscmd.dll">The parameter is incorrect. </f:ProviderFault></f:Message>
                        </f:WSManFault>
                    </s:Detail>
                </s:Fault>
            </s:Body>
        </s:Envelope>'''
        with pytest.raises(WSManFaultError) as exc:
            raise WSMan._parse_wsman_fault(xml_text)
        assert exc.value.code == 87
        assert exc.value.machine == "SERVER2016.domain.local"
        assert exc.value.message == \
            "Received a WSManFault message. (Code: 87, Machine: " \
            "SERVER2016.domain.local, Reason: The parameter is incorrect., " \
            "Provider: Shell cmd plugin, Provider Path: %systemroot%\\" \
            "system32\\winrscmd.dll, Provider Fault: The parameter is " \
            "incorrect.)"
        assert exc.value.provider == "Shell cmd plugin"
        assert exc.value.provider_fault == "The parameter is incorrect."
        assert exc.value.provider_path == \
            "%systemroot%\\system32\\winrscmd.dll"
        assert exc.value.reason == "The parameter is incorrect."

    def test_raise_wsman_fault_without_provider(self):
        xml_text = r'''
        <s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
            <s:Header>
                <a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action>
                <a:MessageID>uuid:EE71C444-1658-4B3F-916D-54CE43B68BC9</a:MessageID>
                <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
                <a:RelatesTo>uuid.761ca906-0bf0-41bb-a9d9-4cbbca986aeb</a:RelatesTo>
            </s:Header>
            <s:Body>
                <s:Fault>
                    <s:Code>
                        <s:Value>s:Sender</s:Value>
                        <s:Subcode>
                            <s:Value>w:SchemaValidationError</s:Value>
                        </s:Subcode>
                    </s:Code>
                    <s:Reason>
                        <s:Text xml:lang="">The SOAP XML in the message does not match the corresponding XML schema definition. Change the XML and retry. </s:Text>
                    </s:Reason>
                    <s:Detail>
                        <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858817" Machine="SERVER2008.domain.local">
                            <f:Message>The Windows Remote Shell cannot process the request. The SOAP packet contains an element Argument that is invalid. Retry the request with the correct XML element. </f:Message>
                        </f:WSManFault>
                    </s:Detail>
                </s:Fault>
            </s:Body>
        </s:Envelope>'''
        with pytest.raises(WSManFaultError) as exc:
            raise WSMan._parse_wsman_fault(xml_text)
        assert exc.value.code == 2150858817
        assert exc.value.machine == "SERVER2008.domain.local"
        assert exc.value.message == \
            "Received a WSManFault message. (Code: 2150858817, Machine: " \
            "SERVER2008.domain.local, Reason: The Windows Remote Shell " \
            "cannot process the request. The SOAP packet contains an " \
            "element Argument that is invalid. Retry the request with the " \
            "correct XML element.)"
        assert exc.value.provider is None
        assert exc.value.provider_fault is None
        assert exc.value.provider_path is None
        assert exc.value.reason == \
            "The Windows Remote Shell cannot process the request. The SOAP " \
            "packet contains an element Argument that is invalid. Retry the " \
            "request with the correct XML element."

    def test_wsman_update_envelope_size_explicit(self):
        wsman = WSMan("")
        wsman.update_max_payload_size(4096)
        assert wsman.max_envelope_size == 4096
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 1450 <= wsman.max_payload_size <= 1835

    @pytest.mark.parametrize('wsman_conn',
                             # we just want to validate against different env
                             # set on a server
                             [[False, 'test_wsman_update_envelope_size_150']],
                             indirect=True)
    def test_wsman_update_envelope_size_150(self, wsman_conn):
        wsman_conn.update_max_payload_size()
        assert wsman_conn.max_envelope_size == 153600
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 113574 <= wsman_conn.max_payload_size <= 113952

    @pytest.mark.parametrize('wsman_conn',
                             # we just want to validate against different env
                             # set on a server
                             [[False, 'test_wsman_update_envelope_size_500']],
                             indirect=True)
    def test_wsman_update_envelope_size_500(self, wsman_conn):
        wsman_conn.update_max_payload_size()
        assert wsman_conn.max_envelope_size == 512000
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 382374 <= wsman_conn.max_payload_size <= 382752

    @pytest.mark.parametrize('wsman_conn',
                             # we just want to validate against different env
                             # set on a server
                             [[False, 'test_wsman_update_envelope_size_4096']],
                             indirect=True)
    def test_wsman_update_envelope_size_4096(self, wsman_conn):
        wsman_conn.update_max_payload_size()
        assert wsman_conn.max_envelope_size == 4194304
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 3144102 <= wsman_conn.max_payload_size <= 3144480


class TestOptionSet(object):

    def test_set_no_options(self):
        option_set = OptionSet()
        actual = option_set.pack()
        assert len(actual.attrib.keys()) == 1
        assert actual.attrib['{http://www.w3.org/2003/05/soap-envelope}'
                             'mustUnderstand'] == 'true'
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}OptionSet"
        assert actual.text is None
        assert list(actual) == []
        assert str(option_set) == "{}"

    def test_set_one_option(self):
        option_set = OptionSet()
        option_set.add_option("key", "value")
        actual = option_set.pack()
        assert len(actual.attrib.keys()) == 1
        assert actual.attrib['{http://www.w3.org/2003/05/soap-envelope}'
                             'mustUnderstand'] == 'true'
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}OptionSet"
        assert actual.text is None
        children = list(actual)
        assert len(children) == 1
        assert len(children[0].attrib.keys()) == 1
        assert children[0].attrib['Name'] == "key"
        assert children[0].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Option"
        assert children[0].text == "value"
        assert str(option_set) == "{'key': 'value'}"

    def test_set_one_option_with_attributes(self):
        option_set = OptionSet()
        option_set.add_option("key", "value",
                              {"attrib1": "value1", "attrib2": "value2"})
        actual = option_set.pack()
        assert len(actual.attrib.keys()) == 1
        assert actual.attrib['{http://www.w3.org/2003/05/soap-envelope}'
                             'mustUnderstand'] == 'true'
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}OptionSet"
        assert actual.text is None
        children = list(actual)
        assert len(children) == 1
        assert len(children[0].attrib.keys()) == 3
        assert children[0].attrib['Name'] == "key"
        assert children[0].attrib['attrib1'] == "value1"
        assert children[0].attrib['attrib2'] == "value2"
        assert children[0].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Option"
        assert children[0].text == "value"
        assert str(option_set) == "{'key': 'value'}"

    def test_set_multiple_options(self):
        option_set = OptionSet()
        option_set.add_option("key1", "value1")
        option_set.add_option("key2", "value2")
        actual = option_set.pack()
        assert len(actual.attrib.keys()) == 1
        assert actual.attrib['{http://www.w3.org/2003/05/soap-envelope}'
                             'mustUnderstand'] == 'true'
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}OptionSet"
        assert actual.text is None
        children = list(actual)
        assert len(children) == 2

        assert len(children[0].attrib.keys()) == 1
        assert children[0].attrib['Name'] == "key1"
        assert children[0].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Option"
        assert children[0].text == "value1"

        assert len(children[1].attrib.keys()) == 1
        assert children[1].attrib['Name'] == "key2"
        assert children[1].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Option"
        assert children[1].text == "value2"

        assert str(option_set) == "{'key1': 'value1', 'key2': 'value2'}"


class TestSelectorSet(object):

    def test_set_no_options(self):
        selector_set = SelectorSet()
        actual = selector_set.pack()
        assert len(actual.attrib.keys()) == 0
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet"
        assert actual.text is None
        assert list(actual) == []
        assert str(selector_set) == "{}"

    def test_set_one_option(self):
        selector_set = SelectorSet()
        selector_set.add_option("key", "value")
        actual = selector_set.pack()
        assert len(actual.attrib.keys()) == 0
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet"
        assert actual.text is None
        children = list(actual)
        assert len(children) == 1
        assert len(children[0].attrib.keys()) == 1
        assert children[0].attrib['Name'] == "key"
        assert children[0].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Selector"
        assert children[0].text == "value"
        assert str(selector_set) == "{'key': 'value'}"

    def test_set_one_option_with_attributes(self):
        selector_set = SelectorSet()
        selector_set.add_option("key", "value",
                                {"attrib1": "value1", "attrib2": "value2"})
        actual = selector_set.pack()
        assert len(actual.attrib.keys()) == 0
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet"
        assert actual.text is None
        children = list(actual)
        assert len(children) == 1
        assert len(children[0].attrib.keys()) == 3
        assert children[0].attrib['Name'] == "key"
        assert children[0].attrib['attrib1'] == "value1"
        assert children[0].attrib['attrib2'] == "value2"
        assert children[0].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Selector"
        assert children[0].text == "value"
        assert str(selector_set) == "{'key': 'value'}"

    def test_set_multiple_options(self):
        selector_set = SelectorSet()
        selector_set.add_option("key1", "value1")
        selector_set.add_option("key2", "value2")
        actual = selector_set.pack()
        assert len(actual.attrib.keys()) == 0
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet"
        assert actual.text is None
        children = list(actual)
        assert len(children) == 2

        assert len(children[0].attrib.keys()) == 1
        assert children[0].attrib['Name'] == "key1"
        assert children[0].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Selector"
        assert children[0].text == "value1"

        assert len(children[1].attrib.keys()) == 1
        assert children[1].attrib['Name'] == "key2"
        assert children[1].tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Selector"
        assert children[1].text == "value2"

        assert str(selector_set) == "{'key1': 'value1', 'key2': 'value2'}"



class TestTransportHTTP(object):

    def test_not_supported_auth(self):
        with pytest.raises(ValueError) as err:
            _TransportHTTP("", "", auth="fake")
        assert str(err.value) == \
            "The specified auth 'fake' is not supported, please select one " \
            "of 'basic, certificate, credssp, kerberos, negotiate, ntlm'"

    def test_invalid_encryption_value(self):
        with pytest.raises(ValueError) as err:
            _TransportHTTP("", "", encryption="fake")
        assert str(err.value) == \
            "The encryption value 'fake' must be auto, always, or never"

    def test_encryption_always_not_valid_auth_ssl(self):
        with pytest.raises(ValueError) as err:
            _TransportHTTP("", "", auth="basic", encryption="always", ssl=True)
        assert str(err.value) == \
            "Cannot use message encryption with auth 'basic', either set " \
            "encryption='auto' or use one of the following auth providers: " \
            "credssp, kerberos, negotiate, ntlm"

    def test_encryption_auto_not_valid_auth_no_ssl(self):
        with pytest.raises(ValueError) as err:
            _TransportHTTP("", "", auth="basic", encryption="auto", ssl=False)
        assert str(err.value) == \
            "Cannot use message encryption with auth 'basic', either set " \
            "encryption='never', use ssl=True or use one of the following " \
            "auth providers: credssp, kerberos, negotiate, ntlm"

    def test_build_basic_no_username(self):
        transport = _TransportHTTP("")
        with pytest.raises(ValueError) as err:
            transport._build_auth_basic(None)
        assert str(err.value) == \
            "For basic auth, the username must be specified"

    def test_build_basic_no_password(self):
        transport = _TransportHTTP("", username="user")
        with pytest.raises(ValueError) as err:
            transport._build_auth_basic(None)
        assert str(err.value) == \
            "For basic auth, the password must be specified"

    def test_build_basic(self):
        transport = _TransportHTTP("", username="user", password="pass",
                                   auth="basic")
        session = transport._build_session()
        assert transport.encryption is None
        assert isinstance(session.auth, requests.auth.HTTPBasicAuth)
        assert session.auth.username == "user"
        assert session.auth.password == "pass"

    def test_build_certificate_no_key_pem(self):
        transport = _TransportHTTP("")
        with pytest.raises(ValueError) as err:
            transport._build_auth_certificate(None)
        assert str(err.value) == \
            "For certificate auth, the path to the certificate key pem file " \
            "must be specified with certificate_key_pem"

    def test_build_certificate_no_pem(self):
        transport = _TransportHTTP("", certificate_key_pem="path")
        with pytest.raises(ValueError) as err:
            transport._build_auth_certificate(None)
        assert str(err.value) == \
            "For certificate auth, the path to the certificate pem file " \
            "must be specified with certificate_pem"

    def test_build_certificate_not_ssl(self):
        transport = _TransportHTTP("", certificate_key_pem="path",
                                   certificate_pem="path", ssl=False)
        with pytest.raises(ValueError) as err:
            transport._build_auth_certificate(None)
        assert str(err.value) == "For certificate auth, SSL must be used"

    def test_build_certificate(self):
        transport = _TransportHTTP("", auth="certificate",
                                   certificate_key_pem="key_pem",
                                   certificate_pem="pem")
        session = transport._build_session()
        assert transport.encryption is None
        assert session.auth is None
        assert session.cert == ("pem", "key_pem")
        assert session.headers['Authorization'] == \
            "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/" \
            "https/mutual"

    @pytest.mark.skipif(
        requests_credssp,
        reason="only raises if requests-credssp is not installed",
    )
    def test_build_credssp_not_imported(self):
        transport = _TransportHTTP("", username="user", password="password")
        with pytest.raises(
            ImportError,
            match=(
                r"Cannot use CredSSP auth as requests-credssp is not "
                r"installed: No module named '?requests_credssp'?"
            ),
        ):
            transport._build_auth_credssp(None)

    def test_build_credssp_no_username(self):
        transport = _TransportHTTP("")
        with pytest.raises(ValueError) as err:
            transport._build_auth_credssp(None)
        assert str(err.value) == \
            "For credssp auth, the username must be specified"

    def test_build_credssp_no_password(self):
        transport = _TransportHTTP("", username="user")
        with pytest.raises(ValueError) as err:
            transport._build_auth_credssp(None)
        assert str(err.value) == \
            "For credssp auth, the password must be specified"

    def test_build_credssp_no_kwargs(self):
        credssp = pytest.importorskip("requests_credssp")

        transport = _TransportHTTP("", username="user", password="pass",
                                   auth="credssp")
        session = transport._build_session()
        assert isinstance(session.auth, credssp.HttpCredSSPAuth)
        assert session.auth.disable_tlsv1_2 is False
        assert session.auth.minimum_version == 2
        assert session.auth.password == 'pass'
        assert session.auth.username == 'user'

    def test_build_credssp_with_kwargs(self):
        credssp = pytest.importorskip("requests_credssp")

        transport = _TransportHTTP("", username="user", password="pass",
                                   auth="credssp",
                                   credssp_auth_mechanism="kerberos",
                                   credssp_disable_tlsv1_2=True,
                                   credssp_minimum_version=5)

        session = transport._build_session()
        assert isinstance(session.auth, credssp.HttpCredSSPAuth)
        assert session.auth.disable_tlsv1_2 is True
        assert session.auth.minimum_version == 5
        assert session.auth.password == 'pass'
        assert session.auth.username == 'user'

    def test_build_kerberos(self):
        transport = _TransportHTTP("", auth="kerberos")
        session = transport._build_session()
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "kerberos"
        assert session.auth.delegate is False
        assert session.auth.hostname_override is None
        assert session.auth.password is None
        assert session.auth.send_cbt is True
        assert session.auth.service == 'WSMAN'
        assert session.auth.username is None
        assert session.auth.wrap_required is False

    def test_build_kerberos_with_kwargs(self):
        transport = _TransportHTTP("", auth="kerberos", username="user",
                                   ssl=False, password="pass",
                                   negotiate_delegate=True,
                                   negotiate_hostname_override="host",
                                   negotiate_send_cbt=False,
                                   negotiate_service="HTTP")
        session = transport._build_session()
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "kerberos"
        assert session.auth.delegate is True
        assert session.auth.hostname_override == "host"
        assert session.auth.password == "pass"
        assert session.auth.send_cbt is False
        assert session.auth.service == 'HTTP'
        assert session.auth.username == "user"
        assert session.auth.wrap_required is True

    def test_build_negotiate(self):
        transport = _TransportHTTP("")
        session = transport._build_session()
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "negotiate"
        assert session.auth.delegate is False
        assert session.auth.hostname_override is None
        assert session.auth.password is None
        assert session.auth.send_cbt is True
        assert session.auth.service == 'WSMAN'
        assert session.auth.username is None
        assert session.auth.wrap_required is False

    def test_build_negotiate_with_kwargs(self):
        transport = _TransportHTTP("", auth="negotiate", username="user",
                                   ssl=False, password="pass",
                                   negotiate_delegate=True,
                                   negotiate_hostname_override="host",
                                   negotiate_send_cbt=False,
                                   negotiate_service="HTTP")
        session = transport._build_session()
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "negotiate"
        assert session.auth.delegate is True
        assert session.auth.hostname_override == "host"
        assert session.auth.password == "pass"
        assert session.auth.send_cbt is False
        assert session.auth.service == 'HTTP'
        assert session.auth.username == "user"
        assert session.auth.wrap_required is True

    def test_build_ntlm(self):
        transport = _TransportHTTP("", auth="ntlm")
        session = transport._build_session()
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "ntlm"
        assert session.auth.delegate is False
        assert session.auth.hostname_override is None
        assert session.auth.password is None
        assert session.auth.send_cbt is True
        assert session.auth.service == 'WSMAN'
        assert session.auth.username is None
        assert session.auth.wrap_required is False

    def test_build_ntlm_with_kwargs(self):
        transport = _TransportHTTP("", auth="ntlm", username="user",
                                   ssl=False, password="pass",
                                   negotiate_delegate=True,
                                   negotiate_hostname_override="host",
                                   negotiate_send_cbt=False,
                                   negotiate_service="HTTP",
                                   cert_validation=False)
        session = transport._build_session()
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert session.auth.auth_provider == "ntlm"
        assert session.auth.delegate is True
        assert session.auth.hostname_override == "host"
        assert session.auth.password == "pass"
        assert session.auth.send_cbt is False
        assert session.auth.service == 'HTTP'
        assert session.auth.username == "user"
        assert session.auth.wrap_required is True

    def test_build_session_default(self):
        transport = _TransportHTTP("")
        session = transport._build_session()
        assert session.headers['User-Agent'] == "Python PSRP Client"
        assert session.trust_env is True
        assert isinstance(session.auth, HTTPNegotiateAuth)
        assert 'http' not in session.proxies
        assert 'https' not in session.proxies
        assert session.verify is True

    def test_build_session_cert_validate(self):
        transport = _TransportHTTP("", cert_validation=True)
        session = transport._build_session()
        assert session.verify is True

    def test_build_session_cert_validate_env(self):
        transport = _TransportHTTP("", cert_validation=True)
        os.environ['REQUESTS_CA_BUNDLE'] = 'path_to_REQUESTS_CA_CERT'
        try:
            session = transport._build_session()
        finally:
            del os.environ['REQUESTS_CA_BUNDLE']
        assert session.verify == 'path_to_REQUESTS_CA_CERT'

    def test_build_session_cert_validate_path_override_env(self):
        transport = _TransportHTTP("", cert_validation="kwarg_path")
        os.environ['REQUESTS_CA_BUNDLE'] = 'path_to_REQUESTS_CA_CERT'
        try:
            session = transport._build_session()
        finally:
            del os.environ['REQUESTS_CA_BUNDLE']
        assert session.verify == 'kwarg_path'

    def test_build_session_cert_no_validate(self):
        transport = _TransportHTTP("", cert_validation=False)
        session = transport._build_session()
        assert session.verify is False

    def test_build_session_cert_no_validate_override_env(self):
        transport = _TransportHTTP("", cert_validation=False)
        os.environ['REQUESTS_CA_BUNDLE'] = 'path_to_REQUESTS_CA_CERT'
        try:
            session = transport._build_session()
        finally:
            del os.environ['REQUESTS_CA_BUNDLE']
        assert session.verify is False

    def test_build_session_proxies_default(self):
        transport = _TransportHTTP("server")
        session = transport._build_session()
        assert 'http' not in session.proxies
        assert 'https' not in session.proxies

    def test_build_session_proxies_env(self):
        transport = _TransportHTTP("server")
        os.environ['https_proxy'] = "https://envproxy"
        try:
            session = transport._build_session()
        finally:
            del os.environ['https_proxy']
        assert 'http' not in session.proxies
        assert session.proxies["https"] == "https://envproxy"

    def test_build_session_proxies_kwarg(self):
        transport = _TransportHTTP("server", proxy="https://kwargproxy")
        session = transport._build_session()
        assert 'http' not in session.proxies
        assert session.proxies["https"] == "https://kwargproxy"

    def test_build_session_proxies_kwarg_non_ssl(self):
        transport = _TransportHTTP("server", proxy="http://kwargproxy",
                                   ssl=False)
        session = transport._build_session()
        assert session.proxies["http"] == "http://kwargproxy"
        assert 'https' not in session.proxies

    def test_build_session_proxies_env_kwarg_override(self):
        transport = _TransportHTTP("server", proxy="https://kwargproxy")
        os.environ['https_proxy'] = "https://envproxy"
        try:
            session = transport._build_session()
        finally:
            del os.environ['https_proxy']
        assert 'http' not in session.proxies
        assert session.proxies['https'] == "https://kwargproxy"

    def test_build_session_proxies_env_no_proxy_override(self):
        transport = _TransportHTTP("server", no_proxy=True)
        os.environ['https_proxy'] = "https://envproxy"
        try:
            session = transport._build_session()
        finally:
            del os.environ['https_proxy']
        assert session.proxies == {'https': False}

    def test_build_session_proxies_kwarg_ignore_no_proxy(self):
        transport = _TransportHTTP("server", proxy="https://kwargproxy",
                                   no_proxy=True)
        session = transport._build_session()
        assert 'http' not in session.proxies
        assert session.proxies['https'] == "https://kwargproxy"

    def test_send_without_encryption(self, monkeypatch):
        send_mock = MagicMock()

        monkeypatch.setattr(_TransportHTTP, "_send_request", send_mock)

        transport = _TransportHTTP("server")
        transport.send(b"message")

        assert send_mock.call_count == 1
        actual_request = send_mock.call_args[0][0]

        assert actual_request.body == b"message"
        assert actual_request.url == "https://server:5986/wsman"
        assert actual_request.headers['content-type'] == "application/soap+xml;charset=UTF-8"

    def test_send_with_encryption(self, monkeypatch):
        send_mock = MagicMock()

        def send_request(self, *args, **kwargs):
            self.session.auth.contexts['server'] = MagicMock()

            return send_mock(*args, **kwargs)

        wrap_mock = MagicMock()
        wrap_mock.return_value = "multipart/encrypted", b"wrapped"

        monkeypatch.setattr(_TransportHTTP, "_send_request", send_request)
        monkeypatch.setattr(WinRMEncryption, "wrap_message", wrap_mock)

        transport = _TransportHTTP("server", ssl=False)
        transport.send(b"message")
        transport.send(b"message 2")

        assert send_mock.call_count == 3
        actual_request1 = send_mock.call_args_list[0][0][0]
        actual_request2 = send_mock.call_args_list[1][0][0]
        actual_request3 = send_mock.call_args_list[2][0][0]

        assert actual_request1.body is None
        assert actual_request1.url == "http://server:5985/wsman"

        assert actual_request2.body == b"wrapped"
        assert actual_request2.headers['content-type'] == \
            'multipart/encrypted;protocol="application/' \
            'HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
        assert actual_request2.url == "http://server:5985/wsman"

        assert actual_request3.body == b"wrapped"
        assert actual_request3.headers['content-type'] == \
            'multipart/encrypted;protocol="application/' \
            'HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
        assert actual_request3.url == "http://server:5985/wsman"

        assert wrap_mock.call_count == 2
        assert wrap_mock.call_args_list[0][0][0] == b"message"
        assert wrap_mock.call_args_list[1][0][0] == b"message 2"

    def test_send_default(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = "application/soap+xml;charset=UTF-8"

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = _TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request)
        assert actual == b"content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == (30, 30)

    def test_send_timeout_kwargs(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = "application/soap+xml;charset=UTF-8"

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = _TransportHTTP("server", ssl=True, connection_timeout=20, read_timeout=25)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request)
        assert actual == b"content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == (20, 25)

    def test_send_auth_error(self, monkeypatch):
        response = requests.Response()
        response.status_code = 401

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = _TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        with pytest.raises(AuthenticationError) as err:
            transport._send_request(prep_request)
        assert str(err.value) == "Failed to authenticate the user None with " \
                                 "negotiate"

    def test_send_winrm_error_blank(self, monkeypatch):
        response = requests.Response()
        response.status_code = 500
        response._content = b""

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = _TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        with pytest.raises(WinRMTransportError) as err:
            transport._send_request(prep_request)
        assert str(err.value) == "Bad HTTP response returned from the " \
                                 "server. Code: 500, Content: ''"
        assert err.value.code == 500
        assert err.value.protocol == 'http'
        assert err.value.response_text == ''

    def test_send_winrm_error_content(self, monkeypatch):
        response = requests.Response()
        response.status_code = 500
        response._content = b"error msg"

        send_mock = MagicMock()
        send_mock.return_value = response

        monkeypatch.setattr(requests.Session, "send", send_mock)

        transport = _TransportHTTP("server", ssl=True)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        with pytest.raises(WinRMTransportError) as err:
            transport._send_request(prep_request)
        assert str(err.value) == "Bad HTTP response returned from the " \
                                 "server. Code: 500, Content: 'error msg'"
        assert err.value.code == 500
        assert err.value.protocol == 'http'
        assert err.value.response_text == 'error msg'

    def test_send_winrm_encrypted_single(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = \
            'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-' \
            'encrypted";boundary="Encrypted Boundary"'

        send_mock = MagicMock()
        send_mock.return_value = response
        unwrap_mock = MagicMock()
        unwrap_mock.return_value = b"unwrapped content"

        monkeypatch.setattr(requests.Session, "send", send_mock)
        monkeypatch.setattr(WinRMEncryption, "unwrap_message", unwrap_mock)

        transport = _TransportHTTP("server", ssl=False)
        transport.encryption = WinRMEncryption(None, None)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request)
        assert actual == b"unwrapped content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == (30, 30)

        assert unwrap_mock.call_count == 1
        assert unwrap_mock.call_args[0] == (b"content", "Encrypted Boundary")
        assert unwrap_mock.call_args[1] == {}

    def test_send_winrm_encrypted_multiple(self, monkeypatch):
        response = requests.Response()
        response.status_code = 200
        response._content = b"content"
        response.headers['content-type'] = \
            'multipart/x-multi-encrypted;protocol="application/HTTP-CredSSP-' \
            'session-encrypted";boundary="Encrypted Boundary"'

        send_mock = MagicMock()
        send_mock.return_value = response
        unwrap_mock = MagicMock()
        unwrap_mock.return_value = b"unwrapped content"

        monkeypatch.setattr(requests.Session, "send", send_mock)
        monkeypatch.setattr(WinRMEncryption, "unwrap_message", unwrap_mock)

        transport = _TransportHTTP("server", ssl=False)
        transport.encryption = WinRMEncryption(None, None)
        session = transport._build_session()
        transport.session = session
        request = requests.Request('POST', transport.endpoint, data=b"data")
        prep_request = session.prepare_request(request)

        actual = transport._send_request(prep_request)
        assert actual == b"unwrapped content"
        assert send_mock.call_count == 1
        assert send_mock.call_args[0] == (prep_request,)
        assert send_mock.call_args[1]['timeout'] == (30, 30)

        assert unwrap_mock.call_count == 1
        assert unwrap_mock.call_args[0] == (b"content", "Encrypted Boundary")
        assert unwrap_mock.call_args[1] == {}

    @pytest.mark.parametrize('ssl, server, port, path, expected', [
        [True, 'server', 5986, 'wsman', 'https://server:5986/wsman'],
        [False, 'server', 5985, 'wsman', 'http://server:5985/wsman'],
        [False, 'server', 5985, 'iis-wsman', 'http://server:5985/iis-wsman'],
        [True, '127.0.0.1', 443, 'wsman', 'https://127.0.0.1:443/wsman'],
        [False, '2001:0db8:0a0b:12f0:0000:0000:0000:0001', 80, 'path',
         'http://[2001:db8:a0b:12f0::1]:80/path'],
        [False, '2001:db8:a0b:12f0::1', 80, 'path',
         'http://[2001:db8:a0b:12f0::1]:80/path'],
        [False, '2001:0db8:0a0b:12f0:0001:0001:0001:0001', 5985, 'wsman',
         'http://[2001:db8:a0b:12f0:1:1:1:1]:5985/wsman'],
        [False, 'FE80::0202:B3FF:FE1E:8329', 5985, 'wsman',
         'http://[fe80::202:b3ff:fe1e:8329]:5985/wsman'],
        [True, '[2001:0db8:0a0b:12f0:0000:0000:0000:0001]', 5986, 'wsman',
         'https://[2001:0db8:0a0b:12f0:0000:0000:0000:0001]:5986/wsman'],
    ])
    def test_endpoint_forms(self, ssl, server, port, path, expected):
        actual = _TransportHTTP._create_endpoint(ssl, server, port, path)
        assert actual == expected
