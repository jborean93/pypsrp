import sys
import uuid

import pytest

from pypsrp.exceptions import WinRMError, WinRMTransportError, WSManFaultError
from pypsrp.wsman import OptionSet, SelectorSet, WSMan, WSManAction, NAMESPACES

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET


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
        actual = WSMan(_TransportTest())
        assert actual.max_envelope_size == 153600
        assert actual._max_payload_size < actual.max_envelope_size
        assert actual.operation_timeout == 20
        assert isinstance(actual.session_id, str)

        # verify we get a unique session id each time this is initialised
        new_wsman = WSMan(_TransportTest())
        assert actual.session_id != new_wsman.session_id

    def test_override_default(self):
        actual = WSMan(_TransportTest(), 8192, 30)
        assert actual.max_envelope_size == 8192
        assert actual._max_payload_size < actual.max_envelope_size
        assert actual.operation_timeout == 30

    def test_invoke_command(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.COMMAND))
        actual = wsman.command("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_connect(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.CONNECT))
        actual = wsman.connect("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_create(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.CREATE))
        actual = wsman.create("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_disconnect(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.DISCONNECT))
        actual = wsman.disconnect("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_enumerate(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.ENUMERATE))
        actual = wsman.enumerate("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_delete(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.DELETE))
        actual = wsman.delete("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_get(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.GET))
        actual = wsman.get("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_recieve(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.RECEIVE))
        actual = wsman.receive("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_reconnect(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.RECONNECT))
        actual = wsman.reconnect("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_send(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.SEND))
        actual = wsman.send("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_signal(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.SIGNAL))
        actual = wsman.signal("", None)
        assert actual.tag == "{http://www.w3.org/2003/05/soap-envelope}Body"
        assert actual.text == "body"

    def test_invoke_mismatch_id(self, monkeypatch):
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000001")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)

        wsman = WSMan(_TransportTest(WSManAction.SEND))
        with pytest.raises(WinRMError) as exc:
            wsman.send("", None)
        assert str(exc.value) == \
            "Received related id does not match related expected message " \
            "id: Sent: uuid:00000000-0000-0000-0000-000000000001, Received: " \
            "uuid:00000000-0000-0000-0000-000000000000"

    def test_invoke_transport_error(self):
        wsman = WSMan(_TransportTest())
        with pytest.raises(WinRMTransportError) as exc:
            wsman.send("", None)
        error_msg = "Bad HTTP response returned from the server. Code: 401, " \
                    "Content: not an XML response"
        assert str(exc.value) == error_msg
        assert exc.value.code == 401
        assert exc.value.protocol == "http"
        assert exc.value.message == error_msg
        assert exc.value.response_text == "not an XML response"

    def test_invoke_wsman_fault(self):
        # we set Create and send Send to cause the test transport to fire the
        # error we want
        wsman = WSMan(_TransportTest(WSManAction.CREATE))
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
        xml_text = '''
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
        xml_text = '''
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

    @pytest.mark.parametrize('winrm_transport',
                             # we just want to validate against different env
                             # set on a server
                             [[False, 'test_wsman_update_envelope_size_150']],
                             indirect=True)
    def test_wsman_update_envelope_size_150(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        wsman.update_max_payload_size()
        assert wsman.max_envelope_size == 153600
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 113574 <= wsman._max_payload_size <= 113952

    @pytest.mark.parametrize('winrm_transport',
                             # we just want to validate against different env
                             # set on a server
                             [[False, 'test_wsman_update_envelope_size_500']],
                             indirect=True)
    def test_wsman_update_envelope_size_500(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        wsman.update_max_payload_size()
        assert wsman.max_envelope_size == 512000
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 382374 <= wsman._max_payload_size <= 382752

    @pytest.mark.parametrize('winrm_transport',
                             # we just want to validate against different env
                             # set on a server
                             [[False, 'test_wsman_update_envelope_size_4096']],
                             indirect=True)
    def test_wsman_update_envelope_size_4096(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        wsman.update_max_payload_size()
        assert wsman.max_envelope_size == 4194304
        # this next value is dependent on a lot of things such as python
        # version and rounding differences, we will just assert against a range
        assert 3144102 <= wsman._max_payload_size <= 3144480


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
        assert actual.getchildren() == []
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
        children = actual.getchildren()
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
        children = actual.getchildren()
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
        children = actual.getchildren()
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
        assert actual.getchildren() == []
        assert str(selector_set) == "{}"

    def test_set_one_option(self):
        selector_set = SelectorSet()
        selector_set.add_option("key", "value")
        actual = selector_set.pack()
        assert len(actual.attrib.keys()) == 0
        assert actual.tag == \
            "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet"
        assert actual.text is None
        children = actual.getchildren()
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
        children = actual.getchildren()
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
        children = actual.getchildren()
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
