import pytest

import psrp
from psrp._wsman import WSMan


def test_raise_native_wsman_fault():
    xml_text = """
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
    </s:Envelope>"""

    wsman = WSMan("host")
    with pytest.raises(psrp.WSManFault) as exc:
        wsman.receive_data(xml_text.encode())

    assert exc.value.code == psrp.WSManFaultCode.UNKNOWN
    assert exc.value.machine is None
    assert exc.value.message == (
        "Received a WSManFault message. (Code: WSManFaultCode.UNKNOWN, "
        "Reason: The WS-Management service cannot process a SOAP header "
        "in the request that is marked as mustUnderstand by the client. "
        " This could be caused by the use of a version of the protocol "
        "which is not supported, or may be an incompatibility  between "
        "the client and server implementations.)"
    )
    assert exc.value.provider is None
    assert exc.value.provider_fault is None
    assert exc.value.provider_path is None
    assert exc.value.reason == (
        "The WS-Management service cannot process a SOAP header in the "
        "request that is marked as mustUnderstand by the client.  This "
        "could be caused by the use of a version of the protocol which "
        "is not supported, or may be an incompatibility  between the "
        "client and server implementations."
    )
    assert str(exc.value) == exc.value.message


def test_raise_native_wsman_fault_no_reason():
    xml_text = """
    <s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action><a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo><s:NotUnderstood qname="wsman:ResourceUri" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" />
        </s:Header>
        <s:Body>
            <s:Fault>
                <s:Code>
                    <s:Value>s:Unknown</s:Value>
                </s:Code>
            </s:Fault>
        </s:Body>
    </s:Envelope>"""

    wsman = WSMan("host")
    with pytest.raises(psrp.WSManFault) as exc:
        wsman.receive_data(xml_text.encode())

    assert exc.value.code == psrp.WSManFaultCode.UNKNOWN
    assert exc.value.machine is None
    assert exc.value.message == "Received a WSManFault message. (Code: WSManFaultCode.UNKNOWN)"
    assert exc.value.provider is None
    assert exc.value.provider_fault is None
    assert exc.value.provider_path is None
    assert exc.value.reason is None
    assert str(exc.value) == exc.value.message


def test_raise_wsman_fault_with_wsman_fault():
    xml_text = r"""
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
    </s:Envelope>"""

    wsman = WSMan("host")
    with pytest.raises(psrp.WSManFault) as exc:
        wsman.receive_data(xml_text.encode())

    assert exc.value.code == 87
    assert exc.value.machine == "SERVER2016.domain.local"
    assert exc.value.message == (
        "Received a WSManFault message. (Code: 87, Machine: "
        "SERVER2016.domain.local, Reason: The parameter is incorrect., "
        "Provider: Shell cmd plugin, Provider Path: %systemroot%\\"
        "system32\\winrscmd.dll, Provider Fault: The parameter is "
        "incorrect.)"
    )
    assert exc.value.provider == "Shell cmd plugin"
    assert exc.value.provider_fault == "The parameter is incorrect."
    assert exc.value.provider_path == "%systemroot%\\system32\\winrscmd.dll"
    assert exc.value.reason == "The parameter is incorrect."
    assert str(exc.value) == exc.value.message


def test_raise_wsman_fault_without_provider():
    xml_text = """
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
    </s:Envelope>"""

    wsman = WSMan("host")
    with pytest.raises(psrp.WSManFault) as exc:
        wsman.receive_data(xml_text.encode())

    assert exc.value.code == 2150858817
    assert exc.value.machine == "SERVER2008.domain.local"
    assert exc.value.message == (
        "Received a WSManFault message. (Code: 2150858817, Machine: "
        "SERVER2008.domain.local, Reason: The Windows Remote Shell "
        "cannot process the request. The SOAP packet contains an "
        "element Argument that is invalid. Retry the request with the "
        "correct XML element.)"
    )
    assert exc.value.provider is None
    assert exc.value.provider_fault is None
    assert exc.value.provider_path is None
    assert exc.value.reason == (
        "The Windows Remote Shell cannot process the request. The SOAP "
        "packet contains an element Argument that is invalid. Retry the "
        "request with the correct XML element."
    )
    assert str(exc.value) == exc.value.message


def test_raise_wsman_fault_with_provider_faults():
    xml_text = r"""
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xml:lang="en-US">
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
                <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150859113" Machine="localhost">
                <f:Message>
                    <f:ProviderFault provider="Config provider" path="%systemroot%\system32\WsmSvc.dll">
                        <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150859113" Machine="Dell-Optiplex.MyLab.local">
                            <f:Message>WinRM firewall exception will not work since one of the network connection types on this machine is set to Public. Change the network connection type to either Domain or Private and try again. </f:Message>
                        </f:WSManFault>
                    </f:ProviderFault>
                </f:Message>
                </f:WSManFault>
            </s:Detail>
            </s:Fault>
        </s:Body>
    </s:Envelope>"""

    wsman = WSMan("host")
    with pytest.raises(psrp.WSManFault) as exc:
        wsman.receive_data(xml_text.encode())

    assert exc.value.code == 2150859113
    assert exc.value.machine == "localhost"
    assert exc.value.message == (
        "Received a WSManFault message. (Code: 2150859113, Machine: localhost, Provider: Config provider, "
        "Provider Path: %systemroot%\\system32\\WsmSvc.dll, Provider Fault: <wsmanfault:WSManFault "
        'xmlns:wsmanfault="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150859113" '
        'Machine="Dell-Optiplex.MyLab.local">\n                            <wsmanfault:Message>'
        "WinRM firewall exception will not work since one of the network connection types on this machine is set "
        "to Public. Change the network connection type to either Domain or Private and try again. "
        "</wsmanfault:Message>\n                        </wsmanfault:WSManFault>)"
    )
    assert exc.value.provider == "Config provider"
    assert exc.value.provider_fault == (
        '<wsmanfault:WSManFault xmlns:wsmanfault="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" '
        'Code="2150859113" Machine="Dell-Optiplex.MyLab.local">\n                            '
        "<wsmanfault:Message>WinRM firewall exception will not work since one of the network connection types on "
        "this machine is set to Public. Change the network connection type to either Domain or Private and try "
        "again. </wsmanfault:Message>\n                        </wsmanfault:WSManFault>"
    )
    assert exc.value.provider_path == "%systemroot%\\system32\\WsmSvc.dll"
    assert exc.value.reason == ""
    assert str(exc.value) == exc.value.message
