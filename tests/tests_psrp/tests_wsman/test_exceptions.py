from xml.etree import ElementTree

from psrp._wsman import exceptions


def test_wsman_fault_must_understand() -> None:
    xml_text = r"""<s:Envelope xml:lang="en-US"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action>
        <a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
        <a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo>
        <s:NotUnderstood qname="wsman:ResourceUri"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" />
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code>
                <s:Value>s:MustUnderstand</s:Value>
            </s:Code>
            <s:Reason>
                <s:Text xml:lang=""> Test reason. </s:Text>
            </s:Reason>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.WSManMustUnderstandFault)
    assert actual.code == "s:MustUnderstand"
    assert actual.subcode == "s:MustUnderstand"
    assert actual.reason == "Test reason."
    assert actual.detail is None
    assert actual.element == "wsman:ResourceUri"
    assert (
        str(actual)
        == "Received HTTP Server error response (500 Internal Server Error). WSManFault s:MustUnderstand. Test reason."
    )


def test_wsman_fault_no_reason() -> None:
    xml_text = r"""<s:Envelope xml:lang="en-US"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action>
        <a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
        <a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo>
        <s:NotUnderstood qname="wsman:ResourceUri"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" />
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code>
                <s:Value>s:Unknown</s:Value>
            </s:Code>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.WSManFault)
    assert actual.code == "s:Unknown"
    assert actual.subcode == "s:Unknown"
    assert actual.reason is None
    assert actual.detail is None
    assert str(actual) == "Received HTTP Server error response (500 Internal Server Error). WSManFault s:Unknown."


def test_wsman_fault_with_fault_message() -> None:
    xml_text = r"""<s:Envelope xml:lang="en-US"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
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
                <s:Text xml:lang="">Reason text.</s:Text>
            </s:Reason>
            <s:Detail>
                <f:WSManFault
                    xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858817" Machine="SERVER2008.domain.local">
                    <f:Message>Detail message.</f:Message>
                </f:WSManFault>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.WSManFault)
    assert actual.code == "s:Sender"
    assert actual.subcode == "w:SchemaValidationError"
    assert actual.reason == "Reason text."
    assert isinstance(actual.detail, exceptions.WSManFaultDetail)
    assert actual.detail.raw.startswith("<s:Detail xmlns:")
    assert actual.detail.raw.endswith("</s:Detail>")
    assert actual.detail.detail is None
    assert actual.detail.code == 0x80338041
    assert actual.detail.machine == "SERVER2008.domain.local"
    assert str(actual.detail) == "FaultDetail UNKNOWN_CODE 0x80338041\nDetail message."
    assert (
        str(actual)
        == "Received HTTP Server error response (500 Internal Server Error). WSManFault w:SchemaValidationError.\nFaultDetail UNKNOWN_CODE 0x80338041\nDetail message."
    )


def test_wsman_fault_known_fault() -> None:
    xml_text = r"""<s:Envelope xml:lang="en-US"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action>
        <a:MessageID>uuid:D7C4A9B1-9A18-4048-B346-248D62A6078D</a:MessageID>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
        <a:RelatesTo>uuid:7340FE92-C302-42E5-A337-1918908654F8</a:RelatesTo>
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code>
                <s:Value>s:Receiver</s:Value>
                <s:Subcode>
                    <s:Value>w:TimedOut</s:Value>
                </s:Subcode>
            </s:Code>
            <s:Reason>
                <s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.  </s:Text>
            </s:Reason>
            <s:Detail>
                <f:WSManFault
                    xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858793" Machine="server2022.domain.test">
                    <f:Message>The WS-Management service cannot complete the operation within the time specified in OperationTimeout.  </f:Message>
                </f:WSManFault>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.OperationTimedOut)
    assert actual.code == "s:Receiver"
    assert actual.subcode == "w:TimedOut"
    assert (
        actual.reason
        == "The WS-Management service cannot complete the operation within the time specified in OperationTimeout."
    )
    assert isinstance(actual.detail, exceptions.WSManFaultDetail)
    assert actual.detail.raw.startswith("<s:Detail xmlns:")
    assert actual.detail.raw.endswith("</s:Detail>")
    assert actual.detail.detail is None
    assert actual.detail.code == 0x80338029
    assert actual.detail.machine == "server2022.domain.test"
    assert (
        str(actual.detail)
        == "FaultDetail OPERATION_TIMED_OUT 0x80338029\nThe WS-Management service cannot complete the operation within the time specified in OperationTimeout."
    )
    assert (
        str(actual)
        == "Received HTTP Server error response (500 Internal Server Error). WSManFault w:TimedOut.\nFaultDetail OPERATION_TIMED_OUT 0x80338029\nThe WS-Management service cannot complete the operation within the time specified in OperationTimeout."
    )


def test_wsman_fault_with_fault_detail() -> None:
    xml_text = r"""<s:Envelope xml:lang="en-US"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
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
                <s:Text xml:lang="">The parameter is incorrect 1. </s:Text>
            </s:Reason>
            <s:Detail>
                <w:FaultDetail>http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/InvalidValue</w:FaultDetail>
                <f:WSManFault
                    xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="87" Machine="SERVER2016.domain.local">
                    <f:Message>
                        <f:ProviderFault provider="Shell cmd plugin" path="%systemroot%\system32\winrscmd.dll">The parameter is incorrect 2. </f:ProviderFault>
                    </f:Message>
                </f:WSManFault>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.WSManFault)
    assert actual.code == "s:Sender"
    assert actual.subcode == "w:InvalidParameter"
    assert actual.reason == "The parameter is incorrect 1."
    assert isinstance(actual.detail, exceptions.WSManFaultDetail)
    assert actual.detail.raw.startswith("<s:Detail xmlns:")
    assert actual.detail.raw.endswith("</s:Detail>")
    assert actual.detail.detail == "http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/InvalidValue"
    assert actual.detail.code == 0x00000057
    assert actual.detail.machine == "SERVER2016.domain.local"
    assert str(actual.detail).startswith("FaultDetail UNKNOWN_CODE 0x00000057\n<wsmanfault:Message")
    assert str(actual.detail).endswith("</wsmanfault:Message>")
    assert str(actual).startswith(
        "Received HTTP Server error response (500 Internal Server Error). WSManFault w:InvalidParameter.\nFaultDetail UNKNOWN_CODE 0x00000057\n<wsmanfault:Message"
    )
    assert str(actual).endswith("</wsmanfault:Message>")


def test_raise_wsman_fault_with_provider_fault() -> None:
    xml_text = r"""<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xml:lang="en-US">
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
                <f:WSManFault
                    xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150859113" Machine="localhost">
                    <f:Message>
                        <f:ProviderFault provider="Config provider" path="%systemroot%\system32\WsmSvc.dll">
                            <f:WSManFault
                                xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150859113" Machine="Dell-Optiplex.MyLab.local">
                                <f:Message>WinRM firewall exception will not work since one of the network connection types on this machine is set to Public. Change the network connection type to either Domain or Private and try again. </f:Message>
                            </f:WSManFault>
                        </f:ProviderFault>
                    </f:Message>
                </f:WSManFault>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.WSManFault)
    assert actual.code == "s:Sender"
    assert actual.subcode == "w:SchemaValidationError"
    assert (
        actual.reason
        == "The SOAP XML in the message does not match the corresponding XML schema definition. Change the XML and retry."
    )
    assert isinstance(actual.detail, exceptions.WSManFaultDetail)
    assert actual.detail.raw.startswith("<s:Detail xmlns:")
    assert actual.detail.raw.endswith("</s:Detail>")
    assert actual.detail.detail is None
    assert actual.detail.code == 0x80338169
    assert actual.detail.machine == "localhost"
    assert str(actual.detail).startswith("FaultDetail UNKNOWN_CODE 0x80338169\n<wsmanfault:Message")
    assert str(actual.detail).endswith("</wsmanfault:Message>")
    assert str(actual).startswith(
        "Received HTTP Server error response (500 Internal Server Error). WSManFault w:SchemaValidationError.\nFaultDetail UNKNOWN_CODE 0x80338169\n<wsmanfault:Message"
    )
    assert str(actual).endswith("</wsmanfault:Message>")


def test_wsman_fault_wmi_error_detail() -> None:
    xml_text = r"""<s:Envelope xml:lang="en-US"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action>
        <a:MessageID>uuid:A832545B-9F5C-46AA-BB6A-5E4270D5E530</a:MessageID>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code>
                <s:Value>s:Receiver</s:Value>
                <s:Subcode>
                    <s:Value>w:InternalError</s:Value>
                </s:Subcode>
            </s:Code>
            <s:Reason>
                <s:Text xml:lang="en-US">Reason text. </s:Text>
            </s:Reason>
            <s:Detail>
                <p:MSFT_WmiError b:IsCIM_Error="true"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
                    xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/MSFT_WmiError"
                    xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xsi:type="p:MSFT_WmiError_Type">
                    <p:CIMStatusCode xsi:type="cim:cimUnsignedInt">27</p:CIMStatusCode>
                    <p:CIMStatusCodeDescription xsi:type="cim:cimString" xsi:nil="true" />
                    <p:ErrorSource xsi:type="cim:cimString" xsi:nil="true" />
                    <p:ErrorSourceFormat xsi:type="cim:cimUnsignedShort">0</p:ErrorSourceFormat>
                    <p:ErrorType xsi:type="cim:cimUnsignedShort">0</p:ErrorType>
                    <p:Message xsi:type="cim:cimString">WMI Message. </p:Message>
                    <p:MessageID xsi:type="cim:cimString">HRESULT 0x803381a6</p:MessageID>
                    <p:OtherErrorSourceFormat xsi:type="cim:cimString" xsi:nil="true" />
                    <p:OtherErrorType xsi:type="cim:cimString" xsi:nil="true" />
                    <p:OwningEntity xsi:type="cim:cimString" xsi:nil="true" />
                    <p:PerceivedSeverity xsi:type="cim:cimUnsignedShort">0</p:PerceivedSeverity>
                    <p:ProbableCause xsi:type="cim:cimUnsignedShort">0</p:ProbableCause>
                    <p:ProbableCauseDescription xsi:type="cim:cimString" xsi:nil="true" />
                    <p:error_Category xsi:type="cim:cimUnsignedInt">30</p:error_Category>
                    <p:error_Code xsi:type="cim:cimUnsignedInt">2150859174</p:error_Code>
                    <p:error_Type xsi:type="cim:cimString">HRESULT</p:error_Type>
                    <p:error_WindowsErrorMessage xsi:type="cim:cimString">Windows Error message. </p:error_WindowsErrorMessage>
                </p:MSFT_WmiError>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>"""

    envelope = ElementTree.fromstring(xml_text)

    actual = exceptions.WSManFault.create(envelope)
    assert isinstance(actual, exceptions.WSManFault)
    assert actual.code == "s:Receiver"
    assert actual.subcode == "w:InternalError"
    assert actual.reason == "Reason text."
    assert isinstance(actual.detail, exceptions.WMIError)
    assert actual.detail.raw.startswith("<s:Detail xmlns:")
    assert actual.detail.raw.endswith("</s:Detail>")
    assert actual.detail.detail is None
    assert actual.detail.cim_status_code == 27
    assert actual.detail.cim_status_code_description == ""
    assert actual.detail.error_category == 30
    assert actual.detail.error_code == 0x803381A6
    assert actual.detail.error_source == 0
    assert actual.detail.error_source_format == 0
    assert actual.detail.error_type_str == "HRESULT"
    assert actual.detail.error_windows_error_message == "Windows Error message."
    assert actual.detail.message == "WMI Message."
    assert actual.detail.message_id == "HRESULT 0x803381a6"
    assert actual.detail.other_error_source_format == ""
    assert actual.detail.other_error_type == ""
    assert actual.detail.owning_entity == ""
    assert actual.detail.perceived_severity == 0
    assert actual.detail.probable_cause == 0
    assert actual.detail.probably_cause_description == ""
    assert str(actual.detail) == "WMIError HRESULT 0x803381A6\nWMI Message."
    assert (
        str(actual)
        == "Received HTTP Server error response (500 Internal Server Error). WSManFault w:InternalError.\nWMIError HRESULT 0x803381A6\nWMI Message."
    )
