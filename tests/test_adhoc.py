import pytest

from pypsrp.powershell import PSRP
from pypsrp.shell import SignalCode, WinRS
from pypsrp.transport import TransportHTTP
from pypsrp.wsman import WSMan

server = "SERVER2016.domain.local"
# server = "SERVER2008.domain.local"
username = "vagrant"
password = "Password01"
port = 5986


def test_jordan():
    # executable = "C:\\Windows\\System32\\cmd.exe"
    # arguments = ["/c", "timeout", "&&", "30"]

    executable = "C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe"
    arguments = ["Write-Host ", "hi"]

    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport)
    shell = WinRS(wsman)
    shell.open()
    try:
        command_id = shell.run_executable(executable, arguments)
        rc, stdout, stderr = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
    finally:
        shell.close()

    print()
    print("STDOUT:\n%s" % stdout.decode('utf-8'))
    print("STDERR:\n%s" % stderr.decode('utf-8'))
    print("RC: %d" % rc)

def test_get_config():
    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport)
    wsman.get_server_config()

def test_psrp():
    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport)
    psrp = PSRP(wsman)
    psrp.open()
    psrp.close()


"""
# resourceURI was set as resourceUri with mustUnderstand=true
<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action><a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo><s:NotUnderstood qname="wsman:ResourceUri" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" /></s:Header><s:Body><s:Fault><s:Code><s:Value>s:MustUnderstand</s:Value></s:Code><s:Reason><s:Text xml:lang="">The WS-Management service cannot process a SOAP header in the request that is marked as mustUnderstand by the client.  This could be caused by the use of a version of the protocol which is not supported, or may be an incompatibility  between the client and server implementations. </s:Text></s:Reason></s:Fault></s:Body></s:Envelope>

# CommandId was not set on the rsp:Signal attributes
<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action><a:MessageID>uuid:348D9DCE-B99B-4EBD-A90B-624854B032BB</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:a82b5f24-7a6c-4170-8cd1-d2031b1203fd</a:RelatesTo></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>w:InvalidParameter</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="">The parameter is incorrect. </s:Text></s:Reason><s:Detail><w:FaultDetail>http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/InvalidValue</w:FaultDetail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="87" Machine="SERVER2016.domain.local"><f:Message><f:ProviderFault provider="Shell cmd plugin" path="%systemroot%\system32\winrscmd.dll">The parameter is incorrect. </f:ProviderFault></f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>

# Argument not Arguments was used in CommandLine
<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action><a:MessageID>uuid:EE71C444-1658-4B3F-916D-54CE43B68BC9</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid.761ca906-0bf0-41bb-a9d9-4cbbca986aeb</a:RelatesTo></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>w:SchemaValidationError</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="">The SOAP XML in the message does not match the corresponding XML schema definition. Change the XML and retry. </s:Text></s:Reason><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858817" Machine="SERVER2008.domain.local"><f:Message>The Windows Remote Shell cannot process the request. The SOAP packet contains an element Argument that is invalid. Retry the request with the correct XML element. </f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>
"""
