import pytest

from pypsrp.complex_objects import ObjectMeta
from pypsrp.powershell import PowerShell, RunspacePool
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
    # executable = "powershell.exe"
    arguments = ["Write-Host", "hi"]

    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport)
    shell = WinRS(wsman)
    shell.open()
    try:
        command_id = shell.run_executable(executable, arguments, no_shell=True)
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
    wsman = WSMan(transport, operation_timeout=10)
    wsman.update_max_payload_size()

    """
    host_info = HostInfo(Color.DARK_YELLOW, Color.DARK_MAGENTA,
                         Coordinates(0, 18), Coordinates(0, 0), 25,
                         Size(120, 3000), Size(120, 50), Size(120, 104),
                         Size(219, 104), "Python PSRP")
    """
    runspace_pool = RunspacePool(wsman)
    runspace_pool.open()
    try:
        # ps = PowerShell(runspace_pool)
        # ps.add_script("$VerbosePreference = 'Continue'; Write-Output output; Write-Host host; Write-Verbose verbose; Write-Error hi")
        # ps.add_cmdlet("Get-Service").add_parameter("Name", "netlogon")
        # ps.add_statement()
        # ps.add_cmdlet("Get-Process")
        # ps.add_statement()
        # ps.add_cmdlet("Get-Process").add_cmdlet("Select-Object")
        # ps.add_parameter("Property", "Name")
        # output = ps.invoke()
        # runspace_pool.disconnect()
        # runspace_pool.connect()
        # runspace_pool.max_runspaces = 2
        # runspace_pool.get_available_runspaces()
        runspace_pool.exchange_keys()
    finally:
        runspace_pool.close()
    a = ""


def test_psrp_large():
    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport, operation_timeout=30)
    wsman.update_max_payload_size()
    max_size = wsman._max_payload_size

    payload_string = "a" * (max_size * 3)

    runspace_pool = RunspacePool(wsman)
    runspace_pool.open()
    try:
        ps = PowerShell(runspace_pool)
        ps.add_cmdlet("Write-Output").add_argument(payload_string)
        output = ps.invoke()
    finally:
        runspace_pool.close()

    input_length = len(payload_string)
    output_length = len(output[0])
    print(output_length)
    assert output_length == input_length, "Output: %d != Input: %d" \
                                          % (output_length, input_length)


def test_psrp_object():
    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport, operation_timeout=30)

    runspace_pool = RunspacePool(wsman)
    runspace_pool.open()
    try:
        a = ""
        ps = PowerShell(runspace_pool)
        ps.add_cmdlet("Get-Service")
        output = ps.invoke(raw_output=True)
    finally:
        runspace_pool.close()

    a = ""


def test_psrp_sec_string():
    transport = TransportHTTP(server, port, username, password)
    wsman = WSMan(transport, operation_timeout=30)

    runspace_pool = RunspacePool(wsman)
    runspace_pool.open()
    try:
        runspace_pool.exchange_keys()
        ps = PowerShell(runspace_pool)
        sec_string = runspace_pool._serializer.serialize(u"Hello World", ObjectMeta("SS"))
        ps.add_cmdlet("Set-Variable").add_parameters({"Name": "sec_string", "Value": sec_string})
        ps.add_statement()
        ps.add_script("[System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($sec_string))")
        ps.add_statement()
        ps.add_cmdlet("ConvertTo-SecureString").add_parameters({"String": "abc", "AsPlainText": None, "Force": None})
        output = ps.invoke()
    finally:
        runspace_pool.close()

    a = ""

"""
# resourceURI was set as resourceUri with mustUnderstand=true
<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</a:Action><a:MessageID>uuid:4DB571F9-F8DE-48FD-872C-2AF08D996249</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:eaa98952-3188-458f-b265-b03ace115f20</a:RelatesTo><s:NotUnderstood qname="wsman:ResourceUri" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" /></s:Header><s:Body><s:Fault><s:Code><s:Value>s:MustUnderstand</s:Value></s:Code><s:Reason><s:Text xml:lang="">The WS-Management service cannot process a SOAP header in the request that is marked as mustUnderstand by the client.  This could be caused by the use of a version of the protocol which is not supported, or may be an incompatibility  between the client and server implementations. </s:Text></s:Reason></s:Fault></s:Body></s:Envelope>

# CommandId was not set on the rsp:Signal attributes
<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action><a:MessageID>uuid:348D9DCE-B99B-4EBD-A90B-624854B032BB</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:a82b5f24-7a6c-4170-8cd1-d2031b1203fd</a:RelatesTo></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>w:InvalidParameter</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="">The parameter is incorrect. </s:Text></s:Reason><s:Detail><w:FaultDetail>http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/InvalidValue</w:FaultDetail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="87" Machine="SERVER2016.domain.local"><f:Message><f:ProviderFault provider="Shell cmd plugin" path="%systemroot%\system32\winrscmd.dll">The parameter is incorrect. </f:ProviderFault></f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>

# Argument not Arguments was used in CommandLine
<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action><a:MessageID>uuid:EE71C444-1658-4B3F-916D-54CE43B68BC9</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid.761ca906-0bf0-41bb-a9d9-4cbbca986aeb</a:RelatesTo></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>w:SchemaValidationError</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="">The SOAP XML in the message does not match the corresponding XML schema definition. Change the XML and retry. </s:Text></s:Reason><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858817" Machine="SERVER2008.domain.local"><f:Message>The Windows Remote Shell cannot process the request. The SOAP packet contains an element Argument that is invalid. Retry the request with the correct XML element. </f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>
"""
