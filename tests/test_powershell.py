import pytest

from pypsrp.complex_objects import ObjectMeta
from pypsrp.powershell import RunspacePool, PowerShell
from pypsrp.wsman import WSMan
from .runner import winrm_transport


class TestRunspacePool(object):

    @pytest.mark.parametrize('winrm_transport', [[True, 'test_psrp_secure_string']],
                             indirect=True)
    @pytest.mark.skip()
    def test_psrp_secure_string(self, winrm_transport):
        wsman = WSMan(winrm_transport, operation_timeout=30)

        runspace_pool = RunspacePool(wsman)
        runspace_pool.open()
        try:
            runspace_pool.exchange_keys()
            ps = PowerShell(runspace_pool)
            sec_string = runspace_pool._serializer.serialize(u"Hello World",
                                                             ObjectMeta("SS"))
            ps.add_cmdlet("Set-Variable").add_parameters(
                {"Name": "sec_string", "Value": sec_string})
            ps.add_statement()
            ps.add_script(
                "[System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($sec_string))")
            ps.add_statement()
            ps.add_cmdlet("ConvertTo-SecureString").add_parameters(
                {"String": "abc", "AsPlainText": None, "Force": None})
            output = ps.invoke()
        finally:
            runspace_pool.close()

        a = ""

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_different_string']], indirect=True)
    @pytest.mark.skip()
    def test_different_string(self, winrm_transport):
        wsman = WSMan(winrm_transport, operation_timeout=30)

        runspace_pool = RunspacePool(wsman)
        runspace_pool.open()
        try:
            ps = PowerShell(runspace_pool)
            ps.add_script("C:\\temp\\psrp_string.ps1")
            output = ps.invoke()
        finally:
            runspace_pool.close()
        a = ""
