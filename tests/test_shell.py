# -*- coding: utf-8 -*-

import pytest

from pypsrp.exceptions import WSManFaultError
from pypsrp.shell import SignalCode, WinRS
from pypsrp.wsman import WSMan
from .runner import winrm_transport

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict


class TestWinRS(object):

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_winrs_standard']],
                             indirect=True)
    def test_winrs_standard(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open()
        command_id = shell.run_executable("cmd.exe", ["/c", "echo", "hi"])
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert out[1] == b"hi\r\n"
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport',
                             [[
                                 # no_shell only works on older hosts, rely on
                                 # pre-canned responses from actual test
                                 False,
                                 'test_winrs_no_cmd_shell'
                             ]],
                             indirect=True)
    def test_winrs_no_cmd_shell(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open()
        # this will fail as you need to provide the full path when not running
        # in cmd shell
        with pytest.raises(WSManFaultError) as exc:
            shell.run_executable("powershell.exe", ["Write-Host", "hi"],
                                 no_shell=True)
        assert exc.value.provider_fault == \
            "The system cannot find the file specified."
        assert exc.value.code == 2147942402

        command_id = shell.run_executable(
            r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe",
            ["Write-Host", "hi"], no_shell=True
        )
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert out[1] == b"hi\n"
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport',
                             [[
                                 # to save on test runtime, only run with
                                 # pre-canned responses
                                 False,
                                 'test_winrs_operation_timeout'
                             ]],
                             indirect=True)
    def test_winrs_operation_timeout(self, winrm_transport):
        wsman = WSMan(winrm_transport, operation_timeout=10)
        shell = WinRS(wsman)
        shell.open()
        command_id = shell.run_executable(
            'powershell.exe',
            ['Write-Host hi; Start-Sleep 30; Write-Host hi again']
        )
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert out[1] == b"hi\nhi again\n"
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_winrs_stderr_rc']], indirect=True)
    def test_winrs_stderr_rc(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open()
        command_id = shell.run_executable(
            'cmd.exe', ['/c echo out && echo err>&2 && exit 1']
        )
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 1
        assert out[1] == b"out \r\n"
        assert out[2] == b"err \r\n"

    @pytest.mark.parametrize('winrm_transport', [[True, 'test_winrs_send']],
                             indirect=True)
    def test_winrs_send(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open()
        command_id = shell.run_executable("powershell.exe", ["-"])
        shell.send(command_id, b"Write-Host \"output 1\";", end=False)
        shell.send(command_id, b"Write-Host \"output 2\";")
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert out[1] == b"output 1\noutput 2\n"
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_winrs_environment']], indirect=True)
    def test_winrs_environment(self, winrm_transport):
        complex_chars = '_-(){}[]<>*+-/\?"''!@#$^&|;:i,.`~0'
        env_block = OrderedDict([
            ('env1', 'var1'),
            (1234, 5678),
            (complex_chars, complex_chars),
        ])

        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open(environment=env_block)
        command_id = shell.run_executable("cmd.exe", ["/c", "set"])
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        env_list = out[1].decode('utf-8').splitlines()
        assert out[0] == 0
        assert out[2] == b""
        assert "env1=var1" in env_list
        assert "1234=5678" in env_list
        assert "%s=%s" % (complex_chars, complex_chars) in env_list

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_winrs_extra_opts']], indirect=True)
    def test_winrs_extra_opts(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open(name="shell 1", lifetime=60, idle_time_out=60,
                   working_directory="C:\\Windows")
        command_id = shell.run_executable("powershell.exe", ["(pwd).Path"])
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert out[1] == b"C:\\Windows\r\n"
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport', [[True, 'test_winrs_unicode']],
                             indirect=True)
    def test_winrs_unicode(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open(codepage=65001)
        command_id = shell.run_executable("powershell.exe",
                                          [u"Write-Host こんにちは"])
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert out[1].decode('utf-8') == u"こんにちは\n"
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_winrs_noprofile']], indirect=True)
    def test_winrs_noprofile(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open(no_profile=True)
        command_id = shell.run_executable('cmd.exe', ['/c', 'set'])
        out = shell.get_output(command_id)
        shell.signal(SignalCode.CTRL_C, command_id)
        shell.close()
        assert out[0] == 0
        assert "USERPROFILE=C:\\Users\\Default" in out[1].decode('utf-8').splitlines()
        assert out[2] == b""

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_winrs_bad_cmd_id']], indirect=True)
    def test_winrs_bad_cmd_id(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        shell = WinRS(wsman)
        shell.open()
        old_id = shell.run_executable("cmd.exe", ["/c", "echo", "hi"])
        with pytest.raises(WSManFaultError) as exc:
            shell.get_output("87E77BEB-6761-4C48-9D70-A00266B8459A")
        shell.signal(SignalCode.CTRL_C, old_id)
        shell.close()
        assert exc.value.code == 2150858843
        assert exc.value.reason == \
            "The Windows Remote Shell received a request to perform an " \
            "operation on a command identifier that does not exist. Either " \
            "the command has completed execution or the client specified an " \
            "invalid command identifier."
