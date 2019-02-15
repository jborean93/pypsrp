# -*- coding: utf-8 -*-

import pytest

from pypsrp.exceptions import WSManFaultError
from pypsrp.shell import Process, SignalCode, WinRS
from pypsrp.wsman import WSMan

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict


class TestWinRS(object):

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_winrs_standard']],
                             indirect=True)
    def test_winrs_standard(self, wsman_conn):
        with WinRS(wsman_conn) as shell:
            process = Process(shell, "cmd.exe", ["/c", "echo", "hi"])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 0
            assert process.stdout == b"hi\r\n"
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             [[
                                 # no_shell only works on older hosts, rely on
                                 # pre-canned responses from actual test
                                 False,
                                 'test_winrs_no_cmd_shell'
                             ]],
                             indirect=True)
    def test_winrs_no_cmd_shell(self, wsman_conn):
        with WinRS(wsman_conn) as shell:
            process = Process(shell, "powershell.exe", ["Write-Host", "hi"],
                              no_shell=True)

            # this will fail as you need to provide the full path when not
            # running in cmd shell
            with pytest.raises(WSManFaultError) as exc:
                process.invoke()
            assert exc.value.provider_fault == "The system cannot find the " \
                                               "file specified."
            assert exc.value.code == 2147942402

            # fix the execute path and invoke again
            process.executable = \
                r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe"
            process.invoke()
            process.signal(SignalCode.CTRL_C)

            assert process.rc == 0
            assert process.stdout == b"hi\n"
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             [[
                                 # to save on test runtime, only run with
                                 # pre-canned responses
                                 False,
                                 'test_winrs_operation_timeout'
                             ]],
                             indirect=True)
    def test_winrs_operation_timeout(self, wsman_conn):
        wsman_conn.operation_timeout = 10
        with WinRS(wsman_conn) as shell:
            process = Process(shell, "powershell.exe", ['Write-Host hi; '
                                                        'Start-Sleep 30; '
                                                        'Write-Host hi again'])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 0
            assert process.stdout == b"hi\nhi again\n"
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_winrs_stderr_rc']], indirect=True)
    def test_winrs_stderr_rc(self, wsman_conn):
        with WinRS(wsman_conn) as shell:
            process = Process(shell, "cmd.exe", ["/c echo out && echo "
                                                 "err>&2 && exit 1"])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 1
            assert process.stdout == b"out \r\n"
            assert process.stderr == b"err \r\n"

    @pytest.mark.parametrize('wsman_conn', [[True, 'test_winrs_send']],
                             indirect=True)
    def test_winrs_send(self, wsman_conn):
        with WinRS(wsman_conn) as shell:
            process = Process(shell, "powershell.exe", ["-"])
            process.begin_invoke()
            process.send(b"Write-Host \"output 1\";", end=False)
            process.send(b"Write-Host \"output 2\";")
            process.end_invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 0
            assert process.stdout == b"output 1\noutput 2\n"
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_winrs_environment']], indirect=True)
    def test_winrs_environment(self, wsman_conn):
        complex_chars = r'_-(){}[]<>*+-/\?"''!@#$^&|;:i,.`~0'
        env_block = OrderedDict([
            ('env1', 'var1'),
            (1234, 5678),
            (complex_chars, complex_chars),
        ])

        with WinRS(wsman_conn, environment=env_block) as shell:
            process = Process(shell, "cmd.exe", ["/c", "set"])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            env_list = process.stdout.decode('utf-8').splitlines()
            assert process.rc == 0
            assert "env1=var1" in env_list
            assert "1234=5678" in env_list
            assert "%s=%s" % (complex_chars, complex_chars) in env_list
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_winrs_extra_opts']], indirect=True)
    def test_winrs_extra_opts(self, wsman_conn):
        with WinRS(wsman_conn, name="shell 1", lifetime=60, idle_time_out=60,
                   working_directory="C:\\Windows") as shell:
            assert shell.name == "shell 1"
            assert shell.lifetime == 60
            assert shell.idle_time_out == "PT60.000S"
            assert shell.working_directory == "C:\\Windows"

            process = Process(shell, "powershell.exe", ["(pwd).Path"])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 0
            assert process.stdout == b"C:\\Windows\r\n"
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn', [[True, 'test_winrs_unicode']],
                             indirect=True)
    def test_winrs_unicode(self, wsman_conn):
        with WinRS(wsman_conn, codepage=65001) as shell:
            process = Process(shell, "powershell.exe",
                              [u"Write-Host こんにちは"])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 0
            assert process.stdout.decode('utf-8') == u"こんにちは\n"
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             # not all hosts respect the no_profile, we will
                             # just validate the message against a fake host
                             [[False, 'test_winrs_noprofile']], indirect=True)
    def test_winrs_noprofile(self, wsman_conn):
        with WinRS(wsman_conn, no_profile=True) as shell:
            process = Process(shell, "cmd.exe", ["/c", "set"])
            process.invoke()
            process.signal(SignalCode.CTRL_C)
            assert process.rc == 0
            assert "USERPROFILE=C:\\Users\\Default" in \
                   process.stdout.decode('utf-8').splitlines()
            assert process.stderr == b""

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_winrs_open_already_opened']],
                             indirect=True)
    def test_winrs_open_already_opened(self, wsman_conn):
        with WinRS(wsman_conn) as shell:
            shell.open()
        shell.close()

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_winrs_fail_poll_process']],
                             indirect=True)
    def test_winrs_fail_poll_process(self, wsman_conn):
        with WinRS(wsman_conn) as shell:
            process = Process(shell, "cmd.exe", ["/c", "echo", "hi"])

            # if I poll before beginning it should fail
            with pytest.raises(WSManFaultError) as err:
                process.poll_invoke()
            assert err.value.code == 87
            assert err.value.message == \
                "Received a WSManFault message. (Code: 87, Machine: {0}, " \
                "Reason: The parameter is incorrect., Provider: Shell cmd " \
                "plugin, Provider Path: %systemroot%\\system32\\winrscmd.dll" \
                ", Provider Fault: The parameter is incorrect.)"\
                .format(err.value.machine)
            assert err.value.provider == "Shell cmd plugin"
            assert err.value.provider_fault == "The parameter is incorrect."
            assert err.value.provider_path == \
                "%systemroot%\\system32\\winrscmd.dll"
            assert err.value.reason == "The parameter is incorrect."
