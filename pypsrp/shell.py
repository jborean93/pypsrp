# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import sys

from pypsrp.exceptions import WSManFaultError
from pypsrp.wsman import NAMESPACES, OptionSet, SelectorSet, _float_to_duration

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET


class CommandState(object):
    DONE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
           "CommandState/Done"
    PENDING = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
              "CommandState/Pending"
    RUNNING = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
              "CommandState/Running"


class SignalCode(object):
    """
    [MS-WSMV] 2.2.4.38 Signal - Code
    https://msdn.microsoft.com/en-us/library/cc251558.aspx

    The control code to send in a Signal message to the server
    """
    CTRL_C = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
             "signal/ctrl_c"
    CTRL_BREAK = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
                 "signal/ctrl_break"
    TERMINATE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
                "signal/Terminate"
    PS_CTRL_C = "powershell/signal/ctrl_c"


class WinRS(object):

    def __init__(self, wsman):
        self.wsman = wsman
        self.resource_uri = "http://schemas.microsoft.com/wbem/wsman/1/" \
                            "windows/shell/cmd"
        self.shell_id = None

    def open(self, input_streams='stdin', output_streams='stdout stderr',
             codepage=None, environment=None, idle_time_out=None,
             lifetime=None, name=None, no_profile=None,
             working_directory=None, open_content=None, base_options=None):
        rsp = NAMESPACES['rsp']

        shell = ET.Element("{%s}Shell" % rsp)
        ET.SubElement(shell, "{%s}InputStreams" % rsp).text = input_streams
        ET.SubElement(shell, "{%s}OutputStreams" % rsp).text = output_streams
        if environment is not None:
            env = ET.SubElement(shell, "{%s}Environment" % rsp)
            for key, value in environment:
                ET.SubElement(env, "{%s}Variable" % rsp, Name=key).text = \
                    str(value)

        if idle_time_out is not None:
            ET.SubElement(shell, "{%s}IdleTimeOut" % rsp).text = \
                _float_to_duration(idle_time_out)

        if lifetime is not None:
            ET.SubElement(shell, "{%s}Lifetime" % rsp).text = \
                _float_to_duration(lifetime)

        if name is not None:
            ET.SubElement(shell, "{%s}Name" % rsp).text = name

        if working_directory is not None:
            ET.SubElement(shell, "{%s}WorkingDirectory" % rsp).text = \
                working_directory

        if open_content is not None:
            shell.append(open_content)

        # inherit the base options if it was passed in, otherwise use an empty
        # option set
        options = OptionSet() if base_options is None else base_options
        if no_profile is not None:
            options.add_option('WINRS_NOPROFILE', no_profile)
        if codepage is not None:
            options.add_option('WINRS_CODEPAGE', codepage)

        if len(options.values) == 0:
            # set options back to None if nothing was actually set
            options = None

        response = self._invoke(self.wsman.create, shell, options=options)
        self.shell_id = response.find("rsp:Shell/rsp:ShellId",
                                      namespaces=NAMESPACES).text

    def run_executable(self, executable, arguments=None, no_shell=True):
        rsp = NAMESPACES['rsp']
        arguments = arguments if arguments is not None else []

        command_line = ET.Element("{%s}CommandLine" % rsp)
        ET.SubElement(command_line, "{%s}Command" % rsp).text = executable
        for argument in arguments:
            ET.SubElement(command_line, "{%s}Arguments" % rsp).text = argument

        options = OptionSet()
        options.add_option('WINRS_SKIP_CMD_SHELL', no_shell)
        response = self._invoke(self.wsman.command, command_line, options,
                                self.shell_id)
        return response.find("rsp:CommandResponse/rsp:CommandId",
                             namespaces=NAMESPACES).text

    def get_output(self, command_id):
        rc = None
        stdout = b""
        stderr = b""
        done = False

        while not done:
            try:
                state, rc, buffer = \
                    self._get_receive_response("stdout stderr", command_id)
                done = state == CommandState.DONE
                stdout += buffer['stdout']
                stderr += buffer['stderr']
            except WSManFaultError as exc:
                # if a command exceeds the OperationTimeout set, we will get
                # a WSManFaultError with the code 2150858793. We ignore this
                # and resend the Receive request as the process is still
                # running
                if exc.code == 2150858793:
                    pass
                else:
                    raise exc

        return rc, stdout, stderr

    def send_input(self, command_id, data, end=True):
        rsp = NAMESPACES['rsp']

        send = ET.ElementTree("{%s}Send" % rsp)
        stream = ET.SubElement(send, "{%s}Stream" % rsp, CommandId=command_id,
                               End=end, Name='stdin')
        stream.text = base64.b64encode(data).decode('utf-8')
        self._invoke(self.wsman.send, send, shell_id=self.shell_id)

    def signal(self, code, command_id):
        rsp = NAMESPACES['rsp']
        signal = ET.Element("{%s}Signal" % rsp,
                            attrib={"CommandId": command_id})
        ET.SubElement(signal, "{%s}Code" % rsp).text = code
        self._invoke(self.wsman.signal, signal, shell_id=self.shell_id)

    def close(self):
        self._invoke(self.wsman.delete, shell_id=self.shell_id)
        self.shell_id = None

    def _invoke(self, function, resource=None, options=None, shell_id=None):
        selector_set = None
        if shell_id is not None:
            selector_set = SelectorSet()
            selector_set.add_option('ShellId', shell_id)

        return function(self.resource_uri, resource, options, selector_set)

    def _get_receive_response(self, desired_stream, command_id=None):
        rsp = NAMESPACES['rsp']

        receive = ET.Element("{%s}Receive" % rsp)
        stream = ET.SubElement(receive,
                               "{%s}DesiredStream" % rsp)
        stream.text = desired_stream
        if command_id is not None:
            stream.attrib['CommandId'] = command_id

        options = OptionSet()
        options.add_option('WSMAN_CMDSHELL_OPTION_KEEPALIVE', True)

        response = self._invoke(self.wsman.receive, receive,
                                options=options,
                                shell_id=self.shell_id)

        command_state = response.find("rsp:ReceiveResponse/"
                                      "rsp:CommandState",
                                      namespaces=NAMESPACES)
        if command_state is not None:
            command_state = command_state.attrib['State']

        rc = response.find("rsp:ReceiveResponse/"
                           "rsp:CommandState/"
                           "rsp:ExitCode",
                           namespaces=NAMESPACES)
        if rc is not None:
            rc = int(rc.text)

        buffer = {}
        for stream_name in desired_stream.split(" "):
            buffer[stream_name] = b""
        streams = response.findall("rsp:ReceiveResponse/"
                                   "rsp:Stream",
                                   namespaces=NAMESPACES)
        for stream in streams:
            if stream.text is None:
                continue

            stream_value = base64.b64decode(stream.text.encode('utf-8'))
            stream_name = stream.attrib['Name']
            buffer[stream_name] += stream_value

        return command_state, rc, buffer
