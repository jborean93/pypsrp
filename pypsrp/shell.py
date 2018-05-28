# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import sys

from pypsrp.exceptions import WSManFaultError
from pypsrp.wsman import NAMESPACES, OptionSet, SelectorSet

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

    def __init__(self, wsman, resource_uri="http://schemas.microsoft.com/wbem/"
                                           "wsman/1/windows/shell/cmd",
                 id=None, input_streams='stdin',
                 output_streams='stdout stderr', codepage=None,
                 environment=None, idle_time_out=None, lifetime=None,
                 name=None, no_profile=None, working_directory=None):
        self.wsman = wsman
        self.opened = False
        self.id = id
        self.resource_uri = resource_uri
        self.input_streams = input_streams
        self.output_streams = output_streams
        self.codepage = codepage
        self.environment = environment
        self.idle_time_out = idle_time_out
        self.lifetime = lifetime
        self.name = name
        self.no_profile = no_profile
        self.working_directory = working_directory
        self.owner = None
        self.client_ip = None
        self.shell_run_time = None
        self.shell_inactivity = None
        # TODO: should I store a process table like a RunspacePool

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if not self.opened:
            return
        self._invoke(self.wsman.delete, id=self.id)
        self.id = None
        self.opened = False

    def command(self, executable, arguments, no_shell=False, command_id=None):
        rsp = NAMESPACES['rsp']

        options = OptionSet()
        options.add_option('WINRS_SKIP_CMD_SHELL', no_shell)

        arguments = arguments if arguments is not None else []

        cmd = ET.Element("{%s}CommandLine" % rsp)
        if command_id is not None:
            cmd.attrib['CommandId'] = command_id

        ET.SubElement(cmd, "{%s}Command" % rsp).text = executable
        for argument in arguments:
            ET.SubElement(cmd, "{%s}Arguments" % rsp).text = argument

        return self._invoke(self.wsman.command, cmd, options, self.id)

    def open(self, base_options=None, open_content=None):
        if self.opened:
            return

        rsp = NAMESPACES['rsp']

        shell = ET.Element("{%s}Shell" % rsp)
        if self.id is not None:
            shell.attrib['ShellId'] = self.id

        ET.SubElement(shell, "{%s}InputStreams" % rsp).text = \
            self.input_streams
        ET.SubElement(shell, "{%s}OutputStreams" % rsp).text = \
            self.output_streams
        if self.environment is not None:
            env = ET.SubElement(shell, "{%s}Environment" % rsp)
            for key, value in self.environment.items():
                ET.SubElement(env, "{%s}Variable" % rsp,
                              Name=str(key)).text = str(value)

        if self.idle_time_out is not None:
            ET.SubElement(shell, "{%s}IdleTimeOut" % rsp).text = \
                "PT%sS" % str(self.idle_time_out)

        if self.lifetime is not None:
            ET.SubElement(shell, "{%s}Lifetime" % rsp).text = \
                "PT%sS" % self.lifetime

        if self.name is not None:
            ET.SubElement(shell, "{%s}Name" % rsp).text = self.name

        if self.working_directory is not None:
            ET.SubElement(shell, "{%s}WorkingDirectory" % rsp).text = \
                self.working_directory

        if open_content is not None:
            shell.append(open_content)

        # inherit the base options if it was passed in, otherwise use an empty
        # option set
        options = OptionSet() if base_options is None else base_options
        if self.no_profile is not None:
            options.add_option('WINRS_NOPROFILE', self.no_profile)
        if self.codepage is not None:
            options.add_option('WINRS_CODEPAGE', self.codepage)

        if len(options.values) == 0:
            # set options back to None if nothing was actually set
            options = None

        response = self._invoke(self.wsman.create, shell, options=options)
        self._parse_shell_create(response)
        self.opened = True

        return response

    def receive(self, stream='stdout stderr', command_id=None):
        rsp = NAMESPACES['rsp']

        receive = ET.Element("{%s}Receive" % rsp)
        stream_xml = ET.SubElement(receive,
                                   "{%s}DesiredStream" % rsp)
        stream_xml.text = stream
        if command_id is not None:
            stream_xml.attrib['CommandId'] = command_id

        options = OptionSet()
        options.add_option('WSMAN_CMDSHELL_OPTION_KEEPALIVE', True)

        response = self._invoke(self.wsman.receive, receive,
                                options=options,
                                id=self.id)

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
        for stream_name in stream.split(" "):
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

    def send(self, stream, data, command_id=None, end=None):
        rsp = NAMESPACES['rsp']

        send = ET.Element("{%s}Send" % rsp)
        stream = ET.SubElement(send, "{%s}Stream" % rsp, Name=stream)
        if end is not None:
            stream.attrib['End'] = str(end)
        if command_id is not None:
            stream.attrib['CommandId'] = command_id

        stream.text = base64.b64encode(data).decode('utf-8')
        return self._invoke(self.wsman.send, send, id=self.id)

    def signal(self, code, command_id):
        rsp = NAMESPACES['rsp']

        signal = ET.Element("{%s}Signal" % rsp,
                            attrib={"CommandId": command_id})
        ET.SubElement(signal, "{%s}Code" % rsp).text = code
        return self._invoke(self.wsman.signal, signal, id=self.id)

    def _invoke(self, function, resource=None, options=None, id=None):
        selector_set = None
        if id is not None:
            selector_set = SelectorSet()
            selector_set.add_option('ShellId', id)

        return function(self.resource_uri, resource, options, selector_set)

    def _parse_shell_create(self, response):
        fields = {
            "rsp:ShellId": "id",
            "rsp:ResourceUri": "resource_uri",
            "rsp:Owner": "owner",
            "rsp:ClientIP": "client_ip",
            "rsp:IdleTimeOut": "idle_time_out",
            "rsp:OutputStreams": "output_streams",
            "rsp:ShellRunTime": "shell_run_time",
            "rsp:ShellInactivity": "shell_inactivity"
        }

        for xml_element, shell_attr in fields.items():
            element = response.find("rsp:Shell/%s" % xml_element, NAMESPACES)
            if element is not None:
                setattr(self, shell_attr, element.text)


class Process(object):

    def __init__(self, shell, executable, arguments=None, id=None,
                 no_shell=False):
        self.shell = shell
        self.id = id
        self.no_shell = no_shell
        self.executable = executable
        self.arguments = arguments
        self.state = CommandState.PENDING
        self.rc = None
        self.stdout = b""
        self.stderr = b""

    def begin_invoke(self):
        response = self.shell.command(self.executable, self.arguments,
                                      no_shell=self.no_shell)
        self.id = response.find("rsp:CommandResponse/rsp:CommandId",
                                namespaces=NAMESPACES).text

    def end_invoke(self):
        while not self.state == CommandState.DONE:
            self.poll_invoke()

    def invoke(self):
        self.begin_invoke()
        self.end_invoke()

    def poll_invoke(self):
        try:
            self.state, self.rc, buffer = self.shell.receive('stdout stderr',
                                                             self.id)
        except WSManFaultError as exc:
            # if a command exceeds the OperationTimeout set, we will get
            # a WSManFaultError with the code 2150858793. We ignore this
            # and resend the Receive request as the process is still
            # running
            if exc.code == 2150858793:
                pass
            else:
                raise exc
        else:
            self.stdout += buffer['stdout']
            self.stderr += buffer['stderr']

    def send(self, data, end=True):
        self.shell.send("stdin", data, command_id=self.id, end=end)

    def signal(self, code):
        self.shell.signal(code, self.id)
