# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import xml.etree.ElementTree as ET

from pypsrp.exceptions import WSManFaultError
from pypsrp.wsman import NAMESPACES, OptionSet, SelectorSet


log = logging.getLogger(__name__)


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
        """
        A WinRS shell instance. This is used by Process to spawn a new command/
        process on the raw WinRS shell.

        :param wsman: The pypsrp.wsman.WSMan instance to send commands over
        :param resource_uri: The resource URI of the shell, defaults to the
            WinRS cmd shell
        :param id: The ID of the shell, if not specified a dynamic ID will be
            generated by the host
        :param input_streams: The input streams available to the shell
        :param output_streams: The output streams available to the shell
        :param codepage: The codepage of the shell
        :param environment: A dictionary that contains environment key/values
            that are created for the shell instance
        :param idle_time_out: The idle timeout in seconds of the shell
        :param lifetime: The total lifetime of the shell
        :param name: The name (description) of the shell
        :param no_profile: Whether to create the shell with the user profile
            active or not
        :param working_directory: The default working directory of the created
            shell
        """
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

        self._selector_set = None
        # TODO: should I store a process table like a RunspacePool

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        """
        Closes the shell
        """
        if not self.opened:
            return
        self.wsman.delete(self.resource_uri, selector_set=self._selector_set)
        self.id = None
        self.opened = False

    def command(self, executable, arguments, no_shell=False, command_id=None):
        """
        Send a command message to the Shell. Process should really be used
        instead if a normal WinRS process is desired.

        :param executable: The path to the command/executable
        :param arguments: A list of arguments to run with the executable
        :param no_shell: Whether to create the command in the cmd shell or
            bypass it. If True then executable must be the full path to the
            exe. This only works on older OS's before 2012 R2 (not including)
        :param command_id: The command ID to specify when creating the command
        :return: The raw WSMan body response
        """
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

        return self.wsman.command(self.resource_uri, cmd, option_set=options,
                                  selector_set=self._selector_set)

    def open(self, base_options=None, open_content=None):
        """
        Send an open message to the WSMan host

        :param base_options: Any OptionSet options to pass along to the Open
            message
        :param open_content: Any extra XML elements to add to the Open message
        :return: The raw WSMan body response
        """
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

        response = self.wsman.create(self.resource_uri, shell,
                                     option_set=options)
        self._parse_shell_create(response)
        self.opened = True

        return response

    def receive(self, stream='stdout stderr', command_id=None, timeout=None):
        """
        Send a receive message to the WSMan host

        :param stream: The stream(s) separated by a space to receive the
            response for
        :param command_id: If specified the COmmand ID to receive the response
            from the command and not the shell
        :param timeout: Override the default WSMan timeout on the receive
            command
        :return: A tuple of
            state: The command state on the received response
            rc: The return code (if any) on the received response
            buffer: A dict containing a byte string for each buffer, the stream
                name of each buffer is the key in this return value
        """
        rsp = NAMESPACES['rsp']

        receive = ET.Element("{%s}Receive" % rsp)
        stream_xml = ET.SubElement(receive,
                                   "{%s}DesiredStream" % rsp)
        stream_xml.text = stream
        if command_id is not None:
            stream_xml.attrib['CommandId'] = command_id

        options = OptionSet()
        options.add_option('WSMAN_CMDSHELL_OPTION_KEEPALIVE', True)

        response = self.wsman.receive(self.resource_uri, receive,
                                      option_set=options,
                                      selector_set=self._selector_set,
                                      timeout=timeout)

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
        """
        Send the input data to the shell or command (if command_id is set)

        :param stream: The stream to send the data to
        :param data: The byte string of the data to send
        :param command_id: If the input data is for a command, then this
            specifies the Command ID it is for
        :param end: Whether this is the last input element for the command
        :return: The raw WSMan body of the response
        """
        rsp = NAMESPACES['rsp']

        send = ET.Element("{%s}Send" % rsp)
        stream = ET.SubElement(send, "{%s}Stream" % rsp, Name=stream)
        if end is not None:
            stream.attrib['End'] = str(end)
        if command_id is not None:
            stream.attrib['CommandId'] = command_id

        stream.text = base64.b64encode(data).decode('utf-8')
        return self.wsman.send(self.resource_uri, send,
                               selector_set=self._selector_set)

    def signal(self, code, command_id):
        """
        Send a signal to the command

        :param code: The SignalCode value to send
        :param command_id: The command id the signal is for
        :return: The raw WSMan body of the response
        """
        rsp = NAMESPACES['rsp']

        signal = ET.Element("{%s}Signal" % rsp,
                            attrib={"CommandId": command_id})
        ET.SubElement(signal, "{%s}Code" % rsp).text = code
        return self.wsman.signal(self.resource_uri, signal,
                                 selector_set=self._selector_set)

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

        selector_set = response.find("wst:ResourceCreated/"
                                     "wsa:ReferenceParameters/"
                                     "wsman:SelectorSet", NAMESPACES)
        if selector_set is not None:
            self._selector_set = SelectorSet()
            for selector in selector_set:
                self._selector_set.add_option(selector.attrib['Name'],
                                              selector.text)


class Process(object):

    def __init__(self, shell, executable, arguments=None, id=None,
                 no_shell=False):
        """
        A new process to run over a default WinRS shell.

        :param shell: The WinRS shell to run the process over
        :param executable: The execute/command to run
        :param arguments: A list of arguments to use with the executable or
            command
        :param id: The ID of the command, if not specified then this is
            dynamically created
        :param no_shell: Whether to create the command in the cmd shell or
            bypass it. If True then executable must be the full path to the
            exe. This only works on older OS's before 2012 R2 (not including)
        """
        log.debug("Creating WinRS process for '%s' with arguments '%s'"
                  % (executable, arguments))
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
        """
        Start the process in the background and return immediately. Call
        poll_invoke to get the latest output/status of the command and
        end_invoke to wait until the process is complete.
        """
        response = self.shell.command(self.executable, self.arguments,
                                      no_shell=self.no_shell)
        self.id = response.find("rsp:CommandResponse/rsp:CommandId",
                                namespaces=NAMESPACES).text

    def end_invoke(self):
        """
        Wait until the process is done
        """
        while not self.state == CommandState.DONE:
            self.poll_invoke()

    def invoke(self):
        """
        Start the process synchronously and wait for it to be completed.
        """
        self.begin_invoke()
        self.end_invoke()

    def poll_invoke(self, timeout=None):
        """
        Poll the running process to update the output buffer and the status.

        :param timeout: Override the default WSMan timeout when polling the
        process.
        """
        try:
            self.state, self.rc, buffer = self.shell.receive('stdout stderr',
                                                             self.id,
                                                             timeout=timeout)
        except WSManFaultError as exc:
            # if a command exceeds the OperationTimeout set, we will get
            # a WSManFaultError with the code 2150858793. We ignore this
            # as it just meant no output during that operation.
            if exc.code == 2150858793:
                pass
            else:
                raise exc
        else:
            self.stdout += buffer['stdout']
            self.stderr += buffer['stderr']

    def send(self, data, end=True):
        """
        Send data to the running process.

        :param data: The byte string to send
        :param end: Whether this is the last input to send
        :return:
        """
        self.shell.send("stdin", data, command_id=self.id, end=end)

    def signal(self, code):
        """
        Send a signal to the process.

        :param code: The SignalCode to send
        """
        self.shell.signal(code, self.id)
