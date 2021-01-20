# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import enum
import typing
import xml.etree.ElementTree as ElementTree

from psrp.protocol.wsman import (
    CommandResponseEvent,
    CommandState,
    CreateResponseEvent,
    DeleteResponseEvent,
    NAMESPACES,
    OptionSet,
    ReceiveResponseEvent,
    SelectorSet,
    SendResponseEvent,
    SignalCode,
    SignalResponseEvent,
    WSMan,
    WSManEvent,
)


class WinRS:

    def __init__(
            self,
            wsman: typing.Union[WSMan],
            resource_uri: str = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
            shell_id: typing.Optional[str] = None,
            input_streams: str = 'stdin',
            output_streams: str = 'stdout stderr',
            codepage: typing.Optional[int] = None,
            environment: typing.Optional[typing.Dict[str, str]] = None,
            idle_time_out: typing.Optional[int] = None,
            lifetime: typing.Optional[int] = None,
            name: typing.Optional[str] = None,
            no_profile: typing.Optional[bool] = None,
            working_directory: typing.Optional[str] = None,
    ):
        self.wsman = wsman
        self.resource_uri = resource_uri
        self.shell_id = shell_id
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
        self.selector_set: typing.Optional[SelectorSet] = None

    def data_to_send(
            self,
            amount: typing.Optional[int] = None,
    ) -> bytes:
        return self.wsman.data_to_send(amount=amount)

    def receive_data(
            self,
            data: bytes,
    ) -> WSManEvent:
        event = self.wsman.receive_data(data)

        print("Received %s" % event)
        if isinstance(event, CreateResponseEvent):
            self._parse_shell_create(event.body)

        return event

    def command(
            self,
            executable: str,
            args: typing.Optional[typing.List[str]] = None,
            no_shell: bool = False,
            command_id: typing.Optional[str] = None,
    ):
        rsp = NAMESPACES['rsp']

        options = OptionSet()
        options.add_option('WINRS_SKIP_CMD_SHELL', no_shell)

        args = args if args is not None else []

        cmd = ElementTree.Element("{%s}CommandLine" % rsp)
        if command_id is not None:
            cmd.attrib['CommandId'] = command_id

        ElementTree.SubElement(cmd, "{%s}Command" % rsp).text = executable
        for argument in args:
            ElementTree.SubElement(cmd, "{%s}Arguments" % rsp).text = argument

        self.wsman.command(self.resource_uri, cmd, option_set=options, selector_set=self.selector_set)

    def close(
            self,
    ):
        self.wsman.delete(self.resource_uri, selector_set=self.selector_set)

    def open(
            self,
            base_options: typing.Optional[OptionSet] = None,
            open_content: typing.Optional[ElementTree.Element] = None,
    ):
        rsp = NAMESPACES['rsp']

        shell = ElementTree.Element("{%s}Shell" % rsp)
        if self.shell_id is not None:
            shell.attrib['ShellId'] = self.shell_id

        ElementTree.SubElement(shell, "{%s}InputStreams" % rsp).text = self.input_streams
        ElementTree.SubElement(shell, "{%s}OutputStreams" % rsp).text = self.output_streams
        if self.environment is not None:
            env = ElementTree.SubElement(shell, "{%s}Environment" % rsp)
            for key, value in self.environment.items():
                ElementTree.SubElement(env, "{%s}Variable" % rsp, Name=str(key)).text = str(value)

        if self.idle_time_out is not None:
            ElementTree.SubElement(shell, "{%s}IdleTimeOut" % rsp).text = "PT%sS" % str(self.idle_time_out)

        if self.lifetime is not None:
            ElementTree.SubElement(shell, "{%s}Lifetime" % rsp).text = "PT%sS" % self.lifetime

        if self.name is not None:
            ElementTree.SubElement(shell, "{%s}Name" % rsp).text = self.name

        if self.working_directory is not None:
            ElementTree.SubElement(shell, "{%s}WorkingDirectory" % rsp).text = self.working_directory

        if open_content is not None:
            shell.append(open_content)

        # Inherit the base options if it was passed in, otherwise use an empty option set.
        options = OptionSet() if base_options is None else base_options
        if self.no_profile is not None:
            options.add_option('WINRS_NOPROFILE', self.no_profile)

        if self.codepage is not None:
            options.add_option('WINRS_CODEPAGE', self.codepage)

        if len(options.values) == 0:
            # set options back to None if nothing was actually set
            options = None

        self.wsman.create(self.resource_uri, shell, option_set=options)

    def receive(
            self,
            stream: str = 'stdout stderr',
            command_id: typing.Optional[str] = None,
    ):
        rsp = NAMESPACES['rsp']

        receive = ElementTree.Element("{%s}Receive" % rsp)
        stream_xml = ElementTree.SubElement(receive, "{%s}DesiredStream" % rsp)
        stream_xml.text = stream
        if command_id is not None:
            stream_xml.attrib['CommandId'] = command_id

        options = OptionSet()
        options.add_option('WSMAN_CMDSHELL_OPTION_KEEPALIVE', True)

        self.wsman.receive(self.resource_uri, receive, option_set=options, selector_set=self.selector_set)

    def send(
            self,
            stream: str,
            data: bytes,
            command_id: typing.Optional[str] = None,
            end: typing.Optional[bool] = None,
    ):
        rsp = NAMESPACES['rsp']

        send = ElementTree.Element("{%s}Send" % rsp)
        stream = ElementTree.SubElement(send, "{%s}Stream" % rsp, Name=stream)
        stream.text = base64.b64encode(data).decode('utf-8')

        if end is not None:
            stream.attrib['End'] = str(end)

        if command_id is not None:
            stream.attrib['CommandId'] = command_id

        self.wsman.send(self.resource_uri, send, selector_set=self.selector_set)

    def signal(
            self,
            signal: SignalCode,
            command_id: str,
    ):
        rsp = NAMESPACES['rsp']

        body = ElementTree.Element("{%s}Signal" % rsp, attrib={"CommandId": command_id})
        ElementTree.SubElement(body, "{%s}Code" % rsp).text = signal.value

        self.wsman.signal(self.resource_uri, body, selector_set=self.selector_set)

    def _parse_shell_create(
            self,
            response: ElementTree.Element,
    ):
        """ Process a WSMan Create response. """
        fields = {
            'rsp:ShellId': 'shell_id',
            'rsp:ResourceUri': 'resource_uri',
            'rsp:Owner': 'owner',
            'rsp:ClientIP': 'client_ip',
            'rsp:IdleTimeOut': 'idle_time_out',
            'rsp:InputStreams': 'input_streams',
            'rsp:OutputStreams': 'output_streams',
            'rsp:ShellRunTime': 'shell_run_time',
            'rsp:ShellInactivity': 'shell_inactivity',
        }
        for xml_element, shell_attr in fields.items():
            element = response.find('s:Body/rsp:Shell/%s' % xml_element, NAMESPACES)
            if element is not None:
                setattr(self, shell_attr, element.text)

        selector_set = response.find("wst:ResourceCreated/wsa:ReferenceParameters/wsman:SelectorSet", NAMESPACES)
        if selector_set is not None:
            self.selector_set = SelectorSet()
            for selector in selector_set:
                self.selector_set.add_option(selector.attrib['Name'], selector.text)
