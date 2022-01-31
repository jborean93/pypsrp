# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import typing as t
import uuid
import xml.etree.ElementTree as ElementTree

from psrp._wsman import (
    NAMESPACES,
    CreateResponseEvent,
    OptionSet,
    SelectorSet,
    SignalCode,
    WSMan,
    WSManEvent,
)


class CommandInfo(t.NamedTuple):
    command_id: uuid.UUID
    state: str


def enumerate_winrs(
    wsman: WSMan,
    resource_uri: str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    selector_filter: t.Optional[SelectorSet] = None,
) -> str:
    wsen = NAMESPACES["wsen"]
    wsmn = NAMESPACES["wsman"]

    enum_msg = ElementTree.Element("{%s}Enumerate" % wsen)
    ElementTree.SubElement(enum_msg, "{%s}OptimizeEnumeration" % wsmn)
    ElementTree.SubElement(enum_msg, "{%s}MaxElements" % wsmn).text = "32000"

    if selector_filter:
        filter = ElementTree.SubElement(
            enum_msg, "{%s}Filter" % wsmn, Dialect="http://schemas.dmtf.org/wbem/wsman/1/wsman/SelectorFilter"
        )
        filter.append(selector_filter.pack())

    return wsman.enumerate(resource_uri, enum_msg)


def receive_winrs_enumeration(
    wsman: WSMan,
    event: WSManEvent,
) -> t.Tuple[t.List["WinRS"], t.List[CommandInfo]]:
    shells: t.List[WinRS] = []
    commands: t.List[CommandInfo] = []

    items: t.Optional[ElementTree.Element] = event.body.find(
        "wsen:EnumerateResponse/wsman:Items", namespaces=NAMESPACES
    )
    if items is not None:
        for raw in items:
            if raw.tag == "{%s}Shell" % NAMESPACES["rsp"]:
                profile_loaded = False
                raw_profile_loaded = raw.find("rsp:ProfileLoaded", NAMESPACES)
                if raw_profile_loaded is not None:
                    profile_loaded = (raw_profile_loaded.text or "").lower() == "yes"

                shell = WinRS(wsman, no_profile=not profile_loaded)
                shell._parse_shell_create(raw, base_element="")
                shell.selector_set = SelectorSet()
                shell.selector_set.add_option("ShellId", str(shell.shell_id).upper())
                shells.append(shell)

            else:
                command_id = t.cast(ElementTree.Element, raw.find("rsp:CommandId", namespaces=NAMESPACES))
                command_state = t.cast(ElementTree.Element, raw.find("rsp:CommandState", namespaces=NAMESPACES))
                commands.append(CommandInfo(command_id=uuid.UUID(command_id.text), state=command_state.text or ""))

    return shells, commands


class WinRS:
    def __init__(
        self,
        wsman: WSMan,
        resource_uri: str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
        shell_id: t.Optional[str] = None,
        input_streams: str = "stdin",
        output_streams: str = "stdout stderr",
        codepage: t.Optional[int] = None,
        environment: t.Optional[t.Dict[str, str]] = None,
        idle_time_out: t.Optional[int] = None,
        lifetime: t.Optional[int] = None,
        name: t.Optional[str] = None,
        no_profile: t.Optional[bool] = None,
        working_directory: t.Optional[str] = None,
    ):
        self.wsman = wsman
        self.resource_uri = resource_uri
        self.shell_id = uuid.UUID(shell_id) if shell_id else uuid.UUID(int=0)
        self.input_streams = input_streams
        self.output_streams = output_streams
        self.codepage = codepage
        self.environment = environment
        self.idle_time_out = idle_time_out
        self.lifetime = lifetime
        self.name = name
        self.no_profile = no_profile
        self.process_id = -1
        self.working_directory = working_directory
        self.owner: t.Optional[str] = None
        self.client_ip: t.Optional[str] = None
        self.shell_run_time: t.Optional[str] = None
        self.shell_inactivity: t.Optional[str] = None
        self.state = ""
        self.selector_set: t.Optional[SelectorSet] = None

    def data_to_send(
        self,
        amount: t.Optional[int] = None,
    ) -> bytes:
        return self.wsman.data_to_send(amount=amount)

    def receive_data(
        self,
        data: bytes,
    ) -> WSManEvent:
        event = self.wsman.receive_data(data)

        if isinstance(event, CreateResponseEvent):
            self._parse_shell_create(event.body)

        return event

    def command(
        self,
        executable: str,
        args: t.Optional[t.List[str]] = None,
        no_shell: bool = False,
        command_id: t.Optional[uuid.UUID] = None,
    ) -> str:
        rsp = NAMESPACES["rsp"]

        options = OptionSet()
        options.add_option("WINRS_SKIP_CMD_SHELL", str(no_shell))

        args = args if args is not None else []

        cmd = ElementTree.Element("{%s}CommandLine" % rsp)
        if command_id is not None:
            cmd.attrib["CommandId"] = str(command_id).upper()

        ElementTree.SubElement(cmd, "{%s}Command" % rsp).text = executable
        for argument in args:
            ElementTree.SubElement(cmd, "{%s}Arguments" % rsp).text = argument

        return self.wsman.command(self.resource_uri, cmd, option_set=options, selector_set=self.selector_set)

    def close(
        self,
    ) -> str:
        return self.wsman.delete(self.resource_uri, selector_set=self.selector_set)

    def open(
        self,
        base_options: t.Optional[OptionSet] = None,
        open_content: t.Optional[ElementTree.Element] = None,
    ) -> str:
        rsp = NAMESPACES["rsp"]

        shell = ElementTree.Element("{%s}Shell" % rsp)
        if self.shell_id.int != 0:
            shell.attrib["ShellId"] = str(self.shell_id).upper()

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
            options.add_option("WINRS_NOPROFILE", str(self.no_profile))

        if self.codepage is not None:
            options.add_option("WINRS_CODEPAGE", str(self.codepage))

        return self.wsman.create(
            self.resource_uri,
            shell,
            option_set=options if len(options.values) else None,
        )

    def receive(
        self,
        stream: str = "stdout stderr",
        command_id: t.Optional[uuid.UUID] = None,
    ) -> str:
        rsp = NAMESPACES["rsp"]

        receive = ElementTree.Element("{%s}Receive" % rsp)
        stream_xml = ElementTree.SubElement(receive, "{%s}DesiredStream" % rsp)
        stream_xml.text = stream
        if command_id is not None:
            stream_xml.attrib["CommandId"] = str(command_id).upper()

        options = OptionSet()
        options.add_option("WSMAN_CMDSHELL_OPTION_KEEPALIVE", "True")

        return self.wsman.receive(self.resource_uri, receive, option_set=options, selector_set=self.selector_set)

    def send(
        self,
        stream: str,
        data: bytes,
        command_id: t.Optional[uuid.UUID] = None,
        end: t.Optional[bool] = None,
    ) -> str:
        rsp = NAMESPACES["rsp"]

        send = ElementTree.Element("{%s}Send" % rsp)
        stream_body = ElementTree.SubElement(send, "{%s}Stream" % rsp, Name=stream)
        stream_body.text = base64.b64encode(data).decode("utf-8")

        if end is not None:
            stream_body.attrib["End"] = str(end)

        if command_id is not None:
            stream_body.attrib["CommandId"] = str(command_id).upper()

        return self.wsman.send(self.resource_uri, send, selector_set=self.selector_set)

    def signal(
        self,
        signal: SignalCode,
        command_id: uuid.UUID,
    ) -> str:
        rsp = NAMESPACES["rsp"]

        body = ElementTree.Element("{%s}Signal" % rsp, attrib={"CommandId": str(command_id).upper()})
        ElementTree.SubElement(body, "{%s}Code" % rsp).text = signal.value

        return self.wsman.signal(self.resource_uri, body, selector_set=self.selector_set)

    def _parse_shell_create(
        self,
        response: ElementTree.Element,
        base_element: str = "s:Body/rsp:Shell/",
    ) -> None:
        """Process a WSMan Create response."""
        fields = [
            ("rsp:ShellId", "shell_id", uuid.UUID),
            ("rsp:ResourceUri", "resource_uri", str),
            ("rsp:Owner", "owner", str),
            ("rsp:ClientIP", "client_ip", str),
            ("rsp:IdleTimeOut", "idle_time_out", str),
            ("rsp:InputStreams", "input_streams", str),
            ("rsp:OutputStreams", "output_streams", str),
            ("rsp:ProcessId", "process_id", int),
            ("rsp:ShellRunTime", "shell_run_time", str),
            ("rsp:ShellInactivity", "shell_inactivity", str),
            ("rsp:State", "state", str),
        ]
        for xml_element, shell_attr, target_type in fields:
            element = response.find(f"{base_element}{xml_element}", NAMESPACES)
            if element is not None:
                value: t.Any = target_type(element.text)
                setattr(self, shell_attr, value)

        selector_set = response.find("wst:ResourceCreated/wsa:ReferenceParameters/wsman:SelectorSet", NAMESPACES)
        if selector_set is not None:
            self.selector_set = SelectorSet()
            for selector in selector_set:
                self.selector_set.add_option(selector.attrib["Name"], selector.text or "")
