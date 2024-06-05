# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import logging
import typing as t
import uuid
from xml.etree import ElementTree

from ._protocol import (
    NAMESPACES,
    OptionSet,
    SelectorSet,
    SignalCode,
    WSManAction,
    create_envelope,
    create_header,
)
from .events import CreateResponseEvent, FaultEvent, WSManEvent

log = logging.getLogger(__name__)


class WSManClient:
    """WSMan Message Processor.

    This handles creating and processing WSMan envelopes in an IO-less way. New
    messages are queued through the various action functions like
    :meth:`command`, :meth:`create`, :meth:`signal`, etc. The
    :meth:`data_to_send` function is used to get the data to send to the peer
    and :meth:`receive_data` is used to process data from the peer into WSMan
    events.

    Parameters:
        connection_uri: The connection URI used as the target.
        max_envelope_size: The maximum WSMan envelope size allowed.
        operation_timeout: The timeout in seconds that each WSMan operation
            can take on the peer before timing out.
        locale: The locale language string.
        data_locale: The data locale language string.
    """

    def __init__(
        self,
        connection_uri: str,
        max_envelope_size: int = 153600,
        operation_timeout: int = 20,
        locale: str = "en-US",
        data_locale: str | None = None,
    ) -> None:
        self.connection_uri = connection_uri
        self.session_id = str(uuid.uuid4()).upper()
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout
        self.locale = locale
        self.data_locale = data_locale or locale

        self._data_to_send = bytearray()

    def command(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.COMMAND,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def connect(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.CONNECT,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def create(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.CREATE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def delete(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.DELETE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def disconnect(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.DISCONNECT,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def enumerate(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.ENUMERATE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def receive(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.RECEIVE,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def reconnect(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.RECONNECT,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def send(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.SEND,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def signal(
        self,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        return self._build_envelope(
            WSManAction.SIGNAL,
            resource_uri,
            resource=resource,
            option_set=option_set,
            selector_set=selector_set,
            timeout=timeout,
        )

    def data_to_send(
        self,
        amount: int | None = None,
    ) -> bytes:
        """Get a set amount of data to send.

        Gets the data in the queue waiting to be sent to the peer.

        Args:
            amount: The maximum length of data that can be sent.

        Returns:
            bytes: The data to send.
        """
        if amount is None:
            amount = len(self._data_to_send)

        data = bytes(self._data_to_send[:amount])
        self._data_to_send = self._data_to_send[amount:]
        return data

    def receive_data(
        self,
        data: bytes,
    ) -> WSManEvent:
        """Receive raw WSMan payload.

        Receives the raw WSMan payloads and converts it to a WSMan event
        representing the type of response received.

        Args:
            data: The raw bytes to process.

        Returns:
            WSManEvent: The processed WSMan event.

        Raises:
            WSManFault: Raised when a WSMan Fault message is processed and
                contains the fault information.
        """
        wsman_data = ElementTree.fromstring(data)
        event = WSManEvent(wsman_data)

        if isinstance(event, FaultEvent):
            raise event.error

        return event

    def _build_envelope(
        self,
        action: WSManAction,
        resource_uri: str,
        resource: ElementTree.Element | None = None,
        option_set: OptionSet | None = None,
        selector_set: SelectorSet | None = None,
        timeout: int | None = None,
    ) -> str:
        s = NAMESPACES["s"]

        header, message_id = create_header(
            action=action,
            connection_uri=self.connection_uri,
            data_locale=self.data_locale,
            locale=self.locale,
            max_envelope_size=self.max_envelope_size,
            operation_timeout=timeout or self.operation_timeout,
            resource_uri=resource_uri,
            session_id=self.session_id,
            option_set=option_set,
            selector_set=selector_set,
        )
        content = create_envelope(header, resource)
        self._data_to_send += content

        return message_id


class CommandInfo(t.NamedTuple):
    command_id: uuid.UUID
    state: str


class WinRSClient:
    def __init__(
        self,
        wsman: WSManClient,
        resource_uri: str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
        shell_id: str | None = None,
        input_streams: str = "stdin",
        output_streams: str = "stdout stderr",
        codepage: int | None = None,
        environment: dict[str, str] | None = None,
        idle_time_out: int | None = None,
        lifetime: int | None = None,
        name: str | None = None,
        no_profile: bool | None = None,
        working_directory: str | None = None,
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
        self.owner: str | None = None
        self.client_ip: str | None = None
        self.shell_run_time: str | None = None
        self.shell_inactivity: str | None = None
        self.state = ""
        self.selector_set: SelectorSet | None = None

    @classmethod
    def enumerate_winrs(
        cls,
        wsman: WSManClient,
        resource_uri: str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
        selector_filter: SelectorSet | None = None,
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

    @classmethod
    def receive_winrs_enumeration(
        cls,
        wsman: WSManClient,
        data: bytes,
    ) -> tuple[list[WinRSClient], list[CommandInfo]]:
        cmd_enumeration = wsman.receive_data(data)

        shells: list[WinRSClient] = []
        commands: list[CommandInfo] = []

        items: ElementTree.Element | None = cmd_enumeration.body.find(
            "wsen:EnumerateResponse/wsman:Items", namespaces=NAMESPACES
        )
        if items is not None:
            for raw in items:
                if raw.tag == "{%s}Shell" % NAMESPACES["rsp"]:
                    profile_loaded = False
                    raw_profile_loaded = raw.find("rsp:ProfileLoaded", NAMESPACES)
                    if raw_profile_loaded is not None:
                        profile_loaded = (raw_profile_loaded.text or "").lower() == "yes"

                    shell = WinRSClient(wsman, no_profile=not profile_loaded)
                    shell._parse_shell_create(raw, base_element="")
                    shell.selector_set = SelectorSet()
                    shell.selector_set.add_option("ShellId", str(shell.shell_id).upper())
                    shells.append(shell)

                else:
                    command_id = t.cast(ElementTree.Element, raw.find("rsp:CommandId", namespaces=NAMESPACES))
                    command_state = t.cast(ElementTree.Element, raw.find("rsp:CommandState", namespaces=NAMESPACES))
                    commands.append(CommandInfo(command_id=uuid.UUID(command_id.text), state=command_state.text or ""))

        return shells, commands

    def data_to_send(
        self,
        amount: int | None = None,
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
        args: list[str] | None = None,
        no_shell: bool = False,
        command_id: uuid.UUID | None = None,
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
        base_options: OptionSet | None = None,
        open_content: ElementTree.Element | None = None,
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
        command_id: uuid.UUID | None = None,
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
        command_id: uuid.UUID | None = None,
        end: bool | None = None,
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
        """Process a WSManClient Create response."""
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
