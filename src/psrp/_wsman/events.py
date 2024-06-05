# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import typing as t
import uuid
from xml.etree import ElementTree

from ._protocol import NAMESPACES, CommandState, WSManAction
from .exceptions import WSManFault


class _WSManEventRegistry(type):
    __registry: dict[str, _WSManEventRegistry] = {}

    def __init__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        action: WSManAction | None = getattr(cls, "_ACTION", None)
        if action is not None:
            delattr(cls, "_ACTION")
            cls.__registry[action.value] = cls

    def __call__(
        cls,
        data: ElementTree.Element,
    ) -> t.Any:
        action = data.find("s:Header/wsa:Action", namespaces=NAMESPACES)
        new_cls = cls
        if action is not None and action.text:
            new_cls = cls.__registry.get(action.text, cls)

        return super(_WSManEventRegistry, new_cls).__call__(data)


class WSManEvent(metaclass=_WSManEventRegistry):
    def __init__(
        self,
        data: ElementTree.Element,
    ):
        self._raw = data

    @property
    def header(self) -> ElementTree.Element:
        """The WSMan header XML Element."""
        return self._raw.find("s:Header", namespaces=NAMESPACES)  # type: ignore[return-value]

    @property
    def body(self) -> ElementTree.Element:
        """The WSMan body XML Element."""
        return self._raw.find("s:Body", namespaces=NAMESPACES)  # type: ignore[return-value]

    @property
    def message_id(self) -> uuid.UUID:
        """The unique message identifier of the message."""
        message_id = t.cast(ElementTree.Element, self._raw.find("s:Header/wsa:MessageID", namespaces=NAMESPACES))

        # The XML element text starts with uuid: which should be removed
        return uuid.UUID(t.cast(str, message_id.text)[5:])


class GetEvent(WSManEvent):
    _ACTION = WSManAction.GET


class GetResponseEvent(WSManEvent):
    _ACTION = WSManAction.GET_RESPONSE


class PutEvent(WSManEvent):
    _ACTION = WSManAction.PUT


class PutResponseEvent(WSManEvent):
    _ACTION = WSManAction.PUT_RESPONSE


class CreateEvent(WSManEvent):
    _ACTION = WSManAction.CREATE


class CreateResponseEvent(WSManEvent):
    _ACTION = WSManAction.CREATE_RESPONSE


class DeleteEvent(WSManEvent):
    _ACTION = WSManAction.DELETE


class DeleteResponseEvent(WSManEvent):
    _ACTION = WSManAction.DELETE_RESPONSE


class EnumerateEvent(WSManEvent):
    _ACTION = WSManAction.ENUMERATE


class EnumerateResponseEvent(WSManEvent):
    _ACTION = WSManAction.ENUMERATE_RESPONSE


class FaultEvent(WSManEvent):
    _ACTION = WSManAction.FAULT

    def __init__(
        self,
        data: ElementTree.Element,
    ):
        super().__init__(data)
        self.error = WSManFault.create(data)


class FaultAddressingEvent(FaultEvent):
    _ACTION = WSManAction.FAULT_ADDRESSING


class PullEvent(WSManEvent):
    _ACTION = WSManAction.PULL


class PullResponseEvent(WSManEvent):
    _ACTION = WSManAction.PULL_RESPONSE


class CommandEvent(WSManEvent):
    _ACTION = WSManAction.COMMAND


class CommandResponseEvent(WSManEvent):
    _ACTION = WSManAction.COMMAND_RESPONSE

    @property
    def command_id(self) -> uuid.UUID:
        """The unique command identifier of the command that was created."""
        command_id = t.cast(
            ElementTree.Element, self._raw.find("s:Body/rsp:CommandResponse/rsp:CommandId", namespaces=NAMESPACES)
        )
        return uuid.UUID(command_id.text or "")


class ConnectEvent(WSManEvent):
    _ACTION = WSManAction.CONNECT


class ConnectResponseEvent(WSManEvent):
    _ACTION = WSManAction.CONNECT_RESPONSE


class DisconnectEvent(WSManEvent):
    _ACTION = WSManAction.DISCONNECT


class DisconnectResponseEvent(WSManEvent):
    _ACTION = WSManAction.DISCONNECT_RESPONSE


class ReceiveEvent(WSManEvent):
    _ACTION = WSManAction.RECEIVE


class ReceiveResponseEvent(WSManEvent):
    _ACTION = WSManAction.RECEIVE_RESPONSE

    @property
    def command_state(self) -> CommandState | None:
        """Describes the current state of the command."""
        command_state = self._raw.find("s:Body/rsp:ReceiveResponse/rsp:CommandState", namespaces=NAMESPACES)
        return CommandState(command_state.attrib["State"]) if command_state is not None else None

    @property
    def streams(self) -> dict[str, list[bytes]]:
        """Returns the raw command output separated by each stream it was written to."""
        buffer: dict[str, list[bytes]] = {}
        streams = self._raw.findall("s:Body/rsp:ReceiveResponse/rsp:Stream", namespaces=NAMESPACES)
        for stream in streams:
            stream_name = stream.attrib["Name"]
            if stream_name not in buffer:
                buffer[stream_name] = []

            if stream.text is not None:
                stream_value = base64.b64decode(stream.text.encode("utf-8"))
                buffer[stream_name].append(stream_value)

        return buffer


class ReconnectEvent(WSManEvent):
    _ACTION = WSManAction.RECONNECT


class ReconnectResponseEvent(WSManEvent):
    _ACTION = WSManAction.RECONNECT_RESPONSE


class SendEvent(WSManEvent):
    _ACTION = WSManAction.SEND


class SendResponseEvent(WSManEvent):
    _ACTION = WSManAction.SEND_RESPONSE


class SignalEvent(WSManEvent):
    _ACTION = WSManAction.SIGNAL


class SignalResponseEvent(WSManEvent):
    _ACTION = WSManAction.SIGNAL_RESPONSE
