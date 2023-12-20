# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import typing as t


class WSManHTTPError(Exception):
    """Raw HTTP errors for the WSMan connection."""

    def __new__(
        cls,
        msg: str,
        http_code: int,
    ) -> WSManHTTPError:
        if http_code == 401:
            cls = WSManAuthenticationError

        return super().__new__(cls)

    def __init__(
        self,
        msg: str,
        http_code: int,
    ) -> None:
        super().__init__(msg)
        self.http_code = http_code


class WSManAuthenticationError(WSManHTTPError):
    """Authentication problem with WSMan."""


class WSManFaultCode(enum.IntEnum):
    """WSMan error codes.

    A collection of known WSMan error codes as retrieved from `wsmerror.h`_ in the
    Windows SDK. This is built based on the WSManFault exceptions that have
    been defined.

    .. wsmerror.h:
        https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wsmerror.h
    """

    CANCELLED = 0x000004C7
    OPERATION_ABORTED = 0x000003E3
    OPERATION_TIMED_OUT = 0x80338029
    UNEXPECTED_SELECTORS = 0x8033805B
    SHELL_DISCONNECTED = 0x803381C4
    SERVICE_STREAM_DISCONNECTED = 0x803381DE
    UNKNOWN = 0x8033FFFF


class _WSManFaultRegistry(type):
    __registry: dict[int, _WSManFaultRegistry] = {}

    def __init__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        code = getattr(cls, "CODE", None)
        if code is not None:
            cls.__registry[int(code)] = cls

    def __call__(
        cls,
        code: int | None = None,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> t.Any:
        new_cls = cls
        if code is None:
            code = getattr(cls, "CODE", WSManFaultCode.UNKNOWN)
        else:
            new_cls = cls.__registry.get(code, cls)

        return super(_WSManFaultRegistry, new_cls).__call__(code=code, *args, **kwargs)


class WSManFault(Exception, metaclass=_WSManFaultRegistry):
    CODE = WSManFaultCode.UNKNOWN
    MESSAGE = "Unknown WS-Management fault."

    def __init__(
        self,
        code: int | None = None,
        machine: str | None = None,
        reason: str | None = None,
        provider: str | None = None,
        provider_path: str | None = None,
        provider_fault: str | None = None,
    ):
        self.code = code
        self.machine = machine
        self.reason = reason
        self.provider = provider
        self.provider_path = provider_path
        self.provider_fault = provider_fault

    @property
    def message(self) -> str:
        error_details = []
        if self.code:
            if isinstance(self.code, enum.Enum):
                error_details.append("Code: %s %s" % (int(self.code), self.code.name))
            else:
                error_details.append("Code: %s" % int(self.code))

        if self.machine:
            error_details.append("Machine: %s" % self.machine)

        if self.reason:
            error_details.append("Reason: %s" % self.reason)

        if self.provider:
            error_details.append("Provider: %s" % self.provider)

        if self.provider_path:
            error_details.append("Provider Path: %s" % self.provider_path)

        if self.provider_fault:
            error_details.append("Provider Fault: %s" % self.provider_fault)

        return "Received a WSManFault message. (%s)" % ", ".join(error_details)

    def __str__(self) -> str:
        return self.message


class ErrorCancelled(WSManFault):
    # Not a WSMan NtStatus code but is returned for some disconnection operations
    CODE = WSManFaultCode.CANCELLED
    MESSAGE = "The operation was canceled by the user."


class OperationAborted(WSManFault):
    # Not a WSMan NtStatus code but is returned on an active Receive request when the shell is closed.
    CODE = WSManFaultCode.OPERATION_ABORTED
    MESSAGE = "The I/O operation has been aborted because of either a thread exit or an application request."


class UnexpectedSelectors(WSManFault):
    CODE = WSManFaultCode.UNEXPECTED_SELECTORS
    MESSAGE = (
        "The WS-Management service cannot process the request because the request contained invalid selectors "
        "for the resource."
    )


class OperationTimedOut(WSManFault):
    CODE = WSManFaultCode.OPERATION_TIMED_OUT
    MESSAGE = "The WS-Management service cannot complete the operation within the time specified in OperationTimeout."


class ShellDisconnected(WSManFault):
    CODE = WSManFaultCode.SHELL_DISCONNECTED
    MESSAGE = "The WinRM service cannot process the request because the WinRS shell instance is currently disconnected."


class ServiceStreamDisconnected(WSManFault):
    CODE = WSManFaultCode.SERVICE_STREAM_DISCONNECTED
    MESSAGE = "The WS-Management service cannot process the request because the stream is currently disconnected."
