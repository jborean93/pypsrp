# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import typing as t

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
_HTTP_CODES: dict[int, str] = {
    # Information
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    # Successful
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",
    # Redirection
    300: "Multiple Choice",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    # Client error
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",
    421: "Misdirected Request",
    422: "Unprocessable Content",
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    # Server error
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required",
}


class WSManHTTPError(Exception):
    """Raw HTTP errors for the WSMan connection."""

    def __new__(
        cls,
        http_code: int,
        *,
        msg: str | None = None,
    ) -> WSManHTTPError:
        if http_code in [401, 407]:
            cls = WSManAuthenticationError

        return super().__new__(cls)

    def __init__(
        self,
        http_code: int,
        *,
        msg: str | None = None,
    ) -> None:
        reason = _HTTP_CODES.get(http_code, "Unknown")

        error_type = {
            1: "Informational response",
            3: "Redirect response",
            4: "Client error",
            5: "Server error",
        }[http_code // 100]

        exception_msg = f"{error_type} '{http_code} {reason}'."
        if msg:
            exception_msg = f"{exception_msg} {msg}"

        super().__init__(exception_msg)
        self.reason = reason
        self.http_code = http_code


class WSManAuthenticationError(WSManHTTPError):
    """Authentication problem with WSMan."""


class WSManFaultCode(enum.IntEnum):
    """WSMan error codes.

    A collection of known WSMan error codes as retrieved from `wsmerror.h`_ in
    the Windows SDK. This is built based on the WSManFault exceptions that have
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
