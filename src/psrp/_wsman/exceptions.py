# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
from xml.etree import ElementTree

from ._protocol import NAMESPACES

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


class WSManHTTPError(Exception):
    """Raw HTTP errors for the WSMan connection."""

    def __new__(
        cls,
        http_code: int,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> WSManHTTPError:
        if http_code in [401, 407]:
            cls = WSManAuthenticationError

        return super().__new__(cls)

    def __init__(
        self,
        http_code: int,
        *,
        message: str | None = None,
    ) -> None:
        reason = _HTTP_CODES.get(http_code, "Unknown")

        error_type = {
            1: "Informational response",
            3: "Redirect response",
            4: "Client error",
            5: "Server error",
        }[http_code // 100]

        exception_msg = f"Received HTTP {error_type} response ({http_code} {reason})."
        if message:
            exception_msg = f"{exception_msg} {message}"

        super().__init__(exception_msg)
        self.http_code = http_code
        self.http_reason = reason


class WSManAuthenticationError(WSManHTTPError):
    """Authentication problem with WSMan."""


class _WSManFaultRegistry(type):
    __registry: dict[int, _WSManFaultRegistry] = {}

    def __init__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        code = getattr(cls, "_CODE", None)

        if code is not None:
            delattr(cls, "_CODE")
            cls.__registry[code] = cls

    def __call__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> t.Any:
        new_cls = cls
        if (detail := kwargs.get("detail", None)) and isinstance(detail, WSManFaultDetail):
            new_cls = cls.__registry.get(detail.code, cls)

        return super(_WSManFaultRegistry, new_cls).__call__(
            *args,
            **kwargs,
        )


class WSManFault(WSManHTTPError, metaclass=_WSManFaultRegistry):

    def __new__(
        cls,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> WSManFault:
        return super().__new__(cls, http_code=500)  # type: ignore[return-value]

    def __init__(
        self,
        code: str,
        subcode: str,
        *,
        reason: str | None = None,
        detail: FaultDetail | None = None,
    ):
        # code is mostly useless (Sender vs Receiver) whereas subcode could
        # contain useful info.
        message = f"WSManFault {subcode}." if subcode else "WSManFault."
        if detail:
            message = f"{message}\n{detail}"

        elif reason:
            message = f"{message} {reason}"

        super().__init__(http_code=500, message=message)

        self.code = code
        self.subcode = subcode
        self.reason = reason
        self.detail = detail

    @classmethod
    def create(
        cls,
        value: ElementTree.Element,
    ) -> WSManFault:
        fault = t.cast(ElementTree.Element, value.find("s:Body/s:Fault", namespaces=NAMESPACES))

        code_info = fault.find("s:Code/s:Value", namespaces=NAMESPACES)
        code = ""
        if code_info is not None and code_info.text:
            code = code_info.text.strip()

        subcode = code
        subcode_info = fault.find("s:Code/s:Subcode/s:Value", namespaces=NAMESPACES)
        if subcode_info is not None and subcode_info.text:
            subcode = subcode_info.text.strip()

        reason: str | None = None
        reason_info = fault.find("s:Reason/s:Text", namespaces=NAMESPACES)
        if reason_info is not None and reason_info.text:
            reason = reason_info.text.strip()

        if code == "s:MustUnderstand":
            not_understood_info = value.find("s:Header/s:NotUnderstood", namespaces=NAMESPACES)
            not_understood = ""
            if not_understood_info is not None:
                not_understood = not_understood_info.attrib.get("qname", not_understood)

            return WSManMustUnderstandFault(
                code=code,
                subcode=subcode,
                element=not_understood,
                reason=reason,
            )

        detail: FaultDetail | None = None
        detail_info = fault.find("s:Detail", namespaces=NAMESPACES)
        if detail_info is not None:
            detail = FaultDetail.create(detail_info)

        return WSManFault(
            code=code,
            subcode=subcode,
            reason=reason,
            detail=detail,
        )


class ErrorCancelled(WSManFault):
    # Not a WSMan NtStatus code but is returned for some disconnection operations
    _CODE = WSManFaultCode.CANCELLED


class OperationAborted(WSManFault):
    # Not a WSMan NtStatus code but is returned on an active Receive request when the shell is closed.
    _CODE = WSManFaultCode.OPERATION_ABORTED


class UnexpectedSelectors(WSManFault):
    _CODE = WSManFaultCode.UNEXPECTED_SELECTORS


class OperationTimedOut(WSManFault):
    _CODE = WSManFaultCode.OPERATION_TIMED_OUT


class ShellDisconnected(WSManFault):
    _CODE = WSManFaultCode.SHELL_DISCONNECTED


class ServiceStreamDisconnected(WSManFault):
    _CODE = WSManFaultCode.SERVICE_STREAM_DISCONNECTED


class WSManMustUnderstandFault(WSManFault):

    def __init__(
        self,
        code: str,
        subcode: str,
        element: str,
        reason: str | None = None,
    ) -> None:
        super().__init__(code=code, subcode=subcode, reason=reason)
        self.element = element


@dataclasses.dataclass(frozen=True)
class FaultDetail:
    raw: str
    detail: str | None

    def __str__(self) -> str:
        return self.raw

    @classmethod
    def create(
        cls,
        value: ElementTree.Element,
    ) -> FaultDetail:
        raw = ElementTree.tostring(
            value,
            encoding="unicode",
            method="xml",
        ).strip()

        detail: str | None = None
        detail_info = value.find("wsman:FaultDetail", NAMESPACES)
        if detail_info is not None and detail_info.text:
            detail = detail_info.text.strip()

        wsman_fault = value.find("wsmanfault:WSManFault", namespaces=NAMESPACES)
        if wsman_fault is not None:
            code = int(wsman_fault.attrib.get("Code", 0xFFFFFFFF))
            machine = wsman_fault.attrib.get("Machine", "")

            fault_message = ""
            message_info = wsman_fault.find("wsmanfault:Message", NAMESPACES)
            if message_info is not None:
                if message_info.text:
                    fault_message = message_info.text.strip()

                if not fault_message:
                    fault_message = ElementTree.tostring(
                        message_info,
                        encoding="unicode",
                        method="xml",
                    ).strip()

            return WSManFaultDetail(
                raw=raw,
                detail=detail,
                code=code,
                machine=machine,
                message=fault_message,
            )

        wmi_error = value.find("p:MSFT_WmiError", namespaces=NAMESPACES)
        if wmi_error is not None:
            wmi_kwargs: dict[str, t.Any] = {}
            fields = [
                ("p:CIMStatusCode", "cim_status_code", int),
                ("p:CIMStatusCodeDescription", "cim_status_code_description", str),
                ("p:error_Category", "error_category", int),
                ("p:error_Code", "error_code", int),
                ("p:ErrorSource", "error_source", int),
                ("p:ErrorSourceFormat", "error_source_format", int),
                ("p:ErrorType", "error_type", int),
                ("p:error_Type", "error_type_str", str),
                ("p:error_WindowsErrorMessage", "error_windows_error_message", str),
                ("p:Message", "message", str),
                ("p:MessageID", "message_id", str),
                ("p:OtherErrorSourceFormat", "other_error_source_format", str),
                ("p:OtherErrorType", "other_error_type", str),
                ("p:OwningEntity", "owning_entity", str),
                ("p:PerceivedSeverity", "perceived_severity", int),
                ("p:ProbableCause", "probable_cause", int),
                ("p:ProbableCauseDescription", "probably_cause_description", str),
            ]
            for xml_element, attr, target_type in fields:
                element = wmi_error.find(xml_element, NAMESPACES)

                if element is not None and element.text:
                    wmi_kwargs[attr] = target_type(element.text.strip())
                else:
                    wmi_kwargs[attr] = target_type()

            return WMIError(
                raw=raw,
                detail=detail,
                **wmi_kwargs,
            )

        return FaultDetail(raw=raw, detail=detail)


@dataclasses.dataclass(frozen=True)
class WSManFaultDetail(FaultDetail):
    code: int
    machine: str
    message: str

    def __str__(self) -> str:
        error_id = "UNKNOWN_CODE"
        if self.code in WSManFaultCode._value2member_map_:
            error_id = WSManFaultCode(self.code).name

        return f"FaultDetail {error_id} 0x{self.code:08X}\n{self.message}"


@dataclasses.dataclass(frozen=True)
class WMIError(FaultDetail):
    # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/raserverpsprov/msft-wmierror
    cim_status_code: int
    cim_status_code_description: str
    error_category: int
    error_code: int
    error_source: str
    error_source_format: int
    error_type: int
    error_type_str: str
    error_windows_error_message: str
    message: str
    message_id: str
    other_error_source_format: str
    other_error_type: str
    owning_entity: str
    perceived_severity: int
    probable_cause: int
    probably_cause_description: str

    def __str__(self) -> str:
        return f"WMIError {self.error_type_str} 0x{self.error_code:08X}\n{self.message}"
