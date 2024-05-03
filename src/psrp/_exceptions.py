# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from psrpcore.types import ErrorRecord


class PSRPError(Exception):
    """Base error class for psrp operations."""


class PSRPConnectionError(PSRPError):
    """Errors relating to connection problems."""


class PSRPAuthenticationError(PSRPConnectionError):
    """Errors relating to authentication problems."""


class PipelineFailed(PSRPError):
    """A pipeline failed to start/complete."""

    def __init__(
        self,
        message: str,
        error_record: ErrorRecord | None = None,
    ) -> None:
        super().__init__(message)
        self.error_record = error_record


class PipelineStopped(PSRPError):
    """A pipeline was stopped."""

    def __init__(
        self,
        message: str,
        error_record: ErrorRecord | None = None,
    ) -> None:
        super().__init__(message)
        self.error_record = error_record


class RunspaceNotAvailable(PSRPError):
    """A runspace pool is not available for use, most likely connected to another client."""
