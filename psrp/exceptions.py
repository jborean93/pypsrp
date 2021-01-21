# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing


class _WSManFaultRegistry(type):
    __registry = {}

    def __init__(
            cls,
            name,
            bases,
            attributes,
    ):
        cls.__registry.setdefault(cls.CODE, cls)

    def __call__(
            cls,
            **kwargs
    ):
        code = None
        if 'code' in kwargs:
            code = kwargs.pop('code')
        code = code if code is not None else cls.CODE

        new_cls = cls
        if code is not None:
            new_cls = cls.__registry.get(code, cls)

        return super(_WSManFaultRegistry, new_cls).__call__(code=code, **kwargs)

    @staticmethod
    def registry_entries() -> typing.List[typing.Tuple[str, int]]:
        """ Builds a tuple that is used to define the WSManFaultCode enum. """
        entries = []
        for error_details in _WSManFaultRegistry.__registry.values():
            name = error_details.MESSAGE_ID
            if name.startswith('ERROR_'):
                name = name[6:]

            if name.startswith('WSMAN_'):
                name = name[6:]

            value = error_details.CODE

            entries.append((name, value))

        return entries


class WSManFault(Exception, metaclass=_WSManFaultRegistry):
    CODE = 0x8033FFFF
    MESSAGE = 'Unknown WS-Management fault.'
    MESSAGE_ID = 'ERROR_WSMAN_UNKNOWN'

    def __init__(
            self,
            code: typing.Optional[int] = None,
            machine: typing.Optional[str] = None,
            reason: typing.Optional[str] = None,
            provider: typing.Optional[str] = None,
            provider_path: typing.Optional[str] = None,
            provider_fault: typing.Optional[str] = None,
    ):
        self.code = code
        self.machine = machine
        self.reason = reason
        self.provider = provider
        self.provider_path = provider_path
        self.provider_fault = provider_fault

    @property
    def message(self):
        error_details = []
        if self.code:
            error_details.append("Code: %s" % self.code)

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

        if len(error_details) == 0:
            error_details.append("No details provided")

        return "Received a WSManFault message. (%s)" % ", ".join(error_details)

    def __str__(self):
        return self.message


class OperationAborted(WSManFault):
    # Not a WSMan NtStatus code but is returned on an active Receive request when the shell is closed.
    CODE = 0x000003E3
    MESSAGE = 'The I/O operation has been aborted because of either a thread exit or an application request.'
    MESSAGE_ID = 'ERROR_OPERATION_ABORTED'


class OperationTimedOut(WSManFault):
    CODE = 0x80338029
    MESSAGE = ('The WS-Management service cannot complete the operation within the time specified in '
               'OperationTimeout.')
    MESSAGE_ID = 'ERROR_WSMAN_OPERATION_TIMEDOUT'


class ServiceStreamDisconnected(WSManFault):
    CODE = 0x803381DE
    MESSAGE = ('The WS-Management service cannot process the request because the stream is currently disconnected.')
    MESSAGE_ID = 'ERROR_WSMAN_SERVICE_STREAM_DISCONNECTED'


"""WSMan error codes.

A collection of known WSMan error codes as retrieved from `wsman.h`_ in the Windows SDK. This is built based on the
WSManFault exceptions that have been defined.

.. wsman.h:
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wsmandisp.h
"""
WSManFaultCode = enum.IntEnum('WSManFaultCode', _WSManFaultRegistry.registry_entries(), module=__name__)


class PSRPError(Exception):
    """ Base error for any PSRP errors. """
    pass


class MissingCipherError(PSRPError):
    """ Trying to (de)serialize a Secure String but no cipher was provided. """

    @property
    def message(self) -> str:
        return 'Cannot (de)serialize a secure string without an exchanged session key'

    def __str__(self):
        return self.message


class RunspacePoolWantRead(PSRPError):
    """ Runspace Pool must receive more data to generate the next event. """
    pass


class _InvalidState(PSRPError):
    _STATE_OBJ = None

    def __init__(
            self,
            action: str,
            current_state,
            expected_states,
    ):
        self.action = action
        self.current_state = current_state
        self.expected_states = expected_states

    @property
    def message(self) -> str:
        expected_states = ', '.join(self.expected_states)
        return f"{self._STATE_OBJ} state must be one of '{expected_states}' to {self.action}, current state is " \
               f"{self.current_state!s}"

    def __str__(self):
        return self.message


class InvalidRunspacePoolState(_InvalidState):
    """ The Runspace Pool is not in the required state. """
    _STATE_OBJ = 'Runspace Pool'


class InvalidPipelineState(_InvalidState):
    """ The Pipeline is not in the required state. """
    _STATE_OBJ = 'Pipeline'


class InvalidProtocolVersion(PSRPError):
    """ The protocolversion of the peer does not meet the required version. """

    def __init__(
            self,
            action: str,
            current_version,
            required_version,
    ):
        self.action = action
        self.current_version = current_version
        self.required_version = required_version

    @property
    def message(self) -> str:
        return f'{self.action} requires a protocol version of {self.required_version}, current version is ' \
               f'{self.current_version}'

    def __str__(self):
        return self.message
