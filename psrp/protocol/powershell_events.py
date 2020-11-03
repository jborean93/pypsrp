# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from ..dotnet.complex_types import (
    PSInvocationState,
    PSRPErrorRecord,
    RunspacePoolState,
)

from ..dotnet.primitive_types import (
    PSBool,
)

from ..dotnet.ps_base import (
    PSObject,
)

from ..dotnet.psrp_messages import (
    CreatePipeline,
    GetCommandMetadata,
    PSRPMessageType,
)


class _PSRPEventRegistry(type):
    __registry = {}

    def __init__(cls, *args, **kwargs):
        super().__init__(*args, **kwargs)
        message_type = getattr(cls, 'MESSAGE_TYPE', None)
        if message_type is not None and message_type not in cls.__registry:
            cls.__registry[message_type] = cls

    def __call__(
            cls,
            message_type: PSRPMessageType,
            ps_object: PSObject,
            runspace_pool_id: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        new_cls = cls.__registry.get(message_type, cls)
        return super(_PSRPEventRegistry, new_cls).__call__(message_type, ps_object, runspace_pool_id, pipeline_id)


class PSRPEvent(metaclass=_PSRPEventRegistry):

    def __init__(
            self,
            message_type: PSRPMessageType,
            ps_object: PSObject,
            runspace_pool_id: str,
            pipeline_id: typing.Optional[str] = None,
    ):
        self.ps_object = ps_object
        self.runspace_pool_id = runspace_pool_id
        self.pipeline_id = pipeline_id


class ApplicationPrivateDataEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.ApplicationPrivateData


class ConnectRunspacePoolEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.ConnectRunspacePool


class CreatePipelineEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.CreatePipeline

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pipeline: typing.Optional[CreatePipeline] = None


class DebugRecordEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.DebugRecord


class EncryptedSessionKeyEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.EncryptedSessionKey


class EndOfPipelineInputEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.EndOfPipelineInput


class ErrorRecordEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.ErrorRecord


class GetAvailableRunspacesEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.GetAvailableRunspaces


class GetCommandMetadataEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.GetCommandMetadata

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pipeline: typing.Optional[GetCommandMetadata] = None


class InformationRecordEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.InformationRecord


class InitRunspacePoolEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.InitRunspacePool


class PipelineHostCallEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.PipelineHostCall


class PipelineHostResponseEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.PipelineHostResponse


class PublicKeyEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.PublicKey


class PublicKeyRequestEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.PublicKeyRequest


class PipelineInputEvent(PSRPEvent):
    MESSAE_TYPE = PSRPMessageType.PipelineInput


class PipelineOutputEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.PipelineOutput


class PipelineStateEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.PipelineState

    @property
    def state(self) -> PSInvocationState:
        return PSInvocationState(self.ps_object.PipelineState)

    @property
    def reason(self) -> typing.Optional[PSRPErrorRecord]:
        return getattr(self.ps_object, 'ExceptionAsErrorRecord', None)


class ProgressRecordEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.ProgressRecord


class ResetRunspaceStateEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.ResetRunspaceState


class RunspaceAvailabilityEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.RunspaceAvailability

    def __new__(
            cls,
            message_type: PSRPMessageType,
            ps_object: PSObject,
            pipeline_id: typing.Optional[str] = None,
    ):
        # Special case, this message has a boolean value when in response to Set[Max|Min]Runspaces and an Int64
        # value when in response to GetAvailableRunspaces. We want to make sure our event is clear what it is in
        # response to.
        if isinstance(ps_object.SetMinMaxRunspacesResponse, PSBool):
            new_cls = SetRunspaceAvailabilityEvent
        else:
            new_cls = GetRunspaceAvailabilityEvent

        return super().__new__(new_cls)


class SetRunspaceAvailabilityEvent(RunspaceAvailabilityEvent):

    @property
    def success(self) -> bool:
        return self.ps_object.SetMinMaxRunspacesResponse


class GetRunspaceAvailabilityEvent(RunspaceAvailabilityEvent):

    @property
    def count(self) -> int:
        return int(self.ps_object.SetMinMaxRunspacesResponse)


class RunspacePoolHostCallEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.RunspacePoolHostCall


class RunspacePoolHostResponseEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.RunspacePoolHostResponse


class RunspacePoolInitDataEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.RunspacePoolInitData


class RunspacePoolStateEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.RunspacePoolState

    @property
    def state(self) -> RunspacePoolState:
        return RunspacePoolState(self.ps_object.RunspaceState)

    @property
    def reason(self) -> typing.Optional[PSRPErrorRecord]:
        return getattr(self.ps_object, 'ExceptionAsErrorRecord', None)


class SessionCapabilityEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.SessionCapability


class SetMaxRunspacesEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.SetMaxRunspaces


class SetMinRunspacesEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.SetMinRunspaces


class UserEventEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.UserEvent


class VerboseRecordEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.VerboseRecord


class WarningRecordEvent(PSRPEvent):
    MESSAGE_TYPE = PSRPMessageType.WarningRecord
