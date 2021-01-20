# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""PSRP Messages.

The PSRP message types that are used as part of the PSRP fragments exchanged
between the client and the server.

.. MS-PSRP 2.2.2 Message Types:
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/a6136495-3260-4ff9-a982-7edf7ec95af2
"""

import enum
import typing

from .ps_base import (
    _PSMetaTypePSRP,
    PSNoteProperty,
    PSObjectMetaPSRP,
    TypeRegistry,
)

from .complex_types import (
    ApartmentState,
    CommandTypes,
    ErrorRecord as ComplexErrorRecord,
    HostInfo,
    HostMethodIdentifier,
    InformationalRecord,
    ProgressRecordType,
    PSGenericList,
    PSList,
    PSPrimitiveDictionary,
    PSThreadOptions,
    RemoteStreamOptions,
)

from .primitive_types import (
    _PSStringBase,
    PSBool,
    PSByteArray,
    PSDateTime,
    PSGuid,
    PSInt,
    PSInt64,
    PSObject,
    PSString,
    PSUInt,
    PSVersion,
)


class SessionCapability(PSObject, metaclass=_PSMetaTypePSRP):
    """SESSION_CAPABILITY Message.

    Defines the session capability and protocol versions. Message is defined in
    `MS-PSRP 2.2.2.1 SESSION_CAPABILITY`_. The TimeZone property is a .NET type
    serialized to bytes as defined by
    `MS-PSRP 2.2.3.10.1 CurrentSystemTimeZone`_.

    Args:
        PSVersion: The version of the higher-layer application.
        protocolversion: The version of the PowerShell Remoting Protocol.
        SerializationVersion: The version of the serialization system.
        TimeZone: The time zone of the client.

    .. _MS-PSRP 2.2.2.1 SESSION_CAPABILITY:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/2f41abfb-7e30-4fb1-b286-527e9d67ad30

    .. _MS-PSRP 2.2.3.10.1 CurrentSystemTimeZone:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/5e6263c5-358a-459b-a49e-0707e383eb55
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00010002,
        extended_properties=[
            PSNoteProperty('PSVersion', mandatory=True, ps_type=PSVersion),
            PSNoteProperty('protocolversion', mandatory=True, ps_type=PSVersion),
            PSNoteProperty('SerializationVersion', mandatory=True, ps_type=PSVersion),
            PSNoteProperty('TimeZone', optional=True, ps_type=PSByteArray),
        ],
    )


class InitRunspacePool(PSObject, metaclass=_PSMetaTypePSRP):
    """INIT_RUNSPACEPOOL Message.

    Defines the Runspace Pool initialization data. Message is defined in
    `MS-PSRP 2.2.2.2 INIT_RUNSPACEPOOL`_.

    Args:
        MinRunspaces: The minimum number of runspaces in the Runspace Pool.
        MaxRunspaces: The maximum number of runspaces in the Runspace Pool.
        PSThreadOptions: Thread options provided by the higher layer.
        ApartmentState: Apart state provided by the higher layer.
        HostInfo: Host information.
        ApplicationArguments: Application arguments provided by the higher
            layer.

    .. _MS-PSRP 2.2.2.2 INIT_RUNSPACEPOOL:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c867589a-0b43-47bd-9abf-7477699ff6c9

    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00010004,
        extended_properties=[
            PSNoteProperty('MinRunspaces', mandatory=True, ps_type=PSInt),
            PSNoteProperty('MaxRunspaces', mandatory=True, ps_type=PSInt),
            PSNoteProperty('PSThreadOptions', mandatory=True, ps_type=PSThreadOptions),
            PSNoteProperty('ApartmentState', mandatory=True, ps_type=ApartmentState),
            PSNoteProperty('HostInfo', mandatory=True, ps_type=HostInfo),
            PSNoteProperty('ApplicationArguments', mandatory=True, ps_type=PSPrimitiveDictionary),
        ],
    )


class PublicKey(PSObject, metaclass=_PSMetaTypePSRP):
    """PUBLIC_KEY Message.

    Defines the public key created by the client used in the session key
    exchange. Message is defined in `MS-PSRP 2.2.2.3 - PUBLIC_KEY`_.

    Args:
        PublicKey: The base64 encoding of the PKCS1 formatted public key.

    .. _MS-PSRP 2.2.2.3 - PUBLIC_KEY:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/3efa4b90-c089-432b-91db-76a3deb175bc
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00010005,
        extended_properties=[
            PSNoteProperty('PublicKey', mandatory=True, ps_type=PSString),
        ]
    )


class EncryptedSessionKey(PSObject, metaclass=_PSMetaTypePSRP):
    """ENCRYPTED_SESSION_KEY Message.

    Defines the encrypted session key calculated by the server. The value is
    encrypted using the public key that was sent by the client in the
    :class:`PublicKey` message. Message is defined in
    `MS-PSRP 2.2.2.4 - ENCRYPTED_SESSION_KEY`_.

    Note:
        The session key is encrypted using the RSAES-PKCS-v1_5 encryption
        scheme.

    Args:
        EncryptedSessionKey: The base64 encoding of the 256-bit AES encrypted
            session key.

    .. _MS-PSRP 2.2.2.4 - ENCRYPTED_SESSION_KEY:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e3e155af-b379-40cf-80c0-14a124145147
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00010006,
        extended_properties=[
            PSNoteProperty('EncryptedSessionKey', mandatory=True, ps_type=PSString),
        ]
    )


class PublicKeyRequest(_PSStringBase, metaclass=_PSMetaTypePSRP):
    """PUBLIC_KEY_REQUEST Message.

    This is a message that the server sends the client when it wants to start
    the encryption key exchange. Message is defined in
    `MS-PSRP 2.2.2.5 - PUBLIC_KEY_REQUEST`_.

    .. _MS-PSRP 2.2.2.5 - PUBLIC_KEY_REQUEST:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/9ff2857d-a7cb-4da6-81f1-65d08b3dbe63
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00010007,
        tag='S',
    )


class SetMaxRunspaces(PSObject, metaclass=_PSMetaTypePSRP):
    """SET_MAX_RUNSPACES Message.

    Set maximum runspaces in a RunspacePool. Message is defined in
    `MS-PSRP 2.2.2.6 - SET_MAX_RUNSPACES`_.

    Args:
        MaxRunspaces: The maximum runspaces in a pool.
        ci: The Call ID the message is related to.

    .. _MS-PSRP 2.2.2.6 - SET_MAX_RUNSPACES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/92037046-043a-4962-8e7e-2d457249548b
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021002,
        extended_properties=[
            PSNoteProperty('MaxRunspaces', mandatory=True, ps_type=PSInt),
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
        ]
    )


class SetMinRunspaces(PSObject, metaclass=_PSMetaTypePSRP):
    """SET_MIN_RUNSPACES Message.

    Set minimum runspaces in a RunspacePool. Message is defined in
    `MS-PSRP 2.2.2.7 - SET_MIN_RUNSPACES`_.

    Args:
        MinRunspaces: The minimum runspaces in a pool.
        ci: The Call ID the message is related to.

    .. _MS-PSRP 2.2.2.7 - SET_MIN_RUNSPACES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/2d425c82-ead1-4888-911a-b11f545ca441
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021003,
        extended_properties=[
            PSNoteProperty('MinRunspaces', mandatory=True, ps_type=PSInt),
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
        ]
    )


class RunspaceAvailability(PSObject, metaclass=_PSMetaTypePSRP):
    """RUNSPACE_AVAILABILITY Message.

    A response to either set maximum runspaces or set minimum runspaces in a
    RunspacePool or request for available runspaces in a RunspacePool. Message
    is defined in `MS-PSRP 2.2.2.8 - RUNSPACE_AVAILABILITY`_.

    Args:
        SetMinMaxRunspacesResponse: A
            :class:`PSBool <psrp.dotnet.primitive_types.PSBool>` for a set
            min/max response or a
            :class:`PSInt64 <psrp.dotnet.primitive_types.PSInt64>` for a get
            available response.
        ci: The Call ID the message is related to.

    .. _MS-PSRP 2.2.2.8 - RUNSPACE_AVAILABILITY:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/bcab75d9-31a8-4fdc-a8c4-00f41e5985d2
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021004,
        extended_properties=[
            PSNoteProperty('SetMinMaxRunspacesResponse', mandatory=True),
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
        ],
    )


class RunspacePoolState(PSObject, metaclass=_PSMetaTypePSRP):
    """RUNSPACEPOOL_STATE Message.

    Defines the state of the RunspacePool. Message is defined in
    `MS-PSRP 2.2.2.9 RUNSPACEPOOL_STATE`_. The raw RunspaceState values
    correlate to `MS-PSRP 2.2.3.4 RunspacePoolState`_ defined at
    :class:`RunspacePoolState <psrp.dotnet.complex_types.RunspacePoolState>`.

    Args:
        RunspaceState: The RunspacePool state information as an integer.
        ExceptionAsErrorRecord: The optional error record associated with the
            RunspacePool error.

    .. _MS-PSRP 2.2.2.9 RUNSPACEPOOL_STATE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/0a5d8ef3-3b2c-4e16-9f2c-16efdaf16925

    .. _MS-PSRP 2.2.3.4 RunspacePoolState:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/b05495bc-a9b2-4794-9f43-4bf1f3633900
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021005,
        extended_properties=[
            PSNoteProperty('RunspaceState', mandatory=True, ps_type=PSInt),
            PSNoteProperty('ExceptionAsErrorRecord', optional=True, ps_type=ComplexErrorRecord),
        ],
    )


class CreatePipeline(PSObject, metaclass=_PSMetaTypePSRP):
    """CREATE_PIPELINE Message.

    Creates a command pipeline and invoke it in the specified RunspacePool.
    Message is defined in `MS-PSRP 2.2.2.10 CREATE_PIPELINE`_.

    Args:
        NoInput: Whether the pipeline will take input.
        ApartmentState: Apartment state provided by the higher layer.
        RemoteStreamOptions: Stream options that indicate how an application
            must treat messages from the PowerShell streams.
        AddToHistory: Whether the higher layer is to add the pipeline to the
            history field of the runspace.
        HostInfo: The host information.
        PowerShell: The pipeline information to create.
        IsNested: Whether the higher layer is to run the pipeline in nested or
            steppable mode.

    .. _MS-PSRP 2.2.2.10 CREATE_PIPELINE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/2cf8cccb-63ab-404a-82df-caef0c41717a
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021006,
        extended_properties=[
            PSNoteProperty('NoInput', mandatory=True, ps_type=PSBool),
            PSNoteProperty('ApartmentState', mandatory=True, ps_type=ApartmentState),
            PSNoteProperty('RemoteStreamOptions', mandatory=True, ps_type=RemoteStreamOptions),
            PSNoteProperty('AddToHistory', mandatory=True, ps_type=PSBool),
            PSNoteProperty('HostInfo', mandatory=True, ps_type=HostInfo),
            PSNoteProperty('PowerShell', mandatory=True),
            PSNoteProperty('IsNested', mandatory=True, ps_type=PSBool),
        ],
    )


class GetAvailableRunspaces(PSObject, metaclass=_PSMetaTypePSRP):
    """GET_AVAILABLE_RUNSPACES Message.

    Get the number of available runspaces in a RunspacePool. Message is defined
    in `MS-PSRP 2.2.2.11 GET_AVAILABLE_RUNSPACES`_.

    Args:
        ci: The Call ID associated with this operation.

    .. _MS-PSRP 2.2.2.11 GET_AVAILABLE_RUNSPACES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/3f4d5a5c-9e7f-4ea2-8fea-253ddd394638
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021007,
        extended_properties=[
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
        ],
    )


class UserEvent(PSObject, metaclass=_PSMetaTypePSRP):
    """USER_EVENT Message.

    Report a user-defined event from a remote runspace. Message is defined in
    `MS-PSRP 2.2.2.12 USER_EVENT`_.

    Args:
        EventIdentifier: The event identifier.
        SourceIdentifier: The source identifier.
        TimeGenerated: The time when the event was generated.
        Sender: The sender of the event.
        SourceArgs: Event arguments.
        MessageData: Message data associated with the event.
        ComputerName: Name of the computer where the event was fired.
        RunspaceId: The ID of the runspace.

    .. _MS-PSRP 2.2.2.12 USER_EVENT:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c5a79f22-715d-4221-ae4d-47c685197b3b
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021008,
        extended_properties=[
            PSNoteProperty('PSEventArgs.EventIdentifier', ps_type=PSInt),
            PSNoteProperty('PSEventArgs.SourceIdentifier', ps_type=PSString),
            PSNoteProperty('PSEventArgs.TimeGenerated', ps_type=PSDateTime),
            PSNoteProperty('PSEventArgs.Sender'),
            PSNoteProperty('PSEventArgs.SourceArgs', mandatory=True),
            PSNoteProperty('PSEventArgs.MessageData'),
            PSNoteProperty('PSEventArgs.ComputerName', ps_type=PSString),
            PSNoteProperty('PSEventArgs.RunspaceId', ps_type=PSGuid),
        ],
    )

    # Use custom __init__ to make it easier to specify the properties (without the 'PSEventArgs.' prefix).
    def __init__(
            self,
            EventIdentifier: typing.Optional[PSInt] = None,
            SourceIdentifier: typing.Optional[PSString] = None,
            TimeGenerated: typing.Optional[PSDateTime] = None,
            Sender: typing.Optional['PSObject'] = None,
            SourceArgs: typing.Optional['PSObject'] = None,
            MessageData: typing.Optional['PSObject'] = None,
            ComputerName: typing.Optional[PSString] = None,
            RunspaceId: typing.Optional[PSGuid] = None,
    ):
        super().__init__(**{
            'PSEventArgs.EventIdentifier': EventIdentifier,
            'PSEventArgs.SourceIdentifier': SourceIdentifier,
            'PSEventArgs.TimeGenerated': TimeGenerated,
            'PSEventArgs.Sender': Sender,
            'PSEventArgs.SourceArgs': SourceArgs,
            'PSEventArgs.MessageData': MessageData,
            'PSEventArgs.ComputerName': ComputerName,
            'PSEventArgs.RunspaceId': RunspaceId,
        })


class ApplicationPrivateData(PSObject, metaclass=_PSMetaTypePSRP):
    """APPLICATION_PRIVATE_DATA Message.

    Data private to the application using the PowerShell Remoting Protocol on
    the server and client, which is passed by the protocol without
    interpretation. Message is defined in
    `MS-PSRP 2.2.2.13 APPLICATION_PRIVATE_DATA`_.

    Args:
        ApplicationPrivateData: Private data that the higher layer provides to
            the server when a RunspacePool is created.

    .. _MS-PSRP 2.2.2.13 APPLICATION_PRIVATE_DATA:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/f0e105d4-4242-429f-b63b-a600111fb27e
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021009,
        extended_properties=[
            PSNoteProperty('ApplicationPrivateData', mandatory=True, ps_type=PSPrimitiveDictionary),
        ],
    )


class GetCommandMetadata(PSObject, metaclass=_PSMetaTypePSRP):
    """GET_COMMAND_METADATA Message.

    Get command metadata for commands available in a RunspacePool. Message is
    defined in `MS-PSRP 2.2.2.14 GET_COMMAND_METADATA`_.

    Args:
        Name: List of wildcard patterns specifying the command names that the
            server SHOULD return.
        CommandType: The command types to search for.
        Namespace: The command namespaces containing the commands that the
            server SHOULD return.
        ArgumentList: Extra arguments passed to the higher layer above the
            PowerShell Remoting Protocol.

    .. _MS-PSRP 2.2.2.14 GET_COMMAND_METADATA:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/b634ddef-93a0-4d3b-9e63-a630d01f233a
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x0002100A,
        extended_properties=[
            PSNoteProperty('Name', ps_type=PSList),
            PSNoteProperty('CommandType', ps_type=CommandTypes),
            PSNoteProperty('Namespace', ps_type=PSList),
            PSNoteProperty('ArgumentList', ps_type=PSList),
        ],
    )


class RunspacePoolHostCall(PSObject, metaclass=_PSMetaTypePSRP):
    """RUNSPACEPOOL_HOST_CALL Message.

    Method call on the host associated with the RunspacePool on the server.
    Message is defined in `MS-PSRP 2.2.2.15 RUNSPACEPOOL_HOST_CALL`_.

    Args:
        ci: The Call ID associated with this operation.
        mi: The host method identifier.
        mp: The parameters for the method.

    .. _MS-PSRP 2.2.2.15 RUNSPACEPOOL_HOST_CALL:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4623540b-4dd3-440e-a54b-e0fb87dd92c8
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021100,
        extended_properties=[
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
            PSNoteProperty('mi', mandatory=True, ps_type=HostMethodIdentifier),
            PSNoteProperty('mp', mandatory=True, ps_type=PSList),
        ],
    )


class RunspacePoolHostResponse(PSObject, metaclass=_PSMetaTypePSRP):
    """RUNSPACEPOOL_HOST_RESPONSE Message.

    Response from a host call executed on the client RunspacePool's host.
    Message is defined in `MS-PSRP 2.2.2.16 RUNSPACEPOOL_HOST_RESPONSE`_.

    Args:
        ci: The Call ID associated with this operation.
        mi: The host method identifier.
        mr: The return value of the method.
        me: Exception thrown by a host method invocation.

    .. _MS-PSRP 2.2.2.16 RUNSPACEPOOL_HOST_RESPONSE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/9bcdf122-ad6b-45c3-9960-68d22627cdb5
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00021101,
        extended_properties=[
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
            PSNoteProperty('mi', mandatory=True, ps_type=HostMethodIdentifier),
            PSNoteProperty('mr', optional=True),
            PSNoteProperty('me', optional=True, ps_type=ComplexErrorRecord),
        ],
    )


class PipelineInput(PSObject, metaclass=_PSMetaTypePSRP):
    """PIPELINE_INPUT Message.

    Input to a command pipeline on the server. Message is defined in
    `MS-PSRP 2.2.2.17 PIPELINE_INPUT`_. The actual object is the serialized
    object that is being sent as input.

    .. _MS-PSRP 2.2.2.17 PIPELINE_INPUT:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/2c08acdd-3443-48c2-bf87-8fe2808d96ea
    """
    PSObject = PSObjectMetaPSRP(psrp_message_type=0x00041002)


class EndOfPipelineInput(PSObject, metaclass=_PSMetaTypePSRP):
    """END_OF_PIPELINE_INPUT Message.

    Close the input collection for the command pipeline on the server. Message
    is defined in `MS-PSRP 2.2.2.18 END_OF_PIPELINE_INPUT`_.

    .. _MS-PSRP 2.2.2.18 END_OF_PIPELINE_INPUT:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e616e6fd-0241-4823-b415-7dfc247646f1
    """
    PSObject = PSObjectMetaPSRP(psrp_message_type=0x00041003)


class PipelineOutput(PSObject, metaclass=_PSMetaTypePSRP):
    """PIPELINE_OUTPUT Message.

    Output of a command pipeline on the server. Message is defined in
    `MS-PSRP 2.2.2.19 PIPELINE_OUTPUT`_. The actual object is the serialized
    object that is being outputted from the server.

    .. _MS-PSRP 2.2.2.19 PIPELINE_OUTPUT:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/3b2c1076-c435-4aef-bdfe-3179bc452723
    """
    PSObject = PSObjectMetaPSRP(psrp_message_type=0x00041004)


class ErrorRecord(ComplexErrorRecord, metaclass=_PSMetaTypePSRP):
    """ERROR_RECORD Message.

    Error record from a command pipeline on the server.. Message is defined in
    `MS-PSRP 2.2.2.20 ERROR_RECORD`_.

    .. _MS-PSRP 2.2.2.20 ERROR_RECORD:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c527797a-d017-4755-8a81-9f58280a7135
    """
    PSObject = PSObjectMetaPSRP(psrp_message_type=0x00041005)


class PipelineState(PSObject, metaclass=_PSMetaTypePSRP):
    """PIPELINE_STATE Message.

    State information of a command pipeline on the server. Message is defined
    in `MS-PSRP 2.2.2.21 PIPELINE_STATE`_.
    The raw PipelineState values correlate to
    `MS-PSRP 2.2.3.5 PSInvocationState`_ defined at
    :class:`PSInvocationState <psrp.dotnet.complex_types.PSInvocationState>`.

    Args:
        PipelineState: State information of the command pipeline.
        ExceptionAsErrorRecord: The optional error record associated with the
            Pipeline state error.

    .. _MS-PSRP 2.2.2.21 PIPELINE_STATE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/932f0c9d-845a-4883-8efd-b49a593578b8

    .. _MS-PSRP 2.2.3.5 PSInvocationState:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/acaa253a-29be-45fd-911c-6715515a28b9
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00041006,
        extended_properties=[
            PSNoteProperty('PipelineState', mandatory=True, ps_type=PSInt),
            PSNoteProperty('ExceptionAsErrorRecord', optional=True, ps_type=ComplexErrorRecord),
        ],
    )


class DebugRecord(InformationalRecord, metaclass=_PSMetaTypePSRP):
    """DEBUG_RECORD Message.

    Debug record from a command pipeline on the server. Message is defined in
    `MS-PSRP 2.2.2.22 DEBUG_RECORD`_.

    .. _MS-PSRP 2.2.2.22 DEBUG_RECORD:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/43b4cb30-6b14-498b-9325-c60339838a22
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00041007,
        type_names=['System.Management.Automation.DebugRecord'],
    )


class VerboseRecord(InformationalRecord, metaclass=_PSMetaTypePSRP):
    """VERBOSE_RECORD Message.

    Verbose record from a command pipeline on the server. Message is defined in
    `MS-PSRP 2.2.2.23 VERBOSE_RECORD`_.

    .. _MS-PSRP 2.2.2.23 VERBOSE_RECORD:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/f94b18f5-0bd4-4817-8184-eb72767cce94
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00041008,
        type_names=['System.Management.Automation.VerboseRecord'],
    )


class WarningRecord(InformationalRecord, metaclass=_PSMetaTypePSRP):
    """WARNING_RECORD Message.

    Warning record from a command pipeline on the server. Message is defined in
    `MS-PSRP 2.2.2.24 WARNING_RECORD`_.

    .. _MS-PSRP 2.2.2.24 WARNING_RECORD:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/31c10c51-b831-475c-ae62-603426e6a617
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00041009,
        type_names=['System.Management.Automation.WarningRecord'],
    )


class ProgressRecord(PSObject, metaclass=_PSMetaTypePSRP):
    """PROGRESS_RECORD Message.

    Progress record from a command pipeline on the server. Message is defined
    in `MS-PSRP 2.2.2.25 PROGRESS_RECORD`_.

    Args:
        Activity: Description of the activity.
        ActivityId: Id of the activity, used as a key for the linking of
            subordinate activities.
        StatusDescription: Current status of the operation, e.g. "35 of 50
            items copied".
        CurrentOperation: Current operation of the many required to accomplish
            the activity, e.g. "copying foo.txt".
        ParentActivityId: Id of the activity for which this is a subordinate.
        PercentComplete: Percentage of total work for the activity that is
            completed.
        Type: Type of record represented by this instance.
        SecondsRemaining: Estimated time remaining until the activity is
            complete.

    .. _MS-PSRP 2.2.2.25 PROGRESS_RECORD:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/435ab824-1069-43eb-8146-7c50593a47ac
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00041010,
        extended_properties=[
            PSNoteProperty('Activity', ps_type=PSString),
            PSNoteProperty('ActivityId', ps_type=PSInt),
            PSNoteProperty('StatusDescription', ps_type=PSString),
            PSNoteProperty('CurrentOperation', ps_type=PSString),
            PSNoteProperty('ParentActivityId', ps_type=PSInt),
            PSNoteProperty('PercentComplete', ps_type=PSInt),
            PSNoteProperty('Type', ps_type=ProgressRecordType),
            PSNoteProperty('SecondsRemaining', ps_type=PSInt),
        ],
    )


class InformationRecord(PSObject, metaclass=_PSMetaTypePSRP):
    """INFORMATION_RECORD Message.

    Information record from a command pipeline on the server. Message is
    defined in `MS-PSRP 2.2.2.26 INFORMATION_RECORD`_.

    Note:
        This message is only used in ProtocolVersion>=2.3 (PowerShell v5.1+).

    Args:
        MessageData: The message data for the informational record.
        Source: The source of the information record (script path, function
            name, etc.).
        TimeGenerated: The time the informational record was generated.
        Tags: The tags associated with this informational record.
        User: THe user that generated the informational record.
        Computer: THe computer that generated the informational record.
        ProcessId: The process that generated the informational record.
        NativeThreadId: The native thread that generated the informational
            record.
        ManagedThreadId: The managed thread that generated the informational
            record.

    .. _MS-PSRP 2.2.2.26 INFORMATION_RECORD:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/5a3ec5f0-4654-4d87-830c-d3e07c4717c9
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00041011,
        type_names=[
            'System.Management.Automation.InformationRecord',
            'System.Object',
        ],
        extended_properties=[
            PSNoteProperty('MessageData'),
            PSNoteProperty('Source', ps_type=PSString),
            PSNoteProperty('TimeGenerated', ps_type=PSDateTime),
            PSNoteProperty('Tags', ps_type=PSGenericList[PSString]),
            PSNoteProperty('User', ps_type=PSString),
            PSNoteProperty('Computer', ps_type=PSString),
            PSNoteProperty('ProcessId', ps_type=PSUInt),
            PSNoteProperty('NativeThreadId', ps_type=PSUInt),
            PSNoteProperty('ManagedThreadId', ps_type=PSUInt),
        ],
    )


class PipelineHostCall(RunspacePoolHostCall):
    """PIPELINE_HOST_CALL Message.

    Method call on the host associated with the pipeline invocation settings on
    the server. Message is defined in `MS-PSRP 2.2.2.27 PIPELINE_HOST_CALL`_.

    Args:
        ci: The Call ID associated with this operation.
        mi: The host method identifier.
        mp: The parameters for the method.

    .. _MS-PSRP 2.2.2.27 PIPELINE_HOST_CALL:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/16947dfb-99b5-461f-b556-dec1beb33da8
    """
    PSObject = PSObjectMetaPSRP(psrp_message_type=0x00041100)


class PipelineHostResponse(RunspacePoolHostResponse):
    """PIPELINE_HOST_RESPONSE Message.

    Response from a host call executed on the client's host. Message is defined
    in `MS-PSRP 2.2.2.28 PIPELINE_HOST_RESPONSE`_.

    Args:
        ci: The Call ID associated with this operation.
        mi: The host method identifier.
        mr: The return value of the method.
        me: Exception thrown by a host method invocation.

    .. _MS-PSRP 2.2.2.28 PIPELINE_HOST_RESPONSE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d4298dce-ee0d-417d-a73a-b4ad26524e3b
    """
    PSObject = PSObjectMetaPSRP(psrp_message_type=0x00041101)


class ConnectRunspacePool(PSObject, metaclass=_PSMetaTypePSRP):
    """CONNECT_RUNSPACEPOOL Message.

    Connect to a RunspacePool. Message is defined in
    `MS-PSRP 2.2.2.29 CONNECT_RUNSPACEPOOL`_.

    Note:
        This message is only used in ProtocolVersion>=2.2 (PowerShell v3.0+).

    Args:
        MinRunspaces: Minimum number of runspaces in the Runspace Pool.
        MaxRunspaces: Maximum number of runspaces in the RUnspace Pool.

    .. _MS-PSRP 2.2.2.29 CONNECT_RUNSPACEPOOL:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/9192146c-81b5-4abd-9b20-a56df272b95e
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x00010008,
        extended_properties=[
            PSNoteProperty('MinRunspaces', mandatory=True, ps_type=PSInt),
            PSNoteProperty('MaxRunspaces', mandatory=True, ps_type=PSInt),
        ],
    )


class RunspacePoolInitData(PSObject, metaclass=_PSMetaTypePSRP):
    """RUNSPACEPOOL_INIT_DATA Message.

    RunspacePool initialization data. Message is defined in
    `MS-PSRP 2.2.2.30 RUNSPACEPOOL_INIT_DATA`_.

    Note:
        This message is only used in ProtocolVersion>=2.2 (PowerShell v3.0+).

    Args:
        MinRunspaces: Minimum number of runspaces in the Runspace Pool.
        MaxRunspaces: Maximum number of runspaces in the RUnspace Pool.

    .. _MS-PSRP 2.2.2.30 RUNSPACEPOOL_INIT_DATA:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ee0ce0cb-2523-4d43-b8e8-049bb89112ad
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x0002100B,
        extended_properties=[
            PSNoteProperty('MinRunspaces', mandatory=True, ps_type=PSInt),
            PSNoteProperty('MaxRunspaces', mandatory=True, ps_type=PSInt),
        ],
    )


class ResetRunspaceState(PSObject, metaclass=_PSMetaTypePSRP):
    """RESET_RUNSPACE_STATE Message.

    Reset RunspacePool Runspace state. Message is defined in
    `MS-PSRP 2.2.2.31 RESET_RUNSPACE_STATE`_.

    Note:
        This message is only used in ProtocolVersion>=2.3 (PowerShell v5.1+).

    Args:
        ci: The Call ID associated with this operation.

    .. _MS-PSRP 2.2.2.31 RESET_RUNSPACE_STATE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/dc353f4b-c2e1-4172-a6ea-f72d7ef7c6bd
    """
    PSObject = PSObjectMetaPSRP(
        psrp_message_type=0x0002100C,
        extended_properties=[
            PSNoteProperty('ci', mandatory=True, ps_type=PSInt64),
        ],
    )


# This enum is dynamically built based on the registered PSObject with the psrp_message_type info
PSRPMessageType = enum.Enum('PSRPMessageType', {c.__name__: i for i, c in TypeRegistry().psrp_registry.items()},
                            module=__name__)
"""PSRP Mesage types.

The PowerShell Remoting Protocol message types identifiers. Each value
corresponds to a PSRP message type and the unique identifier for that type.
"""
