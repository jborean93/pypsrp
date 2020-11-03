# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Defines the PSRP/.NET Complex Types.

This file contains the PSRP/.NET Complex Type class definitions. A complex type is pretty much anything that isn't a
primitive type as known to the protocol. Most of the types defined here are defined in
`MS-PSRP 2.2.3 Other Object Types`_ but some values are also just other .NET objects that are used in the PSRP
protocol. Some types are a PSRP specific representation of an actual .NET type but with a few minor differences. These
types are prefixed with `PSRP` to differentiate between the PSRP specific ones and the actual .NET types.

.. MS-PSRP 2.2.3 Other Object Types:
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e41c4a38-a821-424b-bc1c-89f8478c39ae
"""

import typing

from .primitive_types import (
    PSBool,
    PSChar,
    PSInt,
    PSInt64,
    PSSecureString,
    PSString,
    PSVersion,
)

from .ps_base import (
    add_note_property,
    PSAliasProperty,
    PSDictBase,
    PSEnumBase,
    PSFlagBase,
    PSGenericBase,
    PSListBase,
    PSNoteProperty,
    PSObject,
    PSObjectMeta,
    PSObjectMetaGeneric,
    PSObjectMetaEnum,
    PSQueueBase,
    PSStackBase,
)


class PSCustomObject(PSObject):
    """PSCustomObject

    This is a PSCustomObject that can be created with an arbitrary amount of extended properties. It is designed to
    replicate the `[PSCustomObject]@{}` syntax that is used in PowerShell.

    Examples:
        >>> obj = PSCustomObject(Property='Value')
        >>> print(obj.Property)
        abc
    """
    PSObject = PSObjectMeta(
        type_names=['System.Management.Automation.PSCustomObject', 'System.Object'],
    )

    def __init__(self, **kwargs):
        for prop_name, prop_value in kwargs.items():
            # Special use case with [PSCustomObject]@{PSTypeName = 'TypeName'} in PowerShell where the value is
            # added to the top of the objects type names.
            if prop_name == 'PSTypeName':
                self.PSObject.type_names.insert(0, prop_value)

            else:
                self.PSObject.extended_properties.append(PSNoteProperty(prop_name, value=prop_value))


class PSStack(PSStackBase):
    """The Stack complex type.

    This is the stack complex type which represents the following types:

        Python: list
        Native Serialization: no
        PSRP: `[MS-PSRP] 2.2.5.2.6.1 Stack`_
        .NET: `System.Collections.Stack`_

    A stack is a last-in, first-out setup but Python does not have a native stack type so this just uses a list.

    .. [MS-PSRP] 2.2.5.2.6.1 Stack
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e9cf648e-38fe-42ba-9ca3-d89a9e0a856a

    .. System.Collections.Stack:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.stack?view=net-5.0
    """
    PSObject = PSObjectMeta(['System.Collections.Stack', 'System.Object'])


class PSQueue(PSQueueBase):
    """The Queue complex type.

    This is the queue complex type which represents the following types:

        Python: queue.Queue
        Native Serialization: yes
        PSRP: `[MS-PSRP] 2.2.5.2.6.2 Queue`_
        .NET: `System.Collections.Queue`_

    .. [MS-PSRP] 2.2.5.2.6.2 Queue
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ade9f023-ac30-4b7e-be17-900c02a6f837

    .. System.Collections.Queue:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.queue?view=net-5.0
    """
    PSObject = PSObjectMeta(['System.Collections.Queue', 'System.Object'])


class PSList(PSListBase):
    """The List complex type.

    This is the queue complex type which represents the following types:

        Python: list
        Native Serialization: yes
        PSRP: `[MS-PSRP] 2.2.5.2.6.3 List`_
        .NET: `System.Collections.ArrayList`_

    .. [MS-PSRP] 2.2.5.2.6.3 List
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/f4bdb166-cefc-4d49-848c-7d08680ae0a7

    .. System.Collections.ArrayList:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.arraylist?view=net-5.0
    """
    # Would prefer an Generic.List<T> but regardless of the type a list is always deserialized by PowerShell as an
    # ArrayList so just do that here.
    PSObject = PSObjectMeta(['System.Collections.ArrayList', 'System.Object'])


class PSGenericList(PSGenericBase, PSListBase):
    """A generic types list type.

    This is a generic type list type that can be used to create a `System.Collections.Generic.List<T>`_ type. Any
    operation that adds a new element to this list will be automatically casted to the type specified when the instance
    was initialised.

    ..Note:
        While the CLIXML will contain the proper type information, when PowerShell deserializes this object it will
        become an ArrayList as represented by `:class:PSList`. This is a limitation of PowerShell Remoting and not
        something done by pypsrp.

    Examples:
        >>> obj = PSGenericList[PSInt](['1', 2, 3])

    .. System.Collections.Generic.List<T>:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.generic.list-1?view=net-5.0
    """
    PSObject = PSObjectMetaGeneric(
        type_names=[
            'System.Collections.Generic.List',
            'System.Object',
        ],
        required_types=1,
    )

    def __init__(self, seq=(), *args, **kwargs):
        seq = [self.PSObject.generic_types[0](e) for e in seq]
        super().__init__(seq, *args, **kwargs)

    def __setitem__(self, key, value):
        expected_type = self.PSObject.generic_types[0]
        if isinstance(key, int):
            value = expected_type(value)

        elif isinstance(key, slice):
            value = [expected_type(e) for e in value]

        return super().__setitem__(key, value)

    def append(self, value):
        value = self.PSObject.generic_types[0](value)
        return super().append(value)

    def extend(self, iterable):
        iterable = [self.PSObject.generic_types[0](e) for e in iterable]
        return super().extend(iterable)

    def insert(self, i, value):
        value = self.PSObject.generic_types[0](value)
        return super().insert(i, value)


class PSDict(PSDictBase):
    """The Dictionary complex type.

    This is the dictionary complex type which represents the following types:

        Python: dict
        Native Serialization: yes
        PSRP: `[MS-PSRP] 2.2.5.2.6.4 Dictionaries`_
        .NET: `System.Collections.Hashtable`_

    .. [MS-PSRP] 2.2.5.2.6.4 Dictionaries
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c4e000a2-21d8-46c0-a71b-0051365d8273

    .. System.Collections.Hashtable:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.hashtable?view=net-5.0
    """
    PSObject = PSObjectMeta(['System.Collections.Hashtable', 'System.Object'])


class ConsoleColor(PSEnumBase, PSInt):
    """Python class for System.ConsoleColor

    This is an auto-generated Python class for the `System.ConsoleColor`_ .NET class. This is also documented under
    `[MS-PSRP] 2.2.3.3 Color`_ but in the `:class:HostInfo` default data format.

    .. System.ConsoleColor:
        https://docs.microsoft.com/en-us/dotnet/api/system.consolecolor?view=net-5.0

    .. [MS-PSRP] 2.2.3.3 Color:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d7edefec-41b1-465d-bc07-2a8ec9d727a1
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.ConsoleColor',
        ],
    )
    Black = 0
    DarkBlue = 1
    DarkGreen = 2
    DarkCyan = 3
    DarkRed = 4
    DarkMagenta = 5
    DarkYellow = 6
    Gray = 7
    DarkGray = 8
    Blue = 9
    Green = 10
    Cyan = 11
    Red = 12
    Magenta = 13
    Yellow = 14
    White = 15


class ProgressRecordType(PSEnumBase, PSInt):
    """Python class for System.Management.Automation.ProgressRecordType

    This is an auto-generated Python class for the `System.Management.Automation.ProgressRecordType`_ .NET class.

    .. System.Management.Automation.ProgressRecordType:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.progressrecordtype
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.ProgressRecordType',
        ],
    )
    Processing = 0
    Completed = 1


class PSCredentialTypes(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.PSCredentialTypes

    This is an auto-generated Python class for the `System.Management.Automation.PSCredentialTypes`_ .NET class.

    .. System.Management.Automation.PSCredentialTypes:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredentialtypes
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.PSCredentialTypes',
        ]
    )
    Generic = 1
    Domain = 2
    Default = Generic | Domain


class PSCredentialUIOptions(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.PSCredentialUIOptions

    This is an auto-generated Python class for the `System.Management.Automation.PSCredentialUIOptions`_ .NET class.

    .. System.Management.Automation.PSCredentialUIOptions:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredentialuioptions
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.PSCredentialUIOptions',
        ]
    )
    none = 0
    ValidateUserNameSyntax = 1
    AlwaysPrompt = 2
    ReadOnlyUsername = 3
    Default = ValidateUserNameSyntax


class SessionStateEntryVisibility(PSEnumBase, PSInt):
    """Python class for System.Management.Automation.SessionStateEntryVisibility

    This is an auto-generated Python class for the `System.Management.Automation.SessionStateEntryVisibility`_ .NET
    class.

    .. System.Management.Automation.SessionStateEntryVisibility:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.sessionstateentryvisibility
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.SessionStateEntryVisibility',
        ],
    )
    Public = 0
    Private = 1


class RunspacePoolState(PSEnumBase, PSInt):
    """RunspacePoolState

    This is the enum used for setting the state for the RunspacePool. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.4 RunspacePoolState`_ and while it shares the same name as the .NET type
    `System.Management.Automation.Runspaces.RunspacePoolState`_ it has a few values that do not match. The .NET values
    are favoured here and any ones that are in the PSRP docs and not in the enum are added manually.t reflect the same
    values.

    .. [MS-PSRP] 2.2.3.4 RunspacePoolState
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/b05495bc-a9b2-4794-9f43-4bf1f3633900

    .. System.Management.Automation.Runspaces.RunspacePoolState:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.runspacepoolstate
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.Runspaces.RunspacePoolState',
        ],
    )
    BeforeOpen = 0
    Opening = 1
    Opened = 2
    Closed = 3
    Closing = 4
    Broken = 5
    Disconnecting = 6
    Disconnected = 7  # 9 in MS-PSRP
    Connecting = 8
    # Referenced as 6 and 7 in MS-PSRP but are internal only so just use a random value
    NegotiationSent = 100
    NegotiationSucceeded = 101


class PSInvocationState(PSEnumBase, PSInt):
    """PSInvocationState

    This is the enum used for setting the state for the RunspacePool. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.5 PSInvocationState`_ and while it shares the same name as the .NET type `RunspacePoolState` it
    does not reflect the same values. It corresponds to the internal class
    `System.Management.Automation.PSInvocationState`_.

    .. [MS-PSRP] 2.2.3.5 PSInvocationState
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/acaa253a-29be-45fd-911c-6715515a28b9

    .. System.Management.Automation.PSInvocationState:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.psinvocationstate
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.PSInvocationState',
        ]
    )
    NotStarted = 0
    Running = 1
    Stopping = 2
    Stopped = 3
    Completed = 4
    Failed = 5
    Disconnected = 6


class PSThreadOptions(PSEnumBase, PSInt):
    """Python class for System.Management.Automation.Runspaces.PSThreadOptions

    This is an auto-generated Python class for the `System.Management.Automation.Runspaces.PSThreadOptions`_ .NET
    class. It is documented in PSRP under `[MS-PSRP] 2.2.3.6 PSThreadOptions`_.

    .. [MS-PSRP] 2.2.3.6 PSThreadOptions:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/bfc63adb-d6f1-4ccc-9bd8-73de6cc78dda

    .. System.Management.Automation.Runspaces.PSThreadOptions:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.psthreadoptions
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.Runspaces.PSThreadOptions',
        ],
    )
    Default = 0
    UseNewThread = 1
    ReuseThread = 2
    UseCurrentThread = 3


class ApartmentState(PSEnumBase, PSInt):
    """Python class for System.Management.Automation.Runspaces.ApartmentState

    This is an auto-generated Python class for the `System.Threading.ApartmentState`_ .NET class. It is documented in
    PSRP under `[MS-PSRP] 2.2.3.7 ApartmentState`_.

    .. [MS-PSRP] 2.2.3.7 ApartmentState:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/6845133d-7503-450d-a74e-388cdd3b2386

    .. System.Threading.ApartmentState:
        https://docs.microsoft.com/en-us/dotnet/api/system.threading.apartmentstate?view=net-5.0
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Threading.ApartmentState',
        ],
    )
    STA = 0
    MTA = 1
    Unknown = 2


class RemoteStreamOptions(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.RemoteStreamOptions

    This is an auto-generated Python class for the `System.Management.Automation.RemoteStreamOptions`_ .NET class. It
    is documented in PSRP under `[MS-PSRP] 2.2.3.8 RemoteStreamOptions`_.

    .. [MS-PSRP] 2.2.3.8 RemoteStreamOptions:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4941e59c-ce01-4549-8eb5-372b8eb6dd12

    .. System.Management.Automation.RemoteStreamOptions:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.remotestreamoptions
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.RemoteStreamOptions',
        ],
    )
    none = 0
    AddInvocationInfoToErrorRecord = 1
    AddInvocationInfoToWarningRecord = 2
    AddInvocationInfoToDebugRecord = 4
    AddInvocationInfoToVerboseRecord = 8
    AddInvocationInfo = 15


class ErrorCategory(PSEnumBase, PSInt):
    """Python class for System.Management.Automation.ErrorCategory

    This is an auto-generated Python class for the `System.Management.Automation.ErrorCategory`_ .NET class. It is
    documented in PSRP under `[MS-PSRP] 2.2.3.9 ErrorCategory`_.
    
    .. [MS-PSRP] 2.2.3.9 ErrorCategory:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ae7d6061-15c8-4184-a05e-1033dbb7228b

    .. System.Management.Automation.ErrorCategory:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.errorcategory
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.ErrorCategory',
        ],
    )
    NotSpecified = 0
    OpenError = 1
    CloseError = 2
    DeviceError = 3
    DeadlockDetected = 4
    InvalidArgument = 5
    InvalidData = 6
    InvalidOperation = 7
    InvalidResult = 8
    InvalidType = 9
    MetadataError = 10
    NotImplemented = 11
    NotInstalled = 12
    ObjectNotFound = 13
    OperationStopped = 14
    OperationTimeout = 15
    SyntaxError = 16
    ParserError = 17
    PermissionDenied = 18
    ResourceBusy = 19
    ResourceExists = 20
    ResourceUnavailable = 21
    ReadError = 22
    WriteError = 23
    FromStdErr = 24
    SecurityError = 25
    ProtocolError = 26
    ConnectionError = 27
    AuthenticationError = 28
    LimitsExceeded = 29
    QuotaExceeded = 30
    NotEnabled = 31


class HostMethodIdentifier(PSEnumBase, PSInt):
    """Host Method Identifier.

    This is an enum class for the System.Management.Automation.Remoting.RemoteHostMethodId .NET class. This is
    documented in `[MS-PSRP] 2.2.3.17 Host Method Identifier`_.

    .. [MS-PSRP] 2.2.3.17 Host Method Identifier:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ddd2a4d1-797d-4d73-8372-7a77a62fb204
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.Remoting.RemoteHostMethodId'
        ],
    )
    GetName = 1
    GetVersion = 2
    GetInstanceId = 3
    GetCurrentCulture = 4
    GetCurrentUICulture = 5
    SetShouldExit = 6
    EnterNestedPrompt = 7
    ExitNestedPrompt = 8
    NotifyBeginApplication = 9
    NotifyEndApplication = 10
    ReadLine = 11
    ReadLineAsSecureString = 12
    Write1 = 13
    Write2 = 14
    WriteLine1 = 15
    WriteLine2 = 16
    WriteLine3 = 17
    WriteErrorLine = 18
    WriteDebugLine = 19
    WriteProgress = 20
    WriteVerboseLine = 21
    WriteWarningLine = 22
    Prompt = 23
    PromptForCredential1 = 24
    PromptForCredential2 = 25
    PromptForChoice = 26
    GetForegroundColor = 27
    SetForegroundColor = 28
    GetBackgroundColor = 29
    SetBackgroundColor = 30
    GetCursorPosition = 31
    SetCursorPosition = 32
    GetWindowPosition = 33
    SetWindowPosition = 34
    GetCursorSize = 35
    SetCursorSize = 36
    GetBufferSize = 37
    SetBufferSize = 38
    GetWindowSize = 39
    SetWindowSize = 40
    GetWindowTitle = 41
    SetWindowTitle = 42
    GetMaxWindowSize = 43
    GetMaxPhysicalWindowSize = 44
    GetKeyAvailable = 45
    ReadKey = 46
    FlushInputBuffer = 47
    SetBufferContents1 = 48
    SetBufferContents2 = 49
    GetBufferContents = 50
    ScrollBufferContents = 51
    PushRunspace = 52
    PopRunspace = 53
    GetIsRunspacePushed = 54
    GetRunspace = 55
    PromptForChoiceMultipleSelection = 56


class CommandTypes(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.CommandTypes

    This is an auto-generated Python class for the `System.Management.Automation.CommandTypes`_ .NET class. This is
    also referenced in `[MS-PSRP] 2.2.3.19 CommandType`_.

    .. [MS-PSRP] 2.2.3.19 CommandType:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/a038c5c9-a220-4064-aa78-ed9cf5a2893c

    .. System.Management.Automation.CommandTypes:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.commandtypes
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.CommandTypes',
        ],
    )
    Alias = 1
    Function = 2
    Filter = 4
    Cmdlet = 8
    ExternalScript = 16
    Application = 32
    Script = 64
    Configuration = 256
    All = 383


class ControlKeyStates(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.Host.ControlKeyStates

    This is an auto-generated Python class for the `System.Management.Automation.Host.ControlKeyStates`_ .NET class.
    This is also referenced in `[MS-PSRP] 2.2.3.27 ControlKeyStates`_.

    .. [MS-PSRP] 2.2.3.27 ControlKeyStates:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/bd7241a2-4ba0-4db1-a2b3-77ea1a8a4cbf

    .. System.Management.Automation.Host.ControlKeyStates:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.controlkeystates
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.Host.ControlKeyStates',
        ],
    )
    RightAltPressed = 1
    LeftAltPressed = 2
    RightCtrlPressed = 4
    LeftCtrlPressed = 8
    ShiftPressed = 16
    NumLockOn = 32
    ScrollLockOn = 64
    CapsLockOn = 128
    EnhancedKey = 256


class BufferCellType(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.Host.BufferCellType

    Defines three types of BufferCells.
    This is an auto-generated Python class for the `System.Management.Automation.Host.BufferCellType`_ .NET class.
    This is also referenced in `[MS-PSRP] 2.2.3.29 BufferCellType`_.

    .. [MS-PSRP] 2.2.3.29 BufferCellType:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/99938ede-6d84-422e-b75d-ace93ea85ea2

    .. System.Management.Automation.Host.BufferCellType:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.buffercelltype
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.Host.ControlKeyStates',
        ],
    )
    Complete = 0
    Leading = 1
    Trailing = 2


class CommandOrigin(PSEnumBase, PSInt):
    """Python class for System.Management.Automation.CommandOrigin

    This is an auto-generated Python class for the `System.Management.Automation.CommandOrigin`_ .NET class. It is
    documented in PSRP under `[MS-PSRP] 2.2.3.30 CommandOrigin`_.

    .. [MS-PSRP] 2.2.3.30 CommandOrigin:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/6c35a5de-d063-4097-ace5-002a0c5e452d

    .. System.Management.Automation.CommandOrigin:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.commandorigin
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.CommandOrigin',
        ],
    )
    Runspace = 0
    Internal = 1


class PipelineResultTypes(PSFlagBase, PSInt):
    """Python class for System.Management.Automation.Runspaces.PipelineResultTypes

    This is an auto-generated Python class for the `System.Management.Automation.Runspaces.PipelineResultTypes`_ .NET
    class. It is documented in PSRP under `[MS-PSRP] 2.2.3.31 PipelineResultTypes`_. .NET and MS-PSRP have separate
    values but .NET is used as it is the correct source. Technically the values are not designed as flags but there are
    some older APIs that combine Output | Error together.

    .. [MS-PSRP] 2.2.3.31 PipelineResultTypes:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/efdce0ba-531e-4904-9cab-b65c476c649a

    .. System.Management.Automation.Runspaces.PipelineResultTypes:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipelineresulttypes
    """
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Management.Automation.Runspaces.PipelineResultTypes',
        ],
    )
    none = 0
    Output = 1
    Error = 2
    Warning = 3
    Verbose = 4
    Debug = 5
    Information = 6
    All = 7
    Null = 8


class Coordinates(PSObject):
    """Coordinates

    Represents an x,y coordinate pair. This is the actual .NET type `System.Management.Automation.Host.Coordinates`_.
    It is documented under `[MS-PSRP 2.2.3.1 Coordinates`_ but the PSRP documentation represents how this value is
    serialized under `:class:HostInfo`.

    Args:
        X: X coordinate (0 is the leftmost column).
        Y: Y coordinate (0 is the topmost row).

    .. [MS-PSRP] 2.2.3.1 Coordinates:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/05db8994-ec5c-485c-9e91-3a398e461d38

    .. System.Management.Automation.Host.Coordinates:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.coordinates
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.Host.Coordinates',
            'System.ValueType',
            'System.Object',
        ],
        adapted_properties=[
            PSNoteProperty('X', mandatory=True, ps_type=PSInt),
            PSNoteProperty('Y', mandatory=True, ps_type=PSInt),
        ],
    )


class Size(PSObject):
    """Size

    Represents a width and height pair. This is the actual .NET type `System.Management.Automation.Host.Size`_.
    It is documented under `[MS-PSRP 2.2.3.2 Size`_ but the PSRP documentation represents how this value is
    serialized under `:class:HostInfo`.

    Args:
        Width: The width of an area.
        Height: The height of an area.

    .. [MS-PSRP] 2.2.3.2 Size:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/98cd950f-cc12-4ab4-955d-c389e3089856

    .. System.Management.Automation.Host.Size:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.size
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.Host.Size',
            'System.ValueType',
            'System.Object',
        ],
        adapted_properties=[
            PSNoteProperty('Width', mandatory=True, ps_type=PSInt),
            PSNoteProperty('Height', mandatory=True, ps_type=PSInt),
        ],
    )


class PSRPCommandParameter(PSObject):
    """Command Parameter

    Represents a parameter of a command implemented by a higher layer on the server. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.13 Command Parameter`_. This is not the same as the actual
    `System.Management.Automation.Runspaces.CommandParameter`_ .NET type but rather a custom format used by PSRP.

    Args:
        N: The name of the parameter, can be `None` to specify a position argument.
        V: The value of the parameter.

    .. [MS-PSRP] 2.2.3.13 Command Parameter:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ccdb5b92-81d8-402a-9730-6a0270001e63

    .. System.Management.Automation.Runspaces.CommandParameter:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandparameter
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('N', ps_type=PSString),
            PSNoteProperty('V'),
        ],
    )


class PSRPCommand(PSObject):
    """Command

    Represents a command in a pipeline. It is documented in PSRP under `[MS-PSRP 2.2.3.12 Command`_. This is not the
    same as the actual `System.Management.Automation.Runspaces.Command`_ .NET type but rather a custom format used by
    PSRP.

    ..Note:
        `MergeError`, `MergeWarning`, `MergeVerbose`, `MergeDebug`, or `MergeInformation` only support certain
        PowerShell versions. They may be ignored if set but the `ProtocolVersion` does not support them.

    ..Note:
        MergePreviousResults only allows a value of `none` or `Output | Error` where the previously unclaimed error
        records from the commands in the same statement will be passed into the current command's input pipeline.

    Args:
        Cmd: The name of the command or text of script to execute.
        Args: List of `:class:CommandParameter` objects to invoke with the `Cmd`.
        IsScript: Indicate to the higher layer whether the command to execute is a script.
        UseLocalScope: Indicate to the higher layer to use the local or global scope when invoking the `Cmd`.
        MergeMyResult: The stream to merge into `MergeToResult`. Only supports `none` or `Error` and is only used in
            protocol 2.1 (PowerShell v2).
        MergeToResult: The stream that `MergeMyResult` is merged into. Only supports `none` or `Output` and is only
            used in protocol 2.1 (PowerShell v2).
        MergePreviousResults: Whether to capture any previously unclaimed objects. PowerShell only supports `none` or
            `Output | Error` and no other combination.
        MergeError: The stream to merge the error stream into. Only supports `none` or `Output` and is used by
            protocol 2.2+ (PowerShell v3+).
        MergeWarning: The stream to merge the warning stream into. Only supports `none` or `Output` and is used by
            protocol 2.2+ (PowerShell v3+).
        MergeVerbose: The stream to merge the verbose stream into. Only supports `none` or `Output` and is used by
            protocol 2.2+ (PowerShell v3+).
        MergeDebug: The stream to merge the debug stream into. Only supports `none` or `Output` and is used by protocol
            2.2+ (PowerShell v3+).
        MergeInformation: The stream to merge the information stream into. Only supports `none` or `Output` and is used
            by protocol 2.3+ (PowerShell v5+).

    TODO: Make sure we test MergePreviousResults with
    The error records aren't pipelined to subsequent commands but are in an unclaimed state for that statement. By
    setting `MergePreviousResults = 'Output, Error'` to a command you are telling it to claim the outstanding error
    records as input (from the incoming Output stream). By default 'Out-Default' sets this to claim any remaining
    error records and output that accordingly.

        $res = $null
        $ps = $null
        try {
            $ps = [powershell]::Create().AddScript('Write-Error test')
            $cmd = [Management.Automation.Runspaces.Command]::new('process { $_ }', $true)

            # Comment out this line and the error doesn't make it to the upstream command.
            $cmd.MergeUnclaimedPreviousCommandResults = 'Error, Output'
            $null = $ps.Commands.AddCommand($cmd)
            $res = $ps.Invoke()
        } finally {
            $ps.Dispose()
        }

        # yield
        $res

    .. [MS-PSRP] 2.2.3.12 Command:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/0cf18d22-b977-4ad5-9ce6-59fef1035a29

    .. System.Management.Automation.Runspaces.Command:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.command
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('Cmd', ps_type=PSString),
            PSNoteProperty('Args', ps_type=PSGenericList[PSRPCommandParameter]),
            PSNoteProperty('IsScript', value=False, ps_type=PSBool),
            PSNoteProperty('UseLocalScope', ps_type=PSBool),
            PSNoteProperty('MergeMyResult', value=PipelineResultTypes.none, ps_type=PipelineResultTypes),
            PSNoteProperty('MergeToResult', value=PipelineResultTypes.none, ps_type=PipelineResultTypes),
            PSNoteProperty('MergePreviousResults', value=PipelineResultTypes.none, ps_type=PipelineResultTypes),
            # ProtocolVersion>=2.2 (ps v3+)
            PSNoteProperty('MergeError', optional=True, ps_type=PipelineResultTypes),
            PSNoteProperty('MergeWarning', optional=True, ps_type=PipelineResultTypes),
            PSNoteProperty('MergeVerbose', optional=True, ps_type=PipelineResultTypes),
            PSNoteProperty('MergeDebug', optional=True, ps_type=PipelineResultTypes),
            # ProtocolVersion>=2.3 (ps v5+)
            PSNoteProperty('MergeInformation', optional=True, ps_type=PipelineResultTypes),
        ],
    )


class PSRPExtraCmds(PSObject):
    """PSRP Extra Cmds

    This is used by `:class:PSRPPipeline` in the `ExtraCmds` property to serialize multiple statements. This isn't
    documented in MS-PSRP or the .NET docs but the behaviour seen when looking at PSRP packets over the wire.

    Args:
        Cmds: A list of `:class:PSRPCommand` objects.
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('Cmds', mandatory=True, ps_type=PSGenericList[PSRPCommand]),
        ],
    )


class PSRPPipeline(PSObject):
    """Pipeline

    The data type that represents a pipeline to be executed. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.11 Pipeline`_. This is not the same as the actual
    `System.Management.Automation.Runspaces.Pipeline`_ .NET type but rather a custom format used by PSRP.

    Args:
        Cmds: List of `:class:PSRPCommand` to run in a single statement for the pipeline.
        ExtraCmds: List of `:class:PSRPExtraCmds` object that contains other statements to run for the pipeline.
        IsNested: Indicates to the higher layer that this is a nested pipeline.
        History: The history information of the pipeline.
        RedirectShellErrorOutputPipe: Redirects the global error output pipe to the commands error output pipe.

    .. [MS-PSRP] 2.2.3.11 Pipeline:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/82a8d1c6-4560-4e68-bfd0-a63c36d6a199

    .. System.Management.Automation.Runspaces.Pipeline:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('Cmds', ps_type=PSGenericList[PSRPCommand]),
            PSNoteProperty('ExtraCmds', optional=True, ps_type=PSGenericList[PSRPExtraCmds]),
            PSNoteProperty('IsNested', ps_type=PSBool),
            PSNoteProperty('History', ps_type=PSString),
            PSNoteProperty('RedirectShellErrorOutputPipe', ps_type=PSBool),
        ],
    )


class HostDefaultData(PSObject):
    """HostInfo default data.

    This defines the default data for a PSHost when creating a RunspacePool or Pipeline. This does not represent an
    actual .NET type but is an internal object representation used by PSRP itself. This type represents the
    `hostDefaultData` property documented at `[MS-PSRP] 2.2.3.14 HostInfo`_.

    Args:
        foreground_color: Color of the character on the screen buffer.
        background_color: Color behind characters on the screen buffer.
        cursor_position: Cursor position in the screen buffer.
        window_position: Position of the view window relative to the screen buffer.
        cursor_size: Cursor size as a percentage 0..100.
        buffer_size: Current size of the screen buffer, measured in character cells.
        window_size: Current view window size, measured in character cells.
        max_window_size:  Size of the largest window position for the current buffer.
        max_physical_window_size: Largest window possible ignoring the current buffer dimensions.
        window_title: The titlebar text of the current view window.

    .. [MS-PSRP] 2.2.3.14 HostInfo:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/510fd8f3-e3ac-45b4-b622-0ad5508a5ac6
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSAliasProperty('data', '_default_data'),
        ],
    )

    def __init__(
            self,
            foreground_color: ConsoleColor,
            background_color: ConsoleColor,
            cursor_position: Coordinates,
            window_position: Coordinates,
            cursor_size: typing.Tuple[PSInt, int],
            buffer_size: Size,
            window_size: Size,
            max_window_size: Size,
            max_physical_window_size: Size,
            window_title: typing.Tuple[PSString, str],
    ):
        super().__init__()

        self.foreground_color = foreground_color
        self.background_color = background_color
        self.cursor_position = cursor_position
        self.window_position = window_position
        self.cursor_size = cursor_size
        self.buffer_size = buffer_size
        self.window_size = window_size
        self.max_window_size = max_window_size
        self.max_physical_window_size = max_physical_window_size
        self.window_title = window_title

    @property
    def _default_data(self):
        def dict_value(value, value_type):
            dict_obj = PSObject()
            add_note_property(dict_obj, 'T', value_type, ps_type=PSString)
            add_note_property(dict_obj, 'V', value)
            return dict_obj

        def color(value: ConsoleColor):
            return dict_value(PSInt(value), value.PSObject.type_names[0])

        def coordinates(value: Coordinates):
            raw = PSObject()
            add_note_property(raw, 'x', value.X, ps_type=PSInt)
            add_note_property(raw, 'y', value.Y, ps_type=PSInt)
            return dict_value(raw, value.PSObject.type_names[0])

        def size(value: Size):
            raw = PSObject()
            add_note_property(raw, 'width', value.Width, ps_type=PSInt)
            add_note_property(raw, 'height', value.Height, ps_type=PSInt)
            return dict_value(raw, value.PSObject.type_names[0])

        a = ''
        return {
            0: color(self.foreground_color),
            1: color(self.background_color),
            2: coordinates(self.cursor_position),
            3: coordinates(self.window_position),
            4: dict_value(self.cursor_size, PSInt.PSObject.type_names[0]),
            5: size(self.buffer_size),
            6: size(self.window_size),
            7: size(self.max_window_size),
            8: size(self.max_physical_window_size),
            9: dict_value(self.window_title, PSString.PSObject.type_names[0]),
        }

    @staticmethod
    def from_psobject(
            data: PSObject,
    ) -> 'HostDefaultData':
        """ Convert the raw HostDefaultData PSObject back to this easier to use object. """
        def coordinates(value) -> Coordinates:
            return Coordinates(X=value.x, Y=value.y)
            
        def size(value) -> Size:
            return Size(Width=value.width, Height=value.height)

        return HostDefaultData(
            foreground_color=data.data[0].V,
            background_color=data.data[1].V,
            cursor_position=coordinates(data.data[2].V),
            window_position=coordinates(data.data[3].V),
            cursor_size=data.data[4].V,
            buffer_size=size(data.data[5].V),
            window_size=size(data.data[6].V),
            max_window_size=size(data.data[7].V),
            max_physical_window_size=size(data.data[8].V),
            window_title=data.data[9].V,
        )


class HostInfo(PSObject):
    """HostInfo

    Defines the PSHost information. Message is defined in `MS-PSRP 2.2.3.14 HostInfo`_.

    Args:
        is_host_null: Whether there is a PSHost (`False`) or not (`True`).
        is_host_ui_null: Whether the PSHost implements the `UI` implementation methods (`False`) or not (`True`).
        is_host_raw_ui_null: Whether the PSHost UI implements the `RawUI` implementation methods (`False`) or not
            (`True`).
        use_runspace_host: When creating a pipeline, set this to `True` to get it to use the associated RunspacePool
            host or not.
        host_default_data: Host default data associated with the PSHost.UI.RawUI implementation. Can be `None` if not
            implemented.

    .. MS-PSRP 2.2.3.13 HostInfo:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/510fd8f3-e3ac-45b4-b622-0ad5508a5ac6
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSAliasProperty('_isHostNull', 'is_host_null', ps_type=PSBool),
            PSAliasProperty('_isHostUINull', 'is_host_ui_null', ps_type=PSBool),
            PSAliasProperty('_isHostRawUINull', 'is_host_raw_ui_null', ps_type=PSBool),
            PSAliasProperty('_useRunspaceHost', 'use_runspace_host', ps_type=PSBool),
            PSAliasProperty('_hostDefaultData', 'host_default_data', optional=True, ps_type=HostDefaultData),
        ],
    )

    def __init__(
            self,
            is_host_null: bool = True,
            is_host_ui_null: bool = True,
            is_host_raw_ui_null: bool = True,
            use_runspace_host: bool = True,
            host_default_data: typing.Optional[HostDefaultData] = None,
    ):
        super().__init__()

        self.is_host_null = is_host_null
        self.is_host_ui_null = is_host_ui_null
        self.is_host_raw_ui_null = is_host_raw_ui_null
        self.use_runspace_host = use_runspace_host
        self.host_default_data = host_default_data
        
    @staticmethod
    def from_psobject(
            value: PSObject,
    ) -> 'HostInfo':
        """ Convert the raw HostInfo PSObject back to this easier to use object. """
        host_data = getattr(value, '_hostDefaultData', None)
        if host_data is not None:
            host_data = HostDefaultData.from_psobject(host_data)

        return HostInfo(
            is_host_null=value._isHostNull,
            is_host_ui_null=value._isHostUINull,
            is_host_raw_ui_null=value._isHostRawUINull,
            use_runspace_host=value._useRunspaceHost,
            host_default_data=host_data,
        )


class PSRPErrorRecord(PSObject):
    """ErrorRecord

    The data type that represents information about an error. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.15 ErrorRecord`_. The invocation specific properties are documented under
    `[MS-PSRP] 2.2.3.15.1 InvocationInfo`_. This is not the same as the actual
    `System.Management.Automation.ErrorRecord`_ .NET type but rather a custom format used by PSRP.

    Args:
        Cmds: List of `:class:PSRPCommand` to run in a single statement for the pipeline.
        ExtraCmds: List of `:class:PSRPExtraCmds` object that contains other statements to run for the pipeline.
        IsNested: Indicates to the higher layer that this is a nested pipeline.
        History: The history information of the pipeline.
        RedirectShellErrorOutputPipe: Redirects the global error output pipe to the commands error output pipe.

    .. [MS-PSRP] 2.2.3.15 ErrorRecord:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/0fe855a7-d13c-44e2-aa88-291e2054ae3a

    .. [MS-PSRP] 2.2.3.15.1 InvocationInfo:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/000363b7-e2f9-4a34-94f5-d540a15aee7b

    .. System.Management.Automation.ErrorRecord:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.errorrecord
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.ErrorRecord',
            'System.Object',
        ],
        extended_properties=[
            PSNoteProperty('Exception', optional=True),
            PSNoteProperty('TargetObject'),
            PSNoteProperty('InvocationInfo'),
            PSNoteProperty('FullyQualifiedErrorId', ps_type=PSString),
            PSNoteProperty('ErrorCategory_Category', ps_type=PSInt),  # This is an ErrorCategory but serialized as Int.
            PSNoteProperty('ErrorCategory_Activity', ps_type=PSString),
            PSNoteProperty('ErrorCategory_Reason', ps_type=PSString),
            PSNoteProperty('ErrorCategory_TargetName', ps_type=PSString),
            PSNoteProperty('ErrorCategory_TargetType', ps_type=PSString),
            PSNoteProperty('ErrorCategory_Message', optional=True, ps_type=PSString),
            PSNoteProperty('ErrorDetails_Message', optional=True, ps_type=PSString),
            PSNoteProperty('ErrorDetails_RecommendedAction', optional=True, ps_type=PSString),
            PSNoteProperty('ErrorDetails_ScriptStackTrace', optional=True, ps_type=PSString),
            PSNoteProperty('SerializeExtendedInfo', value=False, ps_type=PSBool),
            PSNoteProperty('PipelineIterationInfo', optional=True, ps_type=PSGenericList[PSInt]),
            # InvocationInfo-specific Extended Properties
            PSNoteProperty('InvocationInfo_InvocationName', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_BoundParameters', optional=True, ps_type=PSDict),
            PSNoteProperty('InvocationInfo_UnboundArguments', optional=True, ps_type=PSList),
            PSNoteProperty('InvocationInfo_CommandOrigin', optional=True, ps_type=CommandOrigin),
            PSNoteProperty('InvocationInfo_ExpectingInput', optional=True, ps_type=PSBool),
            PSNoteProperty('InvocationInfo_Line', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_OffsetInLine', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_PositionMessage', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_ScriptName', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_ScriptLineNumber', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_HistoryId', optional=True, ps_type=PSInt64),
            PSNoteProperty('InvocationInfo_PipelineLength', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_PipelinePosition', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_PipelineIterationInfo', optional=True, ps_type=PSGenericList[PSInt]),
            PSNoteProperty('InvocationInfo_PSScriptRoot', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_PSCommandPath', optional=True, ps_type=PSString),
        ],
    )


class InformationalRecord(PSObject):
    """InformationalRecord

    InformationalRecord (that is Debug, Warning, or Verbose) is a structure that contains additional information that a
    pipeline can output in addition to the regular data output. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.16 InformationalRecord`_. The invocation specific properties are documented under
    `[MS-PSRP] 2.2.3.15.1 InvocationInfo`_. This also represents the
    `System.Management.Automation.InformationalRecord`_ .NET type.

    .. [MS-PSRP] 2.2.3.16 InformationalRecord:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/97cad2dc-c34a-4db6-bfa1-cbf196853937

    .. [MS-PSRP] 2.2.3.15.1 InvocationInfo:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/000363b7-e2f9-4a34-94f5-d540a15aee7b

    .. System.Management.Automation.InformationalRecord:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.informationalrecord
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.InformationalRecord',
            'System.Object',
        ],
        extended_properties=[
            PSNoteProperty('InformationalRecord_Message', ps_type=PSString),
            PSNoteProperty('InformationalRecord_SerializeInvocationInfo', ps_type=PSBool),
            PSNoteProperty('InformationalRecord_PipelineIterationInfo', ps_type=PSGenericList[PSInt]),
            # InvocationInfo-specific Extended Properties
            PSNoteProperty('InvocationInfo_InvocationName', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_BoundParameters', optional=True, ps_type=PSDict),
            PSNoteProperty('InvocationInfo_UnboundArguments', optional=True, ps_type=PSList),
            PSNoteProperty('InvocationInfo_CommandOrigin', optional=True, ps_type=CommandOrigin),
            PSNoteProperty('InvocationInfo_ExpectingInput', optional=True, ps_type=PSBool),
            PSNoteProperty('InvocationInfo_Line', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_OffsetInLine', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_PositionMessage', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_ScriptName', optional=True, ps_type=PSString),
            PSNoteProperty('InvocationInfo_ScriptLineNumber', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_HistoryId', optional=True, ps_type=PSInt64),
            PSNoteProperty('InvocationInfo_PipelineLength', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_PipelinePosition', optional=True, ps_type=PSInt),
            PSNoteProperty('InvocationInfo_PipelineIterationInfo', optional=True, ps_type=PSGenericList[PSInt]),
        ],
    )


class PSPrimitiveDictionary(PSDict):
    """Primitive Dictionary

    A primitive dictionary represents a dictionary which contains only objects that are primitive types. While Python
    does not place any limitations on the types this object can contain, trying to serialize a PSPrimitiveDictionary
    with complex types to PowerShell will fail. The types that are allowed can be found at
    `[MS-PSRP] 2.2.3.18 Primitive Dictionary`_.

    .. [MS-PSRP] 2.2.3.18 Primitive Dictionary:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/7779aa42-6927-4225-b31c-2771fd869546
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.PSPrimitiveDictionary',
        ],
    )


class CommandMetadataCount(PSObject):
    """CommandMetadataCount

    Special data type used by the command metadata messages. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.21 CommandMetadataCount`_.

    Args:
        Count: The count.

    .. [MS-PSRP] 2.2.3.21 CommandMetadataCount:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4647da0c-18e6-496c-9d9e-c669d40dc1db
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.PSCredential',
        ],
        extended_properties=[
            PSNoteProperty('Count', mandatory=True, ps_type=PSInt),
        ],
    )


class PSCredential(PSObject):
    """PSCredential

    Represents a username and a password. It is documented in PSRP under `[MS-PSRP] 2.2.3.25 PSCredential`_. It also
    represents the `System.Management.Automation.PSCredential`_ .NET type.

    .. Note:
        To be able to serialize this object, the session key exchange must have been run between the client and server.

    Args:
        UserName: The username for the credential.
        Password: The password for the credential.

    .. [MS-PSRP] 2.2.3.25 PSCredential:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/a7c91a93-ee59-4af0-8a67-a9361af9870e

    .. System.Management.Automation.PSCredential:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Management.Automation.PSCredential',
        ],
        adapted_properties=[
            PSNoteProperty('UserName', mandatory=True, ps_type=PSString),
            PSNoteProperty('Password', mandatory=True, ps_type=PSSecureString),
        ],
    )


class PSRPKeyInfo(PSObject):
    """KeyInfo

    Represents a username and a password. It is documented in PSRP under `[MS-PSRP] 2.2.3.26 KeyInfo`_. This is not the
    same as the actual `System.Management.Automation.Host.KeyInfo`_ .NET type but rather a custom format used by PSRP.

    Args:
        virtualKeyCode: A virtual key code that identifies the given key in a device-independent manner.
        character: Character corresponding to the pressed keys.
        controlKeyState: State of the control keys.
        keyDown: True if the event was generated when a key was pressed.

    .. [MS-PSRP] 2.2.3.26 KeyInfo:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/481442e2-5304-4679-b16d-6e53c351339d

    .. System.Management.Automation.Host.KeyInfo:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.keyinfo
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('virtualKeyCode', ps_type=PSInt),
            PSNoteProperty('character', ps_type=PSChar),
            PSNoteProperty('controlKeyState', ps_type=PSInt),  # ControlKeyStates as integer.
            PSNoteProperty('keyDown', ps_type=PSBool),
        ],
    )


class PSRPBufferCell(PSObject):
    """BufferCell

    Represents the contents of a cell of a Host's screen buffer. It is documented in PSRP under
    `[MS-PSRP] 2.2.3.28 BufferCell`_. This is not the same as the actual
    `System.Management.Automation.Host.BufferCell`_ .NET type but rather a custom format used by PSRP.

    Args:
        character: Character visible in the cell.
        foregroundColor: Foreground color.
        backgroundColor: Background color.
        bufferCellType: Type of the buffer cell.

    .. [MS-PSRP] 2.2.3.28 BufferCell:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d6270c27-8855-46b6-834c-5a5d188bfe70

    .. System.Management.Automation.Host.BufferCell:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.buffercell
    """
    PSObject = PSObjectMeta(
        type_names=[],
        adapted_properties=[
            PSNoteProperty('character', ps_type=PSChar),
            PSNoteProperty('foregroundColor', ps_type=ConsoleColor),
            PSNoteProperty('backgroundColor', ps_type=ConsoleColor),
            PSNoteProperty('bufferCellType', ps_type=PSInt),  # BufferCellType as integer.
        ],
    )


class PSRPChoiceDescription(PSObject):
    """ChoiceDescription

    Represents a description of a field for use by `PromptForChoice` in `:class:psrp.host.PSHostUI`. It isn't
    documented in MS-PSRP but the properties are based on what has been seen across the wire. This is not the same as
    the actual `System.Management.Automation.Host.ChoiceDescription`_ .NET type but rather a custom format used by
    PSRP.

    Args:
        helpMessage: Help message for the choice.
        label: Short human-presentable to describe and identify the choice.

    .. System.Management.Automation.Host.ChoiceDescription:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.choicedescription
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('helpMessage', ps_type=PSString),
            PSNoteProperty('label', ps_type=PSString),
        ],
    )


class PSRPFieldDescription(PSObject):
    """FieldDescription

    Represents a description of a field for use by `Prompt` in `:class:psrp.host.PSHostUI`. It isn't documented in
    MS-PSRP but the properties are based on what has been seen across the wire. This is not the same as the actual
    `System.Management.Automation.Host.FieldDescription`_ .NET type but rather a custom format used by PSRP.

    Args:
        name:
        label:
        parameterTypeName:
        parameterTypeFullName:
        parameterAssemblyFullName:
        helpMessage:
        isMandatory:
        metadata:
        modifiedByRemotingProtocol:
        isFromRemoteHost:

    .. System.Management.Automation.Host.FieldDescription:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.fielddescription
    """
    PSObject = PSObjectMeta(
        type_names=[],
        extended_properties=[
            PSNoteProperty('name', ps_type=PSString),
            PSNoteProperty('label', ps_type=PSString),
            PSNoteProperty('parameterTypeName', ps_type=PSString),
            PSNoteProperty('parameterTypeFullName', ps_type=PSString),
            PSNoteProperty('parameterAssemblyFullName', ps_type=PSString),
            PSNoteProperty('helpMessage', ps_type=PSString),
            PSNoteProperty('isMandatory', ps_type=PSBool),
            PSNoteProperty('metadata', ps_type=PSList),
            PSNoteProperty('modifiedByRemotingProtocol', ps_type=PSBool),
            PSNoteProperty('isFromRemoteHost', ps_type=PSBool),
        ],
    )


class NETException(PSObject):
    """.NET Exception

    Represents a .NET `System.Exception`_ type. It isn't documented in MS-PSRP but is used when creating an ErrorRecord
    or just as a base of another exception type.

    Args:
        Message: Message that describes the current exception.
        Data: User defined information about the exception.
        HelpLink: A link to the help file associated with this exception.
        HResult: A coded numerical value that is assigned to a specific exception.
        InnerException: Exception instance that caused the current exception.
        Source: Name of the application or the object that causes the error.
        StackTrace: String representation of the immediate frames on the call stack.
        TargetSite: Method that throws the current exception.

    .. System.Exception:
        https://docs.microsoft.com/en-us/dotnet/api/system.exception?view=net-5.0
    """
    PSObject = PSObjectMeta(
        type_names=[
            'System.Exception',
            'System.Object',
        ],
        adapted_properties=[
            PSNoteProperty('Message', mandatory=True, ps_type=PSString),
            PSNoteProperty('Data', ps_type=PSDict),
            PSNoteProperty('HelpLink', ps_type=PSString),
            PSNoteProperty('HResult', ps_type=PSInt),
            PSNoteProperty('InnerException'),
            PSNoteProperty('Source', ps_type=PSString),
            PSNoteProperty('StackTrace', ps_type=PSString),
            PSNoteProperty('TargetSite', ps_type=PSString),
        ],
    )
