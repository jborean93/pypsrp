# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import collections
import datetime
import enum
import getpass
import os
import platform
import struct
import threading
import typing
import uuid

from xml.etree import (
    ElementTree,
)

from .powershell_events import (
    ApplicationPrivateDataEvent,
    ConnectRunspacePoolEvent,
    CreatePipelineEvent,
    DebugRecordEvent,
    EncryptedSessionKeyEvent,
    EndOfPipelineInputEvent,
    ErrorRecordEvent,
    GetAvailableRunspacesEvent,
    GetCommandMetadataEvent,
    InformationRecordEvent,
    InitRunspacePoolEvent,
    PipelineHostCallEvent,
    PipelineHostResponseEvent,
    PipelineInputEvent,
    PipelineOutputEvent,
    PipelineStateEvent,
    ProgressRecordEvent,
    PSRPEvent,
    PublicKeyEvent,
    PublicKeyRequestEvent,
    ResetRunspaceStateEvent,
    RunspaceAvailabilityEvent,
    RunspacePoolHostCallEvent,
    RunspacePoolHostResponseEvent,
    RunspacePoolInitDataEvent,
    RunspacePoolStateEvent,
    SessionCapabilityEvent,
    SetMaxRunspacesEvent,
    SetMinRunspacesEvent,
    UserEventEvent,
    VerboseRecordEvent,
    WarningRecordEvent,
)

from ..dotnet.complex_types import (
    ApartmentState,
    CommandTypes,
    ErrorCategory,
    ErrorCategoryInfo,
    ErrorDetails,
    ErrorRecord,
    HostInfo,
    HostMethodIdentifier,
    InformationalRecord,
    InvocationInfo,
    NETException,
    PipelineResultTypes,
    ProgressRecordType,
    PSCustomObject,
    PSInvocationState,
    PSList,
    PSThreadOptions,
    RemoteStreamOptions,
    RunspacePoolState,
)

from psrp.dotnet.crypto import (
    create_keypair,
    encrypt_session_key,
    decrypt_session_key,
    PSRemotingCrypto,
)

from ..dotnet.primitive_types import (
    PSDateTime,
    PSGuid,
    PSInt,
    PSString,
    PSUInt,
    PSVersion,
)

from ..dotnet.ps_base import (
    add_note_property,
    PSObject,
)

from ..dotnet.psrp_messages import (
    ApplicationPrivateData,
    ConnectRunspacePool,
    CreatePipeline,
    EncryptedSessionKey,
    EndOfPipelineInput,
    GetAvailableRunspaces,
    GetCommandMetadata,
    InformationRecord,
    InitRunspacePool,
    PipelineHostCall,
    PipelineHostResponse,
    PipelineState,
    ProgressRecord,
    PSRPMessageType,
    PublicKey,
    PublicKeyRequest,
    ResetRunspaceState,
    RunspaceAvailability,
    RunspacePoolHostCall,
    RunspacePoolHostResponse,
    RunspacePoolInitData,
    RunspacePoolState as RunspacePoolStateMsg,
    SessionCapability,
    SetMaxRunspaces,
    SetMinRunspaces,
    UserEvent,
)

from ..dotnet.serializer import (
    deserialize,
    serialize,
)

from ..exceptions import (
    InvalidPipelineState,
    InvalidProtocolVersion,
    InvalidRunspacePoolState,
    PSRPError,
)


class StreamType(enum.Enum):
    """PSRP Message stream type.

    The PSRP message stream type that defines the priority of a PSRP message.
    It is up to the connection to interpret these options and convey the
    priority to the peer in the proper fashion.
    """
    default = enum.auto()  #: The default type used for the majority of PSRP messages.
    prompt_response = enum.auto()  #: Used for host call/responses PSRP messages.


class PSRPMessage:
    """PSRP Message in the outgoing queue.

    Represents a PSRP message to send to the peer or a defragmented object from the peer.

    Args:
        message_type: The PSRP message type the fragment is for.
        data: The PSRP message fragment.
        runspace_pool_id: The Runspace Pool ID the message is for.
        pipeline_id: The pipeline the message is targeted towards or `None` to target the RunspacePool.
        object_id: The data fragment object id.
        stream_type: The StreamType associated with the message.
    """
    def __init__(
            self,
            message_type: PSRPMessageType,
            data: bytearray,
            runspace_pool_id: str,
            pipeline_id: typing.Optional[str],
            object_id: int,
            stream_type: StreamType = StreamType.default,
    ):
        self.message_type: PSRPMessageType = message_type
        self.runspace_pool_id = runspace_pool_id
        self.pipeline_id = pipeline_id
        self.object_id = object_id
        self.stream_type = stream_type
        self._data = bytearray(data)
        self._fragment_counter: int = 0

    def __len__(self) -> int:
        return len(self._data)

    @property
    def data(self) -> bytes:
        """ The internal buffer as a byte string. """
        return bytes(self._data)

    @property
    def fragment_counter(
            self,
    ) -> int:
        """ Get the next fragment ID for the message fragments. """
        fragment_id = self._fragment_counter
        self._fragment_counter += 1
        return fragment_id

    def fragment(
            self,
            length: int,
    ) -> bytes:
        """ Create a fragment with a maximum length. """
        data = self._data[:length]
        self._data = self._data[length:]
        fragment_id = self.fragment_counter
        end = len(self) == 0

        return _create_fragment(self.object_id, fragment_id, data, end)


Fragment = collections.namedtuple('Fragment', ['object_id', 'fragment_id', 'start', 'end', 'data'])
Message = collections.namedtuple('Message', ['destination', 'message_type', 'rpid', 'pid', 'data'])
PSRPPayload = collections.namedtuple('PSRPPayload', ['data', 'stream_type', 'pipeline_id'])

_EMPTY_UUID = '00000000-0000-0000-0000-000000000000'

_DEFAULT_CAPABILITY = SessionCapability(
    PSVersion=PSVersion('2.0'),
    protocolversion=PSVersion('2.3'),
    SerializationVersion=PSVersion('1.1.0.1'),
)


def _create_message(
        client: bool,
        message_type: PSRPMessageType,
        data: bytes,
        runspace_pool_id: str,
        pipeline_id: typing.Optional[str] = None,
) -> bytearray:
    """Create a PSRP message.

    Creates a PSRP message that encapsulates a PSRP message object. The message structure is defined in
    `MS-PSRP 2.2.1 PowerShell Remoting Protocol Message`_.

    Args:
        client: The message is from the client (True) or not (False).
        message_type: The type of message specified by `data`.
        data: The serialized PSRP message data.
        runspace_pool_id: The RunspacePool instance ID.
        pipeline_id: The Pipeline instance ID if the message is targeted towards a pipeline.

    .. _MS-PSRP 2.2.1 PowerShell Remoting Protocol Message:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/497ac440-89fb-4cb3-9cc1-3434c1aa74c3
    """
    destination = 0x00000002 if client else 0x00000001
    rpid = uuid.UUID(runspace_pool_id)
    pid = uuid.UUID(pipeline_id or _EMPTY_UUID)

    return bytearray(b''.join([
        struct.pack('<i', destination),
        struct.pack('<I', message_type.value),
        # .NET serializes uuids/guids in bytes in the little endian form.
        rpid.bytes_le,
        pid.bytes_le,
        data,
    ]))


def _create_fragment(
        object_id: int,
        fragment_id: int,
        data: bytes,
        end: bool = True,
) -> bytes:
    """Create a PSRP fragment.

    Creates a PSRP message fragment. The fragment structure is defined in `MS-PSRP 2.2.4 Packet Fragment`_.

    Args:
        object_id: The unique ID of the PSRP message to which the fragment belongs.
        fragment_id: Identifies where in the sequence of fragments this fragment falls.
        data: The PSRP message value to fragment.
        end: Whether this is the last fragment for the PSRP message (True) or not (False).

    Returns:
        (bytes): The PSRP fragment.

    .. _MS-PSRP 2.2.4 Packet Fragment:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/3610dae4-67f7-4175-82da-a3fab83af288
    """
    start_end_byte = 0
    if fragment_id == 0:
        start_end_byte |= 0x1
    if end:
        start_end_byte |= 0x2

    return b''.join([
        struct.pack(">Q", object_id),
        struct.pack(">Q", fragment_id),
        struct.pack("B", start_end_byte),
        struct.pack(">I", len(data)),
        data,
    ])


def _unpack_message(
        data: bytearray,
) -> Message:
    """ Unpack a PSRP message into a structured format. """
    destination = struct.unpack("<I", data[0:4])[0]
    message_type = PSRPMessageType(struct.unpack("<I", data[4:8])[0])
    rpid = str(uuid.UUID(bytes_le=bytes(data[8:24]))).upper()
    pid = str(uuid.UUID(bytes_le=bytes(data[24:40]))).upper()

    if rpid == _EMPTY_UUID:
        rpid = None
    if pid == _EMPTY_UUID:
        pid = None

    data = data[40:]
    if data.startswith(b"\xEF\xBB\xBF"):
        data = data[3:]  # Handle UTF-8 BOM in data.

    return Message(destination, message_type, rpid, pid, data)


def _unpack_fragment(
        data: bytearray,
) -> Fragment:
    """ Unpack a PSRP fragment into a structured format. """
    object_id = struct.unpack(">Q", data[0:8])[0]
    fragment_id = struct.unpack(">Q", data[8:16])[0]
    start_end_byte = struct.unpack("B", data[16:17])[0]
    start = start_end_byte & 0x1 == 0x1
    end = start_end_byte & 0x2 == 0x2
    length = struct.unpack(">I", data[17:21])[0]

    return Fragment(object_id, fragment_id, start, end, data[21:length + 21])


def _dict_to_psobject(**kwargs) -> PSObject:
    """ Builds a PSObject with note properties set by the kwargs. """
    obj = PSObject()
    for key, value in kwargs.items():
        add_note_property(obj, key, value)

    return obj


def state_check(
        action: typing.Optional[str] = None,
        require_states: typing.Optional[typing.List[typing.Union[PSInvocationState, RunspacePoolState]]] = None,
        require_version: typing.Optional[PSVersion] = None,
        skip_states: typing.Optional[typing.List[typing.Union[PSInvocationState, RunspacePoolState]]] = None,
):
    """Checks the state before running a function.

    This checks the state of a Runspace Pool or Pipeline to ensure it meets the requirements or skips the action
    altogether if it isn't needed for the current state.

    Args:
        action: A human description of the action for the error message.
        require_states: The state(s) that the Runspace Pool or Pipeline must be in to run the function.
        require_version: The protocolversion that the peer must be equal to or greater for this function.
        skip_states: A list of states that define whether the function is skipped if the Runspace Pool or Pipeline
            state is in.
    """
    def decorator(func):
        def wrapper(
                self: typing.Union['_RunspacePoolBase', '_PipelineBase'],
                *args,
                **kwargs
        ):
            action_desc = action or func.__name__
            current_state = self.state

            if isinstance(self, _RunspacePoolBase):
                runspace = self
                state_exp = InvalidRunspacePoolState

            else:
                runspace = self.runspace_pool
                state_exp = InvalidPipelineState

            if skip_states is not None and current_state in skip_states:
                return

            if require_states and current_state not in require_states:
                raise state_exp(action_desc, current_state, require_states)

            their_capability = runspace.their_capability
            current_version = getattr(their_capability, 'protocolversion', require_version)
            if require_version is not None and current_version < require_version:
                raise InvalidProtocolVersion(action_desc, current_version, require_version)

            return func(self, *args, **kwargs)
        return wrapper
    return decorator


class _RunspacePoolBase:
    """Runspace Pool base class.

    This is the base class for a Runspace Pool. It contains the common attributes and methods used by both a client
    and server based Runspace Pool.

    Args:
        runspace_id: The UUID that identified the Runspace Pool.
        capability: The SessionCapability of the caller.
        application_arguments: Any arguments supplied when creating the Runspace Pool as a client.
        application_private_data: Any special data supplied by the Runspace Pool as a server.

    Attributes:
        host: The HostInfo that contains host information of the client.
        runspace_id: See args.
        state: The current state of the Runspace Pool.
        apartment_state: The apartment state of the thread used to execute commands within this Runspace Pool.
        thread_options: Determines whether a new thread is created for each invocation.
        pipeline_table: A dictionary that contains associated pipelines with this Runspace Pool.
        our_capability: The SessionCapability of the caller.
        their_capability: The SessionCapability of the peer, only populated after the Runspace Pool has been opened.
        application_arguments: The application arguments from the client, will be populated for the server after the
            Runspace Pool has been opened.
        application_private_data: The app private data supplied by the server, will be populated for the client after
            the Runspace Pool has been opened.
    """

    def __new__(cls, *args, **kwargs):
        if cls in [_RunspacePoolBase]:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'Runspace Pool types.')

        return super().__new__(cls)

    def __init__(
            self,
            runspace_id: str,
            capability: SessionCapability,
            application_arguments: typing.Dict,
            application_private_data: typing.Dict,
    ):
        self.host: typing.Optional[HostInfo] = None
        self.runspace_id = runspace_id.upper()
        self.state = RunspacePoolState.BeforeOpen
        self.apartment_state = ApartmentState.Unknown
        self.thread_options = PSThreadOptions.Default
        self.pipeline_table: typing.Dict[str, _PipelineBase] = {}
        self.our_capability = capability
        self.their_capability: typing.Optional[SessionCapability] = None
        self.application_arguments = application_arguments
        self.application_private_data = application_private_data

        self._ci_table = {}
        self.__ci_counter = 1
        self.__fragment_counter = 1
        self._cipher: typing.Optional[PSRemotingCrypto] = None
        self._exchange_key = None
        self._min_runspaces = 0
        self._max_runspaces = 0
        self._send_buffer: typing.List[PSRPMessage] = []
        self._receive_buffer = bytearray()
        self._incoming_buffer: typing.Dict[int, typing.Union[typing.List[bytes], PSRPEvent, PSRPMessage]] = {}

    @property
    def max_runspaces(
            self,
    ) -> int:
        """ The maximum number of runspaces the pool maintains. """
        return self._max_runspaces

    @property
    def min_runspaces(
            self,
    ) -> int:
        """ The minimum number of runspaces the pool maintains. """
        return self._min_runspaces

    @property
    def _ci_counter(
            self,
    ) -> int:
        """ Counter used for ci calls. """
        ci = self.__ci_counter
        self.__ci_counter += 1
        return ci

    @property
    def _fragment_counter(
            self,
    ) -> int:
        """ Counter used for fragment object IDs. """
        count = self.__fragment_counter
        self.__fragment_counter += 1
        return count

    def data_to_send(
            self,
            amount: typing.Optional[int] = None,
    ) -> typing.Optional[PSRPPayload]:
        """Gets the next PSRP payload.

        Returns the PSRPPayload that contains the data that needs to be sent to the peer. This is a non-blocking call
        and is used by the implementer to get the next PSRP payload that is then sent over it's transport.

        Args:
            amount: The maximum size of the data fragment that can be sent. This must be 22 or larger to fit the
                fragment headers.

        Returns:
             (typing.Optional[PSRPPayload]): The payload (if any) that needs to be sent to the peer.
        """
        if amount is not None and amount < 22:
            raise ValueError('amount must be 22 or larger to fit a PSRP fragment')

        current_buffer = bytearray()
        stream_type = StreamType.default
        pipeline_id = None
        fragment_size = 21
        # TODO: prioritise prompt_response over default if the last fragment was an end fragment.

        for message in list(self._send_buffer):
            if amount is not None and amount < fragment_size:
                break

            if not current_buffer:
                stream_type = message.stream_type
                pipeline_id = message.pipeline_id

            # We can only combine fragments if they are for the same target.
            if pipeline_id != message.pipeline_id:
                break

            if amount is None:
                allowed_length = len(message)
            else:
                allowed_length = amount - fragment_size
                amount -= fragment_size + len(message)

            current_buffer += message.fragment(allowed_length)
            if len(message) == 0:
                self._send_buffer.remove(message)

                # Special edge case where we need to change the RunspacePool state when the last SessionCapability
                # fragment was sent.
                if self.state == RunspacePoolState.Opening and \
                        message.message_type == PSRPMessageType.SessionCapability:
                    self.state = RunspacePoolState.NegotiationSent

        if current_buffer:
            return PSRPPayload(bytes(current_buffer), stream_type, pipeline_id)

    def receive_data(
            self,
            data: PSRPPayload,
    ):
        """Store any incoming data.

        Stores any incoming payloads in an internal buffer to be processed. This buffer is read when calling
        `:meth:next_event()`.

        Args:
            data: The PSRP payload data received from the transport.
        """
        self._receive_buffer += data.data

    def next_event(
            self,
    ) -> typing.Optional[PSRPEvent]:
        """Process data received from the peer.

        This processes any PSRP data that has been received from the peer. Will return the next PSRP event in the
        receive buffer or `None` if not enough data is available.

        Returns:
            typing.Optional[PSRPEvent]: The next event present in the incoming data buffer or `None` if not enough data
                has been received.
        """
        while self._receive_buffer:
            fragment = _unpack_fragment(self._receive_buffer)
            self._receive_buffer = self._receive_buffer[21 + len(fragment.data):]

            buffer = self._incoming_buffer.setdefault(fragment.object_id, [])
            if fragment.fragment_id != len(buffer):
                raise PSRPError(f'Expecting fragment with a fragment id of {len(buffer)} not {fragment.fragment_id}')
            buffer.append(fragment.data)

            if fragment.end:
                raw_message = _unpack_message(bytearray(b"".join(buffer)))
                message = PSRPMessage(raw_message.message_type, raw_message.data, raw_message.rpid, raw_message.pid,
                                      fragment.object_id)
                self._incoming_buffer[fragment.object_id] = message

        for object_id in list(self._incoming_buffer.keys()):
            event = self._incoming_buffer[object_id]
            if isinstance(event, list):
                continue

            event = self._process_message(event)

            # We only want to clear the incoming buffer entry once we know the caller has the object.
            del self._incoming_buffer[object_id]
            return event

        # Need more data from te peer to produce an event.
        return

    @state_check(
        'send PSRP message',
        require_states=[
            RunspacePoolState.Connecting,
            RunspacePoolState.Opened,
            RunspacePoolState.Opening,
            RunspacePoolState.NegotiationSent,
            RunspacePoolState.NegotiationSucceeded,
        ],
    )
    def prepare_message(
            self,
            message: PSObject,
            message_type: typing.Optional[PSRPMessageType] = None,
            pipeline_id: typing.Optional[str] = None,
            stream_type: StreamType = StreamType.default
    ):
        """ Adds a PSRP message data action to the send buffer. """
        if isinstance(message, EndOfPipelineInput):
            b_data = b""  # Special edge case for this particular message type
        else:
            b_data = ElementTree.tostring(serialize(message, cipher=self._cipher), encoding='utf-8', method='xml')

        if message_type is None:
            message_type = PSRPMessageType(message.PSObject.psrp_message_type)

        is_client = isinstance(self, RunspacePool)
        message = _create_message(is_client, message_type, b_data, self.runspace_id, pipeline_id)

        object_id = self._fragment_counter
        psrp_message = PSRPMessage(message_type, message, self.runspace_id, pipeline_id, object_id, stream_type)
        self._send_buffer.append(psrp_message)

    def process_SessionCapability(
            self,
            event: SessionCapabilityEvent,
    ):
        # TODO: Verify the versions
        self.their_capability = event.ps_object
        self.state = RunspacePoolState.NegotiationSucceeded

    def _process_message(
            self,
            message: PSRPMessage,
    ) -> PSRPEvent:
        """ Process a TransportDataAction data message received from a peer. """
        if not message.data:
            # Special edge case for EndOfPipelineInput which has no data.
            ps_object = None

        else:
            ps_object = deserialize(ElementTree.fromstring(message.data), cipher=self._cipher)

        event = PSRPEvent(message.message_type, ps_object, message.runspace_pool_id, message.pipeline_id)

        process_func = getattr(self, f'process_{message.message_type.name}', None)
        if process_func:
            process_func(event)

        else:
            # TODO: Convert to a warning
            print(f'Received unknown message {message.message_type!s}')

        return event


class RunspacePool(_RunspacePoolBase):
    """Client Runspace Pool.

    Represents a Runspace Pool on a remote host which can contain one or more running pipelines. This is a non blocking
    connection object that handles the incoming and outgoing PSRP packets without worrying about the IO. This model
    is inspired by `Sans-IO model`_ where this object deals with only the PSRP protocol and needs to be combined with
    an IO transport separately.

    This is meant to be a close representation of the `System.Management.Automation.Runspaces.RunspacePool`_ .NET
    class.

    Args:
        application_arguments: Arguments that are sent to the server and accessible through
            `$PSSenderInfo.ApplicationArguments` of a pipeline that runs in this Runspace Pool.
        apartment_state: The apartment state of the thread used to execute commands within this Runspace Pool.
        host: The HostInfo that describes the client hosting application.
        thread_options: Determines whether a new thread is created for each invocation.
        min_runspaces: The minimum number of Runspaces a pool can hold.
        max_runspaces: The maximum number of Runspaces a pool can hold.
        runspace_pool_id: Manually set the Runspace Pool ID, used when reconnecting to an existing Runspace Pool.

    .. _System.Management.Automation.Runspaces.RunspacePool:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.runspacepool

    .. _Sans-IO model:
        https://sans-io.readthedocs.io/
    """
    def __init__(
            self,
            application_arguments: typing.Optional[typing.Dict] = None,
            apartment_state: ApartmentState = ApartmentState.Unknown,
            host: typing.Optional[HostInfo] = None,
            thread_options: PSThreadOptions = PSThreadOptions.Default,
            min_runspaces: int = 1,
            max_runspaces: int = 1,
            runspace_pool_id: typing.Optional[str] = None,
    ):
        super().__init__(
            runspace_pool_id or str(uuid.uuid4()),
            capability=_DEFAULT_CAPABILITY,
            application_arguments=application_arguments or {},
            application_private_data={},
        )
        self.apartment_state = apartment_state
        self.host = host
        self.thread_options = thread_options
        self._min_runspaces = min_runspaces
        self._max_runspaces = max_runspaces

    @state_check(
        'connect to Runspace Pool',
        require_states=[RunspacePoolState.Disconnected],
        skip_states=[RunspacePoolState.Opened],
    )
    def connect(self):
        self.state = RunspacePoolState.Connecting

        self.prepare_message(self.our_capability)
        self.prepare_message(ConnectRunspacePool())

    @state_check(
        skip_states=[RunspacePoolState.Closed, RunspacePoolState.Closing, RunspacePoolState.Broken],
    )
    def close(self):
        """Closes the RunspacePool.

        This closes the RunspacePool on the peer. Closing the Runspace Pool is done through a connection specific
        process. This method just verifies the Runspace Pool is in a state that can be closed and that no pipelines are
        still running.
        """
        if self.pipeline_table:
            raise PSRPError('Must close these pipelines first')
        self.state = RunspacePoolState.Closing

    @state_check(
        'get available Runspaces',
        require_states=[RunspacePoolState.Opened],
    )
    def get_available_runspaces(self) -> int:
        """Get the number of Runspaces available.

        This builds a request to get the number of available Runspaces in the pool. The
        :class:`psrp.protocol.powershell_events.GetRunspaceAvailabilityEvent` is returned once the response is received from the server.
        """
        ci = self._ci_counter
        self._ci_table[ci] = None
        self.prepare_message(GetAvailableRunspaces(ci=ci))

        return ci

    @state_check(
        'open Runspace Pool',
        require_states=[RunspacePoolState.BeforeOpen],
        skip_states=[RunspacePoolState.Opened],
    )
    def open(self):
        """Opens the RunspacePool.

        This opens the RunspacePool on the peer.
        """
        host = self.host or HostInfo()
        self.state = RunspacePoolState.Opening

        self.prepare_message(self.our_capability)

        init_runspace_pool = InitRunspacePool(
            MinRunspaces=self._min_runspaces,
            MaxRunspaces=self._max_runspaces,
            PSThreadOptions=self.thread_options,
            ApartmentState=self.apartment_state,
            HostInfo=host,
            ApplicationArguments=self.application_arguments,
        )
        self.prepare_message(init_runspace_pool)

    @state_check(
        'start session key exchange',
        require_states=[RunspacePoolState.Opened],
    )
    def exchange_key(self):
        """Exchange session specific key.

        Request the session key from the peer.
        """
        if self._cipher:
            return

        self._exchange_key, public_key = create_keypair()
        b64_public_key = base64.b64encode(public_key).decode()

        self.prepare_message(PublicKey(PublicKey=b64_public_key))

    @state_check(
        'response to host call',
        require_states=[RunspacePoolState.Opened],
    )
    def host_response(
            self,
            ci: int,
            return_value: typing.Optional[typing.Any] = None,
            error_record: typing.Optional[ErrorRecord] = None,
    ):
        """Respond to a host call.

        Respond to a host call event with either a return value or an error record.

        Args:
            ci: The call ID associated with the host call to response to.
            return_value: The return value for the host call.
            error_record: The error record raised by the host when running the host call.
        """
        call_event = self._ci_table.pop(ci)

        method_identifier = call_event.ps_object.mi
        pipeline_id = call_event.pipeline_id

        host_call_obj = PipelineHostResponse if pipeline_id else RunspacePoolHostResponse

        host_call = host_call_obj(ci=ci, mi=method_identifier)
        if return_value is not None:
            host_call.mr = return_value

        if error_record is not None:
            host_call.me = error_record

        self.prepare_message(host_call, pipeline_id=pipeline_id, stream_type=StreamType.prompt_response)

    @state_check(
        'reset Runspace Pool state',
        require_states=[RunspacePoolState.Opened],
        require_version=PSVersion('2.3'),
        skip_states=[RunspacePoolState.BeforeOpen],
    )
    def reset_runspace_state(self) -> int:
        """Reset the Runspace Pool state.

        Resets the variable table for the Runspace Pool back to the default state.
        """
        ci = self._ci_counter
        self._ci_table[ci] = None
        self.prepare_message(ResetRunspaceState(ci=ci))

        return ci

    def set_max_runspaces(
            self,
            value: int,
    ) -> typing.Optional[int]:
        """Set the maximum number of runspaces.

        Build a request to set the maximum number of Runspaces the pool maintains. The `max_runspaces` property is
        updated once the `:class:SetMaxRunspacesEvent` is fired.

        Args:
            value: The maximum number of runspaces in a pool to change to.
        """
        if self.state == RunspacePoolState.BeforeOpen or self._max_runspaces == value:
            self._max_runspaces = value
            return

        ci = self._ci_counter
        self._ci_table[ci] = lambda e: setattr(self, '_max_runspaces', value)
        self.prepare_message(SetMaxRunspaces(MaxRunspaces=value, ci=ci))

        return ci

    def set_min_runspaces(
            self,
            value: int,
    ) -> typing.Optional[int]:
        """Set the minimum number of runspaces.

        Build a request to set the minimum number of Runspaces the pool maintains. The `min_runspaces` property is
        updated once the `:class:SetMinRunspacesEvent` is fired.

        Args:
            value: The minimum number of runspaces in a pool to change to.
        """
        if self.state == RunspacePoolState.BeforeOpen or self._min_runspaces == value:
            self._min_runspaces = value
            return

        ci = self._ci_counter
        self._ci_table[ci] = lambda e: setattr(self, '_min_runspaces', value)
        self.prepare_message(SetMinRunspaces(MinRunspaces=value, ci=ci))

        return ci

    def process_ApplicationPrivateData(
            self,
            event: ApplicationPrivateDataEvent,
    ):
        self.application_private_data = event.ps_object.ApplicationPrivateData

    def process_DebugRecord(
            self,
            event: DebugRecordEvent,
    ):
        pass

    def process_EncryptedSessionKey(
            self,
            event: EncryptedSessionKeyEvent,
    ):
        encrypted_session_key = base64.b64decode(event.ps_object.EncryptedSessionKey)
        session_key = decrypt_session_key(self._exchange_key, encrypted_session_key)
        self._cipher = PSRemotingCrypto(session_key)

    def process_ErrorRecord(
            self,
            event: ErrorRecordEvent,
    ):
        pass

    def process_InformationRecord(
            self,
            event: InformationRecordEvent,
    ):
        pass

    def process_PipelineHostCall(
            self,
            event: PipelineHostCallEvent,
    ):
        # Store the event for the host response to use.
        self._ci_table[event.ps_object.ci] = event

    def process_PipelineOutput(
            self,
            event: PipelineOutputEvent,
    ):
        pass

    def process_PipelineState(
            self,
            event: PipelineStateEvent,
    ):
        pipeline = self.pipeline_table[event.pipeline_id]
        pipeline.state = event.state

        if event.state in [PSInvocationState.Completed, PSInvocationState.Stopped]:
            del self.pipeline_table[event.pipeline_id]

    def process_ProgressRecord(
            self,
            event: ProgressRecordEvent,
    ):
        pass

    def process_PublicKeyRequest(
            self,
            event: PublicKeyRequestEvent,
    ):
        self.exchange_key()

    def process_RunspaceAvailability(
            self,
            event: RunspaceAvailabilityEvent,
    ):
        handler = self._ci_table.pop(int(event.ps_object.ci))
        if handler is not None:
            handler(event)

    def process_RunspacePoolHostCall(
            self,
            event: RunspacePoolHostCallEvent,
    ):
        # Store the event for the host response to use.
        self._ci_table[int(event.ps_object.ci)] = event

    def process_RunspacePoolInitData(
            self,
            event: RunspacePoolInitDataEvent,
    ):
        self._min_runspaces = event.ps_object.MinRunspaces
        self._max_runspaces = event.ps_object.MaxRunspaces

    def process_RunspacePoolState(
            self,
            event: RunspacePoolStateEvent,
    ):
        self.state = event.state

    def process_UserEvent(
            self,
            event: UserEventEvent,
    ):
        pass

    def process_VerboseRecord(
            self,
            event: VerboseRecordEvent,
    ):
        pass

    def process_WarningRecord(
            self,
            event: WarningRecordEvent,
    ):
        pass


class ServerRunspacePool(_RunspacePoolBase):

    def __init__(
            self,
            application_private_data: typing.Optional[typing.Dict] = None,
    ):
        super().__init__(
            _EMPTY_UUID,
            capability=_DEFAULT_CAPABILITY,
            application_arguments={},
            application_private_data=application_private_data or {},
        )

    @state_check(
        'generate Runspace Pool event',
        require_states=[RunspacePoolState.Opened],
    )
    def format_event(
            self,
            event_identifier: typing.Union[PSInt, int],
            source_identifier: typing.Union[PSString, str],
            sender: typing.Any = None,
            source_args: typing.Optional[typing.List[typing.Any]] = None,
            message_data: typing.Any = None,
            time_generated: typing.Optional[typing.Union[PSDateTime, datetime.datetime]] = None,
            computer: typing.Optional[typing.Union[PSString, str]] = None,
    ):
        """Send event to client.

        Sends an event to the client Runspace Pool.

        Args:
            event_identifier: Unique identifier of this event.
            source_identifier: Identifier associated with the source of this
                event.
            sender: Object that generated this event.
            source_args: List of arguments captured by the original event
                source.
            message_data: Additional user data associated with this event.
            time_generated: Time and date that this event was generated,
                defaults to now.
            computer: The name of the computer on which this event was
                generated, defaults to the current computer.
        """
        time_generated = PSDateTime.now() if time_generated is None else time_generated
        computer = platform.node() if computer is None else computer

        self.prepare_message(UserEvent(
            EventIdentifier=PSInt(event_identifier),
            SourceIdentifier=PSString(source_identifier),
            TimeGenerated=time_generated,
            Sender=sender,
            SourceArgs=source_args or [],
            MessageData=message_data,
            ComputerName=computer,
            RunspaceId=PSGuid(self.runspace_id),
        ))

    @state_check(
        'create host call',
        require_states=[RunspacePoolState.Opened],
    )
    def host_call(
            self,
            method: HostMethodIdentifier,
            parameters: typing.Optional[typing.List] = None,
            pipeline_id: typing.Optional[str] = None,
    ) -> int:
        ci = self._ci_counter

        call_type = PipelineHostCall if pipeline_id else RunspacePoolHostCall
        call = call_type(
            ci=ci,
            mi=method,
            mp=parameters,
        )
        self.prepare_message(call, pipeline_id=pipeline_id, stream_type=StreamType.prompt_response)

        return ci

    @state_check(
        'request exchange key',
        require_states=[RunspacePoolState.Opened],
    )
    def request_key(self):
        if self._cipher:
            return
        self.prepare_message(PublicKeyRequest())

    def process_ConnectRunspacePool(
            self,
            event: ConnectRunspacePoolEvent,
    ):
        # TODO: Handle <S></S> ConnectRunspacePool object
        self._max_runspaces = event.ps_object.MaxRunspaces
        self._min_runspaces = event.ps_object.MinRunspaces

        self.prepare_message(RunspacePoolInitData(
            MinRunspaces=self.min_runspaces,
            MaxRunspaces=self.max_runspaces,
        ))

        self.prepare_message(ApplicationPrivateData(ApplicationPrivateData=self.application_private_data))

    def process_CreatePipeline(
            self,
            event: CreatePipelineEvent,
    ):
        create_pipeline = event.ps_object
        powershell = create_pipeline.PowerShell

        pipeline = ServerPowerShell(
            runspace_pool=self,
            pipeline_id=event.pipeline_id,
            add_to_history=create_pipeline.AddToHistory,
            apartment_state=create_pipeline.ApartmentState,
            history=powershell.History,
            host=HostInfo.from_psobject(create_pipeline.HostInfo),
            is_nested=create_pipeline.IsNested,
            no_input=create_pipeline.NoInput,
            remote_stream_options=create_pipeline.RemoteStreamOptions,
            redirect_shell_error_to_out=powershell.RedirectShellErrorOutputPipe,
        )
        commands = [powershell.Cmds]
        commands.extend([c.Cmds for c in getattr(powershell, 'ExtraCmds', [])])

        for statements in commands:
            for raw_cmd in statements:
                cmd = Command.from_psobject(raw_cmd)
                pipeline.commands.append(cmd)

            pipeline.commands[-1].end_of_statement = True

        event.pipeline = pipeline

    def process_EndOfPipelineInput(
            self,
            event: EndOfPipelineInputEvent,
    ):
        pass

    def process_GetAvailableRunspaces(
            self,
            event: GetAvailableRunspacesEvent,
    ):
        # TODO: This should reflect the available runspaces and not the max.
        self.prepare_message(RunspaceAvailability(
            SetMinMaxRunspacesResponse=self.max_runspaces,
            ci=event.ps_object.ci,
        ))

    def process_GetCommandMetadata(
            self,
            event: GetCommandMetadataEvent,
    ):
        get_meta = event.ps_object
        pipeline = ServerGetCommandMetadata(
            runspace_pool=self,
            pipeline_id=event.pipeline_id,
            name=get_meta.Name,
            command_type=get_meta.CommandType,
            namespace=get_meta.Namespace,
            arguments=get_meta.ArgumentList,
        )
        event.pipeline = pipeline

    def process_InitRunspacePool(
            self,
            event: InitRunspacePoolEvent,
    ):
        self.apartment_state = event.ps_object.ApartmentState
        self.application_arguments = event.ps_object.ApplicationArguments
        self.host = event.ps_object.HostInfo
        self.thread_options = event.ps_object.PSThreadOptions
        self._max_runspaces = event.ps_object.MaxRunspaces
        self._min_runspaces = event.ps_object.MinRunspaces

        self.prepare_message(ApplicationPrivateData(ApplicationPrivateData=self.application_private_data))
        self.state = RunspacePoolState.Opened
        self.prepare_message(RunspacePoolStateMsg(RunspaceState=int(self.state)))

    def process_PipelineHostResponse(
            self,
            event: PipelineHostResponseEvent,
    ):
        pass

    def process_PipelineInput(
            self,
            event: PipelineInputEvent,
    ):
        pass

    def process_PublicKey(
            self,
            event: PublicKeyEvent,
    ):
        session_key = os.urandom(32)
        self._cipher = PSRemotingCrypto(session_key)

        exchange_key = base64.b64decode(event.ps_object.PublicKey)
        encrypted_session_key = encrypt_session_key(exchange_key, session_key)

        msg = EncryptedSessionKey(
            EncryptedSessionKey=base64.b64encode(encrypted_session_key).decode(),
        )
        self.prepare_message(msg)

    def process_ResetRunspaceState(
            self,
            event: ResetRunspaceStateEvent,
    ):
        pass

    def process_RunspacePoolHostResponse(
            self,
            event: RunspacePoolHostResponseEvent,
    ):
        pass

    def process_SessionCapability(
            self,
            event: SessionCapabilityEvent,
    ):
        super().process_SessionCapability(event)
        self.prepare_message(self.our_capability)

        # The session capability from the server must be set to \x00 so we set the ID after generating it.
        self.runspace_id = event.runspace_pool_id

    def process_SetMaxRunspaces(
            self,
            event: SetMaxRunspacesEvent,
    ):
        self._max_runspaces = event.ps_object.MaxRunspaces
        self.prepare_message(RunspaceAvailability(
            SetMinMaxRunspacesResponse=True,
            ci=event.ps_object.ci,
        ))

    def process_SetMinRunspaces(
            self,
            event: SetMinRunspacesEvent,
    ):
        self._min_runspaces = event.ps_object.MinRunspaces
        self.prepare_message(RunspaceAvailability(
            SetMinMaxRunspacesResponse=True,
            ci=event.ps_object.ci,
        ))


RunspacePoolType = typing.TypeVar('RunspacePoolType', bound=_RunspacePoolBase)


class _PipelineBase(typing.Generic[RunspacePoolType]):

    def __new__(cls, *args, **kwargs):
        if cls in [_PipelineBase, _ClientPipeline, _ServerPipeline, GetCommandMetadataPipeline, PowerShell]:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'client/server pipeline types.')

        return super().__new__(cls)

    def __init__(
            self,
            runspace_pool: RunspacePoolType,
            pipeline_id: str,
    ):
        self.runspace_pool = runspace_pool
        self.state = PSInvocationState.NotStarted
        self.pipeline_id = pipeline_id.upper()
        runspace_pool.pipeline_table[self.pipeline_id] = self

    def close(self):
        del self.runspace_pool.pipeline_table[self.pipeline_id]

    def prepare_message(
            self,
            message: PSObject,
            message_type: typing.Optional[PSRPMessageType] = None,
            stream_type: StreamType = StreamType.default
    ):
        self.runspace_pool.prepare_message(message, message_type=message_type, pipeline_id=self.pipeline_id,
                                           stream_type=stream_type)


class _ClientPipeline(_PipelineBase[RunspacePool]):

    def __init__(
            self,
            runspace_pool: RunspacePool,
    ):
        super().__init__(runspace_pool, str(uuid.uuid4()))

    def invoke(self):
        self.prepare_message(self.to_psobject())
        self.state = PSInvocationState.Running

    def send(
            self,
            data: typing.Any,
    ):
        self.prepare_message(data, message_type=PSRPMessageType.PipelineInput)

    def send_end(self):
        self.prepare_message(EndOfPipelineInput())

    @state_check(
        'response to pipeline host call',
        require_states=[PSInvocationState.Running],
    )
    def host_response(
            self,
            ci: int,
            return_value: typing.Optional[typing.Any] = None,
            error_record: typing.Optional[ErrorRecord] = None,
    ):
        """Respond to a host call.

        Respond to a host call event with either a return value or an error record.

        Args:
            ci: The call ID associated with the host call to response to.
            return_value: The return value for the host call.
            error_record: The error record raised by the host when running the host call.
        """
        self.runspace_pool.host_response(ci, return_value, error_record)

    def to_psobject(self) -> PSObject:
        raise NotImplementedError()  # pragma: no cover


class _ServerPipeline(_PipelineBase[ServerRunspacePool]):

    @state_check(
        'starting pipeline',
        require_states=[PSInvocationState.NotStarted],
        skip_states=[PSInvocationState.Running],
    )
    def start(self):
        self.state = PSInvocationState.Running

    @state_check(
        'closing pipeline',
        skip_states=[PSInvocationState.Stopped],
    )
    def close(self):
        super().close()
        self.state = PSInvocationState.Completed
        self._send_state()

    @state_check(
        'closing pipeline',
        require_states=[PSInvocationState.Running],
        skip_states=[PSInvocationState.Stopping, PSInvocationState.Stopped],
    )
    def stop(self):
        self.state = PSInvocationState.Stopped

        exception = NETException(
            Message='The pipeline has been stopped.',
            HResult=-2146233087,
        )
        exception.PSTypeNames.extend([
            'System.Management.Automation.PipelineStoppedException',
            'System.Management.Automation.RuntimeException',
            'System.SystemException',
        ])

        stopped_error = ErrorRecord(
            Exception=exception,
            CategoryInfo=ErrorCategoryInfo(
                Category=ErrorCategory.OperationStopped,
                Reason='PipelineStoppedException',
            ),
            FullyQualifiedErrorId='PipelineStopped',
        )
        self._send_state(stopped_error)
        super().close()

    @state_check(
        'making pipeline host call',
        require_states=[PSInvocationState.Running],
    )
    def host_call(
            self,
            method: HostMethodIdentifier,
            parameters: typing.Optional[typing.List] = None,
    ) -> int:
        return self.runspace_pool.host_call(method, parameters, self.pipeline_id)

    @state_check(
        'writing output record',
        require_states=[PSInvocationState.Running],
    )
    def write_output(
            self,
            value: typing.Any,
    ):
        """Write object.

        Write an object to the output stream.

        Args:
            value: The object to write.
        """
        self.prepare_message(value, message_type=PSRPMessageType.PipelineOutput)

    @state_check(
        'writing error record',
        require_states=[PSInvocationState.Running],
    )
    def write_error(
            self,
            exception: NETException,
            category_info: typing.Optional[ErrorCategoryInfo] = None,
            target_object: typing.Any = None,
            fully_qualified_error_id: typing.Optional[str] = None,
            error_details: typing.Optional[ErrorDetails] = None,
            invocation_info: typing.Optional[InvocationInfo] = None,
            pipeline_iteration_info: typing.Optional[typing.List[typing.Union[PSInt, int]]] = None,
            script_stack_trace: typing.Optional[str] = None,
            serialize_extended_info: bool = False,
    ):
        category_info = category_info or ErrorCategoryInfo()

        value = ErrorRecord(
            Exception=exception,
            CategoryInfo=category_info,
            TargetObject=target_object,
            FullyQualifiedErrorId=fully_qualified_error_id,
            InvocationInfo=invocation_info,
            ErrorDetails=error_details,
            PipelineIterationInfo=pipeline_iteration_info,
            ScriptStackTrace=script_stack_trace,
        )
        value.serialize_extended_info = serialize_extended_info
        self.prepare_message(value, message_type=PSRPMessageType.ErrorRecord)

    @state_check(
        'writing debug record',
        require_states=[PSInvocationState.Running],
    )
    def write_debug(
            self,
            message: typing.Union[str],
            invocation_info: typing.Optional[InvocationInfo] = None,
            pipeline_iteration_info: typing.Optional[typing.List[typing.Union[PSInt, int]]] = None,
            serialize_extended_info: bool = False,
    ):
        value = InformationalRecord(
            Message=message,
            InvocationInfo=invocation_info,
            PipelineIterationInfo=pipeline_iteration_info,
        )
        value.serialize_extended_info = serialize_extended_info
        self.prepare_message(value, message_type=PSRPMessageType.DebugRecord)

    @state_check(
        'writing verbose record',
        require_states=[PSInvocationState.Running],
    )
    def write_verbose(
            self,
            message: typing.Union[str],
            invocation_info: typing.Optional[InvocationInfo] = None,
            pipeline_iteration_info: typing.Optional[typing.List[typing.Union[PSInt, int]]] = None,
            serialize_extended_info: bool = False,
    ):
        value = InformationalRecord(
            Message=message,
            InvocationInfo=invocation_info,
            PipelineIterationInfo=pipeline_iteration_info,
        )
        value.serialize_extended_info = serialize_extended_info
        self.prepare_message(value, message_type=PSRPMessageType.VerboseRecord)

    @state_check(
        'writing warning record',
        require_states=[PSInvocationState.Running],
    )
    def write_warning(
            self,
            message: typing.Union[str],
            invocation_info: typing.Optional[InvocationInfo] = None,
            pipeline_iteration_info: typing.Optional[typing.List[typing.Union[PSInt, int]]] = None,
            serialize_extended_info: bool = False,
    ):
        value = InformationalRecord(
            Message=message,
            InvocationInfo=invocation_info,
            PipelineIterationInfo=pipeline_iteration_info,
        )
        value.serialize_extended_info = serialize_extended_info
        self.prepare_message(value, message_type=PSRPMessageType.WarningRecord)

    @state_check(
        'writing progress record',
        require_states=[PSInvocationState.Running],
    )
    def write_progress(
            self,
            activity: typing.Union[PSString, str],
            activity_id: typing.Union[PSInt, int],
            status_description: typing.Union[PSString, str],
            current_operation: typing.Optional[typing.Union[PSString, str]] = None,
            parent_activity_id: typing.Union[PSInt, int] = -1,
            percent_complete: typing.Union[PSInt, int] = -1,
            record_type: ProgressRecordType = ProgressRecordType.Processing,
            seconds_remaining: typing.Union[PSInt, int] = -1,
    ):
        """Write a progress record.

        Writes a progress record to send to the client.

        Args:
            activity: The description of the activity for which progress is
                being reported.
            activity_id: The Id of the activity to which this record
                corresponds. Used as a key for linking of subordinate
                activities.
            status_description: Current status of the operation, e.g.
                "35 of 50 items copied.".
            current_operation: Current operation of the many required to
                accomplish the activity, e.g. "copying foo.txt".
            parent_activity_id: The Id of the activity for which this record is
                a subordinate.
            percent_complete: The estimate of the percentage of total work for
                the activity that is completed. Set to a negative value to
                indicate that the percentage completed should not be displayed.
            record_type: The type of record represented.
            seconds_remaining: The estimate of time remaining until this
                activity is completed. Set to a negative value to indicate that
                the seconds remaining should not be displayed.
        """
        value = ProgressRecord(
            Activity=activity,
            ActivityId=activity_id,
            StatusDescription=status_description,
            CurrentOperation=current_operation,
            ParentActivityId=parent_activity_id,
            PercentComplete=percent_complete,
            Type=record_type,
            SecondsRemaining=seconds_remaining,
        )
        self.prepare_message(value, message_type=PSRPMessageType.ProgressRecord)

    @state_check(
        'writing information record',
        require_states=[PSInvocationState.Running],
        require_version=PSVersion('2.3'),
    )
    def write_information(
            self,
            message_data: typing.Any,
            source: typing.Union[PSString, str],
            time_generated: typing.Optional[typing.Union[PSDateTime, datetime.datetime]] = None,
            tags: typing.Optional[PSList[PSString, str]] = None,
            user: typing.Optional[typing.Union[PSString, str]] = None,
            computer: typing.Optional[typing.Union[PSString, str]] = None,
            process_id: typing.Optional[typing.Union[PSUInt, int]] = None,
            native_thread_id: typing.Optional[typing.Union[PSUInt, int]] = None,
            managed_thread_id: typing.Union[PSUInt, int] = None,
    ):
        """Write an information record.

        Writes an information record to send to the client.

        Note:
            This requires ProtocolVersion 2.3 (PowerShell 5.1+).

        Args:
            message_data: Data for this record.
            source: The source of this record, e.g. script path, function name,
                etc.
            time_generated: The time the record was generated, will default to
                now if not specified.
            tags: Tags associated with the record, if any.
            user: The user that generated the record, defaults to the current
                user.
            computer: The computer that generated the record, defaults to the
                current computer.
            process_id: The process that generated the record, defaults to the
                current process.
            native_thread_id: The native thread that generated the record,
                defaults to the current thread.
            managed_thread_id: The managed thread that generated the record,
                defaults to 0.
        """
        time_generated = PSDateTime.now() if time_generated is None else time_generated
        tags = tags or []
        user = getpass.getuser() if user is None else user
        computer = platform.node() if computer is None else computer
        process_id = os.getpid() if process_id is None else process_id
        native_thread_id = threading.get_native_id() if native_thread_id is None else native_thread_id

        value = InformationRecord(
            MessageData=message_data,
            Source=source,
            TimeGenerated=time_generated,
            Tags=tags,
            User=user,
            Computer=computer,
            ProcessId=process_id or 0,
            NativeThreadId=native_thread_id or 0,
            ManagedThreadId=managed_thread_id or 0,
        )
        self.prepare_message(value, message_type=PSRPMessageType.InformationRecord)

    def _send_state(
            self,
            error_record: typing.Optional[ErrorRecord] = None,
    ):
        state = PipelineState(
            PipelineState=int(self.state),
        )
        if error_record is not None:
            state.ExceptionAsErrorRecord = error_record
        self.prepare_message(state)


class PowerShell(_PipelineBase):
    """
    Args:
        add_to_history: Whether to add the pipeline to the history field of the runspace.
        apartment_state: The apartment state of the thread that executes the pipeline.
        host: The host information to use when executing the pipeline.
        no_input: Whether there is any data to be input into the pipeline.
        remote_stream_options: Whether to add invocation info the the PowerShell streams or not.
        redirect_shell_error_to_out: Redirects the global error output pipe to the commands error output pipe.
    """
    def __init__(
            self,
            add_to_history: bool = False,
            apartment_state: typing.Optional[ApartmentState] = None,
            history: typing.Optional[str] = None,
            host: typing.Optional[HostInfo] = None,
            is_nested: bool = False,
            no_input: bool = True,
            remote_stream_options: RemoteStreamOptions = RemoteStreamOptions.none,
            redirect_shell_error_to_out: bool = True,
            *args,
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.add_to_history = add_to_history
        self.apartment_state = apartment_state or self.runspace_pool.apartment_state
        self.commands: typing.List[Command] = []
        self.history = history
        self.host = host or HostInfo()
        self.is_nested = is_nested
        self.no_input = no_input
        self.remote_stream_options = remote_stream_options
        self.redirect_shell_error_to_out = redirect_shell_error_to_out

    def to_psobject(self) -> CreatePipeline:
        if not self.commands:
            raise ValueError('A command is required to invoke a PowerShell pipeline.')

        extra_cmds = [[]]
        for cmd in self.commands:
            cmd_psobject = cmd.to_psobject(self.runspace_pool.their_capability.protocolversion)
            extra_cmds[-1].append(cmd_psobject)
            if cmd.end_of_statement:
                extra_cmds.append([])
        cmds = extra_cmds.pop(0)

        # MS-PSRP 2.2.3.11 Pipeline
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/82a8d1c6-4560-4e68-bfd0-a63c36d6a199
        pipeline_kwargs = {
            'Cmds': cmds,
            'IsNested': self.is_nested,
            'History': self.history,
            'RedirectShellErrorOutputPipe': self.redirect_shell_error_to_out,
        }

        if extra_cmds:
            # This isn't documented in MS-PSRP but this is how PowerShell batches multiple statements in 1 pipeline.
            # TODO: ExtraCmds may not work with protocol <=2.1.
            pipeline_kwargs['ExtraCmds'] = [_dict_to_psobject(Cmds=s) for s in extra_cmds]

        return CreatePipeline(
            NoInput=self.no_input,
            ApartmentState=self.apartment_state,
            RemoteStreamOptions=self.remote_stream_options,
            AddToHistory=self.add_to_history,
            HostInfo=self.host,
            PowerShell=_dict_to_psobject(**pipeline_kwargs),
            IsNested=self.is_nested,
        )


class ClientPowerShell(PowerShell, _ClientPipeline):

    def __init__(
            self,
            runspace_pool: RunspacePoolType,
            *args,
            **kwargs,
    ):
        super().__init__(runspace_pool=runspace_pool, *args, **kwargs)

    def add_argument(
            self,
            value: typing.Any,
    ):
        self.add_parameter(None, value)

    def add_command(
            self,
            cmdlet: typing.Union[str, 'Command'],
            use_local_scope: typing.Optional[bool] = None,
    ):
        if isinstance(cmdlet, str):
            cmdlet = Command(cmdlet, use_local_scope=use_local_scope)

        elif use_local_scope is not None:
            raise TypeError('Cannot set use_local_scope with Command')

        self.commands.append(cmdlet)

    def add_parameter(
            self,
            name: typing.Optional[str],
            value: typing.Any = None,
    ):
        if not self.commands:
            raise ValueError('A command is required to add a parameter/argument. A command must be added to the '
                             'PowerShell instance first.')

        self.commands[-1].parameters.append((name, value))

    def add_parameters(
            self,
            parameters: typing.Dict[str, typing.Any],
    ):
        for name, value in parameters.items():
            self.add_parameter(name, value)

    def add_script(
            self,
            script: str,
            use_local_scope: typing.Optional[bool] = None,
    ):
        self.add_command(Command(script, True, use_local_scope=use_local_scope))

    def add_statement(self):
        if not self.commands:
            return

        self.commands[-1].end_of_statement = True


class ServerPowerShell(PowerShell, _ServerPipeline):

    def __init__(
            self,
            runspace_pool: RunspacePoolType,
            pipeline_id: str,
            *args,
            **kwargs,
    ):
        super().__init__(runspace_pool=runspace_pool, pipeline_id=pipeline_id, *args, **kwargs)


class GetCommandMetadataPipeline(_PipelineBase):

    def __init__(
            self,
            name: typing.Union[str, typing.List[str]],
            command_type: CommandTypes = CommandTypes.All,
            namespace: typing.Optional[typing.List[str]] = None,
            arguments: typing.Optional[typing.List[str]] = None,
            *args,
            **kwargs
    ):
        super().__init__(*args, **kwargs)

        if not isinstance(name, list):
            name = [name]
        self.name = name
        self.command_type = command_type
        self.namespace = namespace
        self.arguments = arguments

    def to_psobject(self) -> GetCommandMetadata:
        return GetCommandMetadata(
            Name=self.name,
            CommandType=self.command_type,
            Namespace=self.namespace,
            ArgumentList=self.arguments,
        )


class ClientGetCommandMetadata(GetCommandMetadataPipeline, _ClientPipeline):

    def __init__(
            self,
            runspace_pool: RunspacePoolType,
            *args,
            **kwargs,
    ):
        super().__init__(runspace_pool=runspace_pool, *args, **kwargs)


class ServerGetCommandMetadata(GetCommandMetadataPipeline, _ServerPipeline):

    def __init__(
            self,
            runspace_pool: RunspacePoolType,
            pipeline_id: str,
            *args,
            **kwargs,
    ):
        super().__init__(runspace_pool=runspace_pool, pipeline_id=pipeline_id, *args, **kwargs)
        self._count = None
        # TODO: Add support for writing other command info types.

    def write_count(
            self,
            count: typing.Union[PSInt, int],
    ):
        self._count = count
        obj = PSCustomObject(
            PSTypeName='Selected.Microsoft.PowerShell.Commands.GenericMeasureInfo',
            Count=count,
        )
        self.write_output(obj)

    def write_cmdlet_info(
            self,
            name: typing.Union[PSString, str],
            namespace: typing.Union[PSString, str],
            help_uri: typing.Union[PSString, str] = '',
            output_type: typing.Optional[typing.List[typing.Union[PSString, str]]] = None,
            parameters: typing.Optional[typing.Dict[typing.Union[PSString, str], typing.Any]] = None,
    ):

        self.write_output(PSCustomObject(
            PSTypeName='Selected.System.Management.Automation.CmdletInfo',
            CommandType=CommandTypes.Cmdlet,
            Name=name,
            Namespace=namespace,
            HelpUri=help_uri,
            OutputType=output_type or [],
            Parameters=parameters or {},
            ResolvedCommandName=None,
        ))

    def write_output(
            self,
            value: typing.Any,
    ):
        if self._count is None:
            raise ValueError('write_count must be called before writing to the command metadata pipeline')
        super().write_output(value)


class Command:

    def __init__(
            self,
            name: str,
            is_script: bool = False,
            use_local_scope: typing.Optional[bool] = None,
    ):
        self.command_text = name
        self.is_script = is_script
        self.use_local_scope = use_local_scope
        self.parameters: typing.List[typing.Tuple[typing.Optional[str], typing.Any]] = []
        self.end_of_statement = False

        self.merge_unclaimed = False
        self._merge_my = PipelineResultTypes.none
        self._merge_to = PipelineResultTypes.none
        self._merge_error = PipelineResultTypes.none
        self._merge_warning = PipelineResultTypes.none
        self._merge_verbose = PipelineResultTypes.none
        self._merge_debug = PipelineResultTypes.none
        self._merge_information = PipelineResultTypes.none

    def __repr__(self):
        cls = self.__class__
        return f"{cls.__name__}(name='{self.command_text}', is_script={self.is_script}, " \
               f"use_local_scope={self.use_local_scope!s})"

    def __str__(self):
        return self.command_text

    @property
    def merge_my(self) -> PipelineResultTypes:
        return self._merge_my

    @property
    def merge_to(self) -> PipelineResultTypes:
        return self._merge_to

    @property
    def merge_error(self) -> PipelineResultTypes:
        return self._merge_error

    @property
    def merge_warning(self) -> PipelineResultTypes:
        return self._merge_warning

    @property
    def merge_verbose(self) -> PipelineResultTypes:
        return self._merge_verbose

    @property
    def merge_debug(self) -> PipelineResultTypes:
        return self._merge_debug

    @property
    def merge_information(self) -> PipelineResultTypes:
        return self._merge_information

    def redirect_all(
            self,
            stream: PipelineResultTypes.Output,
    ):
        if stream == PipelineResultTypes.none:
            self._merge_my = stream
            self._merge_to = stream

        self.redirect_error(stream)
        self.redirect_warning(stream)
        self.redirect_verbose(stream)
        self.redirect_debug(stream)
        self.redirect_information(stream)

    def redirect_error(
            self,
            stream: PipelineResultTypes.Output
    ):
        self._validate_redirection_to(stream)
        if stream == PipelineResultTypes.none:
            self._merge_my = PipelineResultTypes.none
            self._merge_to = PipelineResultTypes.none

        elif stream != PipelineResultTypes.Null:
            self._merge_my = PipelineResultTypes.Error
            self._merge_to = stream

        self._merge_error = stream

    def redirect_warning(
            self,
            stream: PipelineResultTypes.Output
    ):
        self._validate_redirection_to(stream)
        self._merge_warning = stream

    def redirect_verbose(
            self,
            stream: PipelineResultTypes.Output
    ):
        self._validate_redirection_to(stream)
        self._merge_verbose = stream

    def redirect_debug(
            self,
            stream: PipelineResultTypes.Output
    ):
        self._validate_redirection_to(stream)
        self._merge_debug = stream

    def redirect_information(
            self,
            stream: PipelineResultTypes.Output
    ):
        self._validate_redirection_to(stream)
        self._merge_information = stream

    def _validate_redirection_to(
            self,
            stream: PipelineResultTypes,
    ):
        if stream not in [
            PipelineResultTypes.none,
            PipelineResultTypes.Output,
            PipelineResultTypes.Null
        ]:
            raise ValueError('Invalid redirection stream, must be none, Output, or Null')

    def to_psobject(
            self,
            protocol_version: PSVersion,
    ) -> PSObject:
        merge_previous = PipelineResultTypes.Output | PipelineResultTypes.Error \
            if self.merge_unclaimed else PipelineResultTypes.none

        command_kwargs = {
            'Cmd': self.command_text,
            'Args': [_dict_to_psobject(N=n, V=v) for n, v in self.parameters],
            'IsScript': self.is_script,
            'UseLocalScope': self.use_local_scope,
            'MergeMyResult': self.merge_my,
            'MergeToResult': self.merge_to,
            'MergePreviousResults': merge_previous,
        }

        # For backwards compatibility we need to optional set these values based on the peer's protocol version.
        if protocol_version >= PSVersion('2.2'):
            command_kwargs['MergeError'] = self.merge_error
            command_kwargs['MergeWarning'] = self.merge_warning
            command_kwargs['MergeVerbose'] = self.merge_verbose
            command_kwargs['MergeDebug'] = self.merge_debug

        if protocol_version >= PSVersion('2.3'):
            command_kwargs['MergeInformation'] = self.merge_information

        return _dict_to_psobject(**command_kwargs)

    @staticmethod
    def from_psobject(
            command: PSObject,
    ) -> 'Command':
        cmd = Command(
            name=command.Cmd,
            is_script=command.IsScript,
            use_local_scope=command.UseLocalScope,
        )
        for argument in command.Args:
            cmd.parameters.append((argument.N, argument.V))

        merge_unclaimed = PipelineResultTypes.Output | PipelineResultTypes.Error
        cmd.merge_unclaimed = bool(command.MergePreviousResults == merge_unclaimed)

        cmd._merge_my = command.MergeMyResult
        cmd._merge_to = command.MergeToResult

        # Depending on the peer protocolversion, these fields may not be present.
        for name in ['Error', 'Warning', 'Verbose', 'Debug', 'Information']:
            value = getattr(command, f'Merge{name}', None)
            if value is not None:
                setattr(cmd, f'_merge_{name.lower()}', value)

        return cmd


PipelineType = typing.TypeVar('PipelineType', bound=_PipelineBase)
