# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import struct
import sys
import uuid
import warnings

from six import binary_type

from pypsrp.complex_objects import (
    ApartmentState,
    CommandType,
    ComplexObject,
    ErrorRecord,
    GenericComplexObject,
    HostInfo,
    HostMethodIdentifier,
    InformationalRecord,
    ListMeta,
    ObjectMeta,
    Pipeline,
    ProgressRecordType,
    PSArrayList,
    PSObjectArray,
    PSPrimitiveDictionary,
    PSStringArray,
    PSThreadOptions,
    RemoteStreamOptions,
)

from pypsrp.dotnet import (
    NoToString,
    PSBool,
    PSByteArray,
    PSDateTime,
    PSGuid,
    PSInt,
    PSInt64,
    PSObject,
    PSPropertyInfo,
    PSString,
    PSVersion,
)

from pypsrp.exceptions import SerializationError
from pypsrp._utils import to_string


if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)


class Destination(object):
    # The destination of a PSRP message
    CLIENT = 0x00000001
    SERVER = 0x00000002


class MessageType(object):
    """
    [MS-PSRP] 2.2.1 PowerShell Remoting Protocol Message - MessageType
    https://msdn.microsoft.com/en-us/library/dd303832.aspx

    Identifier of the message contained within a PSRP message
    """
    SESSION_CAPABILITY = 0x00010002
    INIT_RUNSPACEPOOL = 0x00010004
    PUBLIC_KEY = 0x00010005
    ENCRYPTED_SESSION_KEY = 0x00010006
    PUBLIC_KEY_REQUEST = 0x00010007
    CONNECT_RUNSPACEPOOL = 0x00010008
    RUNSPACEPOOL_INIT_DATA = 0x002100B
    RESET_RUNSPACE_STATE = 0x0002100C
    SET_MAX_RUNSPACES = 0x00021002
    SET_MIN_RUNSPACES = 0x00021003
    RUNSPACE_AVAILABILITY = 0x00021004
    RUNSPACEPOOL_STATE = 0x00021005
    CREATE_PIPELINE = 0x00021006
    GET_AVAILABLE_RUNSPACES = 0x00021007
    USER_EVENT = 0x00021008
    APPLICATION_PRIVATE_DATA = 0x00021009
    GET_COMMAND_METADATA = 0x0002100A
    RUNSPACEPOOL_HOST_CALL = 0x00021100
    RUNSPACEPOOL_HOST_RESPONSE = 0x00021101
    PIPELINE_INPUT = 0x00041002
    END_OF_PIPELINE_INPUT = 0x00041003
    PIPELINE_OUTPUT = 0x00041004
    ERROR_RECORD = 0x00041005
    PIPELINE_STATE = 0x00041006
    DEBUG_RECORD = 0x00041007
    VERBOSE_RECORD = 0x00041008
    WARNING_RECORD = 0x00041009
    PROGRESS_RECORD = 0x00041010
    INFORMATION_RECORD = 0x00041011
    PIPELINE_HOST_CALL = 0x00041100
    PIPELINE_HOST_RESPONSE = 0x00041101


class Message(object):

    def __init__(self, destination, rpid, pid, data, serializer):
        """
        [MS-PSRP] 2.2.1 PowerShell Remoting Protocol Message
        https://msdn.microsoft.com/en-us/library/dd303832.aspx

        Used to contain a PSRP message in the structure required by PSRP.

        :param destination: The Destination of the message
        :param rpid: The uuid representation of the RunspacePool
        :param pid: The uuid representation of the PowerShell pipeline
        :param data: The PSRP Message object
        :param serializer: The serializer object used to serialize the message
            when packing
        """
        self.destination = destination
        self.message_type = data.MESSAGE_TYPE

        empty_uuid = uuid.UUID(bytes=b"\x00" * 16)
        self.rpid = uuid.UUID(rpid) if rpid is not None else empty_uuid
        self.pid = uuid.UUID(pid) if pid is not None else empty_uuid
        self.data = data
        self._serializer = serializer

    def pack(self):
        if self.message_type == MessageType.PUBLIC_KEY_REQUEST:
            message_data = ET.Element("S")
        elif self.message_type == MessageType.END_OF_PIPELINE_INPUT:
            message_data = b""
        elif self.message_type == MessageType.PIPELINE_INPUT:
            message_data = self._serializer.serialize(self.data.data)
        elif self.message_type == MessageType.CONNECT_RUNSPACEPOOL and \
                (self.data.min_runspaces is None and
                 self.data.max_runspaces is None):
            message_data = ET.Element("S")
        else:
            message_data = self._serializer.serialize(self.data)

        if not isinstance(message_data, binary_type):
            message_data = \
                ET.tostring(message_data, encoding='utf-8', method='xml')
        log.debug("Packing PSRP message: %s" % to_string(message_data))

        data = struct.pack("<I", self.destination)
        data += struct.pack("<I", self.message_type)

        # .NET stores uuids/guids in bytes in the little endian form
        data += self.rpid.bytes_le
        data += self.pid.bytes_le
        data += message_data

        return data

    @staticmethod
    def unpack(data, serializer):
        destination = struct.unpack("<I", data[0:4])[0]
        message_type = struct.unpack("<I", data[4:8])[0]
        rpid = str(uuid.UUID(bytes_le=data[8:24]))
        pid = str(uuid.UUID(bytes_le=data[24:40]))

        if data[40:43] == b"\xEF\xBB\xBF":
            # 40-43 is the UTF-8 BOM which we don't care about
            message_data = to_string(data[43:])
        else:
            message_data = to_string(data[40:])

        log.debug("Unpacking PSRP message of type %d: %s"
                  % (message_type, message_data))

        message_obj = {
            MessageType.SESSION_CAPABILITY: SessionCapability,
            MessageType.INIT_RUNSPACEPOOL: InitRunspacePool,
            MessageType.PUBLIC_KEY: PublicKey,
            MessageType.ENCRYPTED_SESSION_KEY: EncryptedSessionKey,
            MessageType.PUBLIC_KEY_REQUEST: PublicKeyRequest,
            MessageType.SET_MAX_RUNSPACES: SetMaxRunspaces,
            MessageType.SET_MIN_RUNSPACES: SetMinRunspaces,
            MessageType.RUNSPACE_AVAILABILITY: RunspaceAvailability,
            MessageType.RUNSPACEPOOL_STATE: RunspacePoolStateMessage,
            MessageType.CREATE_PIPELINE: CreatePipeline,
            MessageType.GET_AVAILABLE_RUNSPACES: GetAvailableRunspaces,
            MessageType.USER_EVENT: UserEvent,
            MessageType.APPLICATION_PRIVATE_DATA: ApplicationPrivateData,
            MessageType.GET_COMMAND_METADATA: GetCommandMetadata,
            MessageType.RUNSPACEPOOL_HOST_CALL: RunspacePoolHostCall,
            MessageType.RUNSPACEPOOL_HOST_RESPONSE: RunspacePoolHostResponse,
            MessageType.PIPELINE_INPUT: PipelineInput,
            MessageType.END_OF_PIPELINE_INPUT: EndOfPipelineInput,
            MessageType.PIPELINE_OUTPUT: PipelineOutput,
            MessageType.ERROR_RECORD: ErrorRecordMessage,
            MessageType.PIPELINE_STATE: PipelineState,
            MessageType.DEBUG_RECORD: DebugRecord,
            MessageType.VERBOSE_RECORD: VerboseRecord,
            MessageType.WARNING_RECORD: WarningRecord,
            MessageType.PROGRESS_RECORD: ProgressRecord,
            MessageType.INFORMATION_RECORD: InformationRecord,
            MessageType.PIPELINE_HOST_CALL: PipelineHostCall,
            MessageType.PIPELINE_HOST_RESPONSE: PipelineHostResponse,
            MessageType.CONNECT_RUNSPACEPOOL: ConnectRunspacePool,
            MessageType.RUNSPACEPOOL_INIT_DATA: RunspacePoolInitData,
            MessageType.RESET_RUNSPACE_STATE: ResetRunspaceState
        }[message_type]

        # PIPELINE_OUTPUT is a weird one, it contains the actual output objects
        # not encapsulated so we set it to a dynamic object and the serializer
        # will work out what is best
        if message_type == MessageType.PIPELINE_OUTPUT:
            # try to deserialize using our known objects, if that fails then
            # we want to get a generic object at least but raise a warning
            try:
                message_data = serializer.deserialize(message_data)
            except SerializationError as err:
                warnings.warn("Failed to deserialize msg, trying to "
                              "deserialize as generic complex object: %s"
                              % str(err))
                meta = ObjectMeta("ObjDynamic", object=GenericComplexObject)
                message_data = serializer.deserialize(message_data, meta)
            message = PipelineOutput()
            message.data = message_data
        elif message_type == MessageType.PIPELINE_INPUT:
            message_data = serializer.deserialize(message_data)
            message = PipelineInput()
            message.data = message_data
        elif message_type == MessageType.PUBLIC_KEY_REQUEST:
            message = PublicKeyRequest()
        else:
            message_meta = ObjectMeta("Obj", object=message_obj)
            message = serializer.deserialize(message_data, message_meta)

        return Message(destination, rpid, pid, message, serializer)


class SessionCapability(PSObject):
    MESSAGE_TYPE = MessageType.SESSION_CAPABILITY

    def __init__(self, protocol_version=None, ps_version=None, serialization_version=None, time_zone=None):
        """
        [MS-PSRP] 2.2.2.1 SESSION_CAPABILITY Message
        https://msdn.microsoft.com/en-us/library/dd340636.aspx

        :param protocol_version: The PSRP version.
        :param ps_version: The PowerShell version.
        :param serialization_version: The serialization version.
        :param time_zone: Time Zone information of the host, should be a byte string.
        """
        super(SessionCapability, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('protocol_version', clixml_name='protocolversion', ps_type=PSVersion),
            PSPropertyInfo('ps_version', clixml_name='PSVersion', ps_type=PSVersion),
            PSPropertyInfo('serialization_version', clixml_name='SerializationVersion', ps_type=PSVersion),
            PSPropertyInfo('time_zone', clixml_name='TimeZone', optional=True, ps_type=PSByteArray),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.protocol_version = protocol_version
        self.ps_version = ps_version
        self.serialization_version = serialization_version
        self.time_zone = time_zone


class InitRunspacePool(PSObject):
    MESSAGE_TYPE = MessageType.INIT_RUNSPACEPOOL

    def __init__(self, min_runspaces=None, max_runspaces=None, thread_options=None, apartment_state=None,
                 host_info=None, application_arguments=None):
        """
        [MS-PSRP] 2.2.2.2 INIT_RUNSPACEPOOL Message
        https://msdn.microsoft.com/en-us/library/dd359645.aspx

        :param min_runspaces: The minimum number of runspaces in the pool.
        :param max_runspaces: The maximum number of runspaces in the pool.
        :param thread_options: Thread options provided by the higher layer.
        :param apartment_state: Apartment state provided by the higher layer.
        :param host_info: The client's HostInfo details.
        :param application_arguments: Application arguments provided by a higher layer, stored in the $PSSenderInfo
            variable in the pool.
        """
        super(InitRunspacePool, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('min_runspaces', clixml_name='MinRunspaces', ps_type=PSInt),
            PSPropertyInfo('max_runspaces', clixml_name='MaxRunspaces', ps_type=PSInt),
            PSPropertyInfo('thread_options', clixml_name='PSThreadOptions', ps_type=PSThreadOptions),
            PSPropertyInfo('apartment_state', clixml_name='ApartmentState', ps_type=ApartmentState),
            PSPropertyInfo('host_info', clixml_name='HostInfo', ps_type=HostInfo),
            PSPropertyInfo('application_arguments', clixml_name='ApplicationArguments', ps_type=PSPrimitiveDictionary),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.min_runspaces = min_runspaces
        self.max_runspaces = max_runspaces
        self.thread_options = thread_options
        self.apartment_state = apartment_state
        self.host_info = host_info
        self.application_arguments = application_arguments


class PublicKey(PSObject):
    MESSAGE_TYPE = MessageType.PUBLIC_KEY

    def __init__(self, public_key=None):
        """
        [MS-PSRP] 2.2.2.3 PUBLIC_KEY Message
        https://msdn.microsoft.com/en-us/library/dd644859.aspx

        :param public_key: The Base64 encoding of the public key in the PKCS1 format.
        """
        super(PublicKey, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('public_key', clixml_name='PublicKey', ps_type=PSString),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.public_key = public_key


class EncryptedSessionKey(PSObject):
    MESSAGE_TYPE = MessageType.ENCRYPTED_SESSION_KEY

    def __init__(self, session_key=None):
        """
        [MS-PSRP] 2.2.2.4 ENCRYPTED_SESSION_KEY Message
        https://msdn.microsoft.com/en-us/library/dd644930.aspx

        :param session_key: The 256-bit key for AES encryption that has been encrypted using the public key from the
            PUBLIC_KEY message using the RSAES-PKCS-v1_5 encryption scheme and then Base64 formatted.
        """
        super(EncryptedSessionKey, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('session_key', clixml_name='EncryptedSessionKey', ps_type=PSString),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.session_key = session_key


class PublicKeyRequest(PSObject):
    MESSAGE_TYPE = MessageType.PUBLIC_KEY_REQUEST

    def __init__(self):
        """
        [MS-PSRP] 2.2.2.5 PUBLIC_KEY_REQUEST Message
        https://msdn.microsoft.com/en-us/library/dd644906.aspx
        """
        super(PublicKeyRequest, self).__init__()
        self.psobject.to_string = NoToString
        self.psobject.type_names = None


class SetMaxRunspaces(PSObject):
    MESSAGE_TYPE = MessageType.SET_MAX_RUNSPACES

    def __init__(self, max_runspaces=None, ci=None):
        """
        [MS-PSRP] 2.2.2.6 SET_MAX_RUNSPACES Message
        https://msdn.microsoft.com/en-us/library/dd304870.aspx

        :param max_runspaces: The maximum number of runspaces.
        :param ci: The ci identifier for the CI table.
        """
        super(SetMaxRunspaces, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('max_runspaces', clixml_name='MaxRunspaces', ps_type=PSInt),
            PSPropertyInfo('ci', clixml_name='CI', ps_type=PSInt64),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.max_runspaces = max_runspaces
        self.ci = ci


class SetMinRunspaces(PSObject):
    MESSAGE_TYPE = MessageType.SET_MIN_RUNSPACES

    def __init__(self, min_runspaces=None, ci=None):
        """
        [MS-PSRP] 2.2.2.7 SET_MIN_RUNSPACES Message
        https://msdn.microsoft.com/en-us/library/dd340570.aspx

        :param max_runspaces: The minimum number of runspaces.
        :param ci: The ci identifier for the CI table.
        """
        super(SetMinRunspaces, self).__init__()
        self._extended_properties = (
            ('min_runspaces', ObjectMeta("I32", name="MinRunspaces")),
            ('ci', ObjectMeta("I64", name="CI")),
        )
        self.min_runspaces = min_runspaces
        self.ci = ci


class RunspaceAvailability(PSObject):
    MESSAGE_TYPE = MessageType.RUNSPACE_AVAILABILITY

    def __init__(self, response=None, ci=None):
        """
        [MS-PSRP] 2.2.2.8 RUNSPACE_AVAILABILITY Message
        https://msdn.microsoft.com/en-us/library/dd359229.aspx

        :param response: The response from the server
        :param ci: The ci identifier for the CI table
        """
        super(RunspaceAvailability, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('response', clixml_name='SetMinMaxRunspacesResponse'),
            PSPropertyInfo('ci', clixml_name='CI', ps_type=PSInt64),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.response = response
        self.ci = ci


class RunspacePoolStateMessage(PSObject):
    MESSAGE_TYPE = MessageType.RUNSPACEPOOL_STATE

    def __init__(self, state=None, error_record=None):
        """
        [MS-PSRP] 2.2.2.9 RUNSPACEPOOL_STATE Message
        https://msdn.microsoft.com/en-us/library/dd303020.aspx

        :param state: The state of the runspace pool.
        :param error_record: An optional error record with error information.
        """
        super(RunspacePoolStateMessage, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('state', clixml_name='RunspaceState', ps_type=PSInt),
            PSPropertyInfo('error_record', clixml_name='ExceptionAsErrorRecord', ps_type=ErrorRecord),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.state = state
        self.error_record = error_record


class CreatePipeline(PSObject):
    MESSAGE_TYPE = MessageType.CREATE_PIPELINE

    def __init__(self, no_input=None, apartment_state=None, remote_stream_options=None, add_to_history=None,
                 host_info=None, pipeline=None, is_nested=None):
        """
        [MS-PSRP] 2.2.2.10 CREATE_PIPELINE Message
        https://msdn.microsoft.com/en-us/library/dd340567.aspx

        :param no_input: Whether the pipeline will take input.
        :param apartment_state: The ApartmentState of the pipeline.
        :param remote_stream_options: The RemoteStreamOptions of the pipeline.
        :param add_to_history: Whether to add the pipeline being execute to the history field of the runspace.
        :param host_info: The HostInformation of the pipeline.
        :param pipeline: The PowerShell object to create.
        :param is_nested: Whether the pipeline is run in nested or steppable mode.
        """
        super(CreatePipeline, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('no_input', clixml_name='NoInput', ps_type=PSBool),
            PSPropertyInfo('apartment_state', clixml_name='ApartmentState', ps_type=ApartmentState),
            PSPropertyInfo('remote_stream_options', clixml_name='RemoteStreamOptions', ps_type=RemoteStreamOptions),
            PSPropertyInfo('add_to_history', clixml_name='AddToHistory', ps_type=PSBool),
            PSPropertyInfo('host_info', clixml_name='HostInfo', ps_type=HostInfo),
            PSPropertyInfo('pipeline', clixml_name='PowerShell', ps_type=Pipeline),
            PSPropertyInfo('is_nested', clixml_name='IsNested', ps_type=PSBool),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.no_input = no_input
        self.apartment_state = apartment_state
        self.remote_stream_options = remote_stream_options
        self.add_to_history = add_to_history
        self.host_info = host_info
        self.pipeline = pipeline
        self.is_nested = is_nested


class GetAvailableRunspaces(PSObject):
    MESSAGE_TYPE = MessageType.GET_AVAILABLE_RUNSPACES

    def __init__(self, ci=None):
        """
        [MS-PSRP] 2.2.2.11 GET_AVAILABLE_RUNSPACES Message
        https://msdn.microsoft.com/en-us/library/dd357512.aspx

        :param ci: The ci identifier for the CI table
        """
        super(GetAvailableRunspaces, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('ci', ps_type=PSInt64),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.ci = ci


class UserEvent(PSObject):
    MESSAGE_TYPE = MessageType.USER_EVENT

    def __init__(self, event_id=None, source_id=None, time=None, sender=None, args=None, data=None, computer=None,
                 runspace_id=None):
        """
        [MS-PSRP] 2.2.2.12 USER_EVENT Message
        https://msdn.microsoft.com/en-us/library/dd359395.aspx

        :param event_id: Event identifier.
        :param source_id: Source identifier.
        :param time: Time when the event was generated.
        :param sender: Sender of the event.
        :param args: Event arguments.
        :param data: Message data.
        :param computer: Name of the computer where the event was fired.
        :param runspace_id: ID of the runspace.
        """
        super(UserEvent, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('event_id', clixml_name='PSEventArgs.EventIdentifier', ps_type=PSInt),
            PSPropertyInfo('source_id', clixml_name='PSEventArgs.SourceIdentifier', ps_type=PSString),
            PSPropertyInfo('time', clixml_name='PSEventArgs.TimeGenerated', ps_type=PSDateTime),
            PSPropertyInfo('sender', clixml_name='PSEventArgs.Sender'),
            PSPropertyInfo('args', clixml_name='PSEventArgs.SourceArgs'),
            PSPropertyInfo('computer', clixml_name='PSEventArgs.ComputerName'),
            PSPropertyInfo('runspace_id', clixml_name='PSEventArgs.RunspaceId', ps_type=PSGuid),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.event_id = event_id
        self.source_id = source_id
        self.time = time
        self.sender = sender
        self.args = args
        self.data = data
        self.computer = computer
        self.runspace_id = runspace_id


class ApplicationPrivateData(PSObject):
    MESSAGE_TYPE = MessageType.APPLICATION_PRIVATE_DATA

    def __init__(self, data=None):
        """
        [MS-PSRP] 2.2.2.13 APPLICATION_PRIVATE_DATA Message
        https://msdn.microsoft.com/en-us/library/dd644934.aspx

        :param data: A dict that contains data to sent to the PowerShell layer
        """
        super(ApplicationPrivateData, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('data', clixml_name='ApplicationPrivateData', ps_type=PSPrimitiveDictionary),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.data = data


class GetCommandMetadata(PSObject):
    MESSAGE_TYPE = MessageType.GET_COMMAND_METADATA

    def __init__(self, names=None, command_type=None, namespace=None, argument_list=None):
        """
        [MS-PSRP] 2.2.2.14 GET_COMMAND_METADATA Message
        https://msdn.microsoft.com/en-us/library/ee175985.aspx

        :param names: A list of wildcard patterns specifying the command names.
        :param command_type: The command type to lookup.
        :param namespace: Wildcard patterns describing the command namespaces containing the commands that the server
            SHOULD return.
        :param argument_list: Extra arguments passed ot the higher-layer above the PSRP.
        """
        super(GetCommandMetadata, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('names', clixml_name='Name', ps_type=PSStringArray),
            PSPropertyInfo('command_type', clixml_name='CommandType', ps_type=CommandType),
            PSPropertyInfo('namespace', clixml_name='Namespace', ps_type=PSStringArray),
            PSPropertyInfo('argument_list', clixml_name='ArgumentList', ps_type=PSObjectArray),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.names = names
        self.command_type = command_type
        self.namespace = namespace
        self.argument_list = argument_list


class RunspacePoolHostCall(PSObject):
    MESSAGE_TYPE = MessageType.RUNSPACEPOOL_HOST_CALL

    def __init__(self, ci=None, mi=None, mp=None):
        """
        [MS-PSRP] 2.2.2.15 RUNSPACE_HOST_CALL Message
        https://msdn.microsoft.com/en-us/library/dd340830.aspx

        :param ci: The call ID.
        :param mi: The host method identifier.
        :param mp: Parameters for the method.
        """
        super(RunspacePoolHostCall, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('ci', ps_type=PSInt64),
            PSPropertyInfo('mi', ps_type=HostMethodIdentifier),
            PSPropertyInfo('mp', ps_type=PSArrayList),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.ci = ci
        self.mi = mi
        self.mp = mp


class RunspacePoolHostResponse(PSObject):
    MESSAGE_TYPE = MessageType.RUNSPACEPOOL_HOST_RESPONSE

    def __init__(self, ci=None, mi=None, mr=None, me=None):
        """
        [MS-PSRP] 2.2.2.16 RUNSPACEPOOL_HOST_RESPONSE Message
        https://msdn.microsoft.com/en-us/library/dd358453.aspx

        :param ci: The call ID.
        :param mi: The host method ID that the response is coming from.
        :param mr: The return value of the method.
        :param me: Exception thrown by a host method invocation.
        """
        super(RunspacePoolHostResponse, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('ci', ps_type=PSInt64),
            PSPropertyInfo('mi', ps_type=HostMethodIdentifier),
            PSPropertyInfo('mr'),
            PSPropertyInfo('me', ps_type=ErrorRecordMessage, optional=True),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.ci = ci
        self.mi = mi
        self.mr = mr
        self.me = me


class PipelineInput(PSObject):
    MESSAGE_TYPE = MessageType.PIPELINE_INPUT

    def __init__(self, data=None):
        """
        [MS-PSRP] 2.2.2.17 PIPELINE_INPUT Message
        https://msdn.microsoft.com/en-us/library/dd340525.aspx

        :param data: The data to serialize and send as the input
        """
        super(PipelineInput, self).__init__()
        self.data = data


class EndOfPipelineInput(PSObject):
    MESSAGE_TYPE = MessageType.END_OF_PIPELINE_INPUT

    def __init__(self):
        """
        [MS-PSRP] 2.2.2.18 END_OF_PIPELINE_INPUT Message
        https://msdn.microsoft.com/en-us/library/dd342785.aspx
        """
        super(EndOfPipelineInput, self).__init__()


class PipelineOutput(PSObject):
    MESSAGE_TYPE = MessageType.PIPELINE_OUTPUT

    def __init__(self, data=None):
        """
        [MS-PSRP] 2.2.2.19 PIPELINE_OUTPUT Message
        https://msdn.microsoft.com/en-us/library/dd357371.aspx
        """
        super(PipelineOutput, self).__init__()
        self.data = data


class ErrorRecordMessage(ErrorRecord):
    MESSAGE_TYPE = MessageType.ERROR_RECORD

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.2.20 ERROR_RECORD Message
        https://msdn.microsoft.com/en-us/library/dd342423.aspx

        :param kwargs:
        """
        super(ErrorRecordMessage, self).__init__(**kwargs)


class PipelineState(PSObject):
    MESSAGE_TYPE = MessageType.PIPELINE_STATE

    def __init__(self, state=None, error_record=None):
        """
        [MS-PSRP] 2.2.2.21 PIPELINE_STATE Message
        https://msdn.microsoft.com/en-us/library/dd304923.aspx

        :param state: The state of the pipeline
        :param error_record: Optional error information.
        """
        super(PipelineState, self).__init__()
        self._extended_properties = (
            PSPropertyInfo('state', clixml_name='PipelineState', ps_type=PSInt),
            PSPropertyInfo('error_record', clixml_name='ExceptionAsErrorRecord', ps_type=ErrorRecord, optional=True),
        )
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.state = state
        self.error_record = error_record


class DebugRecord(InformationalRecord):
    MESSAGE_TYPE = MessageType.DEBUG_RECORD

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.2.22 DEBUG_RECORD Message
        https://msdn.microsoft.com/en-us/library/dd340758.aspx
        """
        super(DebugRecord, self).__init__(**kwargs)
        self.psobject.type_names.insert(0, "System.Management.Automation.DebugRecord")


class VerboseRecord(InformationalRecord):
    MESSAGE_TYPE = MessageType.VERBOSE_RECORD

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.2.23 VERBOSE_RECORD Message
        https://msdn.microsoft.com/en-us/library/dd342930.aspx
        """
        super(VerboseRecord, self).__init__(**kwargs)
        self.psobject.type_names.insert(0, "System.Management.Automation.VerboseRecord")


class WarningRecord(InformationalRecord):
    MESSAGE_TYPE = MessageType.WARNING_RECORD

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.2.24 WARNING_RECORD Message
        https://msdn.microsoft.com/en-us/library/dd303590.aspx
        """
        super(WarningRecord, self).__init__(**kwargs)
        self.psobject.type_names.insert(0, "System.Management.Automation.WarningRecord")


class ProgressRecord(ComplexObject):
    MESSAGE_TYPE = MessageType.PROGRESS_RECORD

    def __init__(self, activity=None, activity_id=None, description=None,
                 current_operation=None, parent_activity_id=None,
                 percent_complete=None, progress_type=None,
                 seconds_remaining=None):
        """
        [MS-PSRP] 2.2.2.25 PROGRESS_RECORD Message
        https://msdn.microsoft.com/en-us/library/dd340751.aspx

        :param kwargs:
        """
        super(ProgressRecord, self).__init__()
        self._extended_properties = (
            ('activity', ObjectMeta("S", name="Activity")),
            ('activity_id', ObjectMeta("I32", name="ActivityId")),
            ('description', ObjectMeta("S", name="StatusDescription")),
            ('current_operation', ObjectMeta("S", name="CurrentOperation")),
            ('parent_activity_id', ObjectMeta("I32", name="ParentActivityId")),
            ('percent_complete', ObjectMeta("I32", name="PercentComplete")),
            ('progress_type', ObjectMeta("Obj", name="Type",
                                         object=ProgressRecordType)),
            ('seconds_remaining', ObjectMeta("I32", name="SecondsRemaining")),
        )
        self.activity = activity
        self.activity_id = activity_id
        self.description = description
        self.current_operation = current_operation
        self.parent_activity_id = parent_activity_id
        self.percent_complete = percent_complete
        self.progress_type = progress_type
        self.seconds_remaining = seconds_remaining


class InformationRecord(ComplexObject):
    MESSAGE_TYPE = MessageType.INFORMATION_RECORD

    def __init__(self, message_data=None, source=None, time_generated=None,
                 tags=None, user=None, computer=None, pid=None,
                 native_thread_id=None, managed_thread_id=None,
                 write_information_stream=None):
        """
        [MS-PSRP] 2.2.2.26 INFORMATION_RECORD Message
        https://msdn.microsoft.com/en-us/library/mt224023.aspx

        Only used in protocol_version 2.3 and above.

        :param kwargs:
        """
        super(InformationRecord, self).__init__()
        self._types = [
            "System.Management.Automation.InformationRecord",
            "System.Object"
        ]
        self._extended_properties = (
            ('message_data', ObjectMeta(name="MessageData")),
            ('source', ObjectMeta("S", name="Source")),
            ('time_generated', ObjectMeta("DT", name="TimeGenerated")),
            ('tags', ListMeta(name="Tags", list_value_meta=ObjectMeta("S"))),
            ('user', ObjectMeta("S", name="User")),
            ('computer', ObjectMeta("S", name="Computer")),
            ('pid', ObjectMeta("U32", name="ProcessId")),
            ('native_thread_id', ObjectMeta("U32", name="NativeThreadId")),
            ('managed_thread_id', ObjectMeta("U32", name="ManagedThreadId")),
            ('write_information_stream', ObjectMeta(
                "B", name="WriteInformationStream", optional=True
            )),
        )
        self.message_data = message_data
        self.source = source
        self.time_generated = time_generated
        self.tags = tags
        self.user = user
        self.computer = computer
        self.pid = pid
        self.native_thread_id = native_thread_id
        self.managed_thread_id = managed_thread_id
        self.write_information_stream = write_information_stream


class PipelineHostCall(RunspacePoolHostCall):
    MESSAGE_TYPE = MessageType.PIPELINE_HOST_CALL
    """
    [MS-PSRP] 2.2.2.27 PIPELINE_HOST_CALL Message
    https://msdn.microsoft.com/en-us/library/dd356915.aspx
    """


class PipelineHostResponse(RunspacePoolHostResponse):
    MESSAGE_TYPE = MessageType.PIPELINE_HOST_RESPONSE
    """
    [MS-PSRP] 2.2.2.28 PIPELINE_HOST_RESPONSE Message
    https://msdn.microsoft.com/en-us/library/dd306168.aspx
    """


class ConnectRunspacePool(ComplexObject):
    MESSAGE_TYPE = MessageType.CONNECT_RUNSPACEPOOL

    def __init__(self, min_runspaces=None, max_runspaces=None):
        """
        [MS-PSRP] 2.2.2.29 CONNECT_RUNSPACEPOOL Message
        https://msdn.microsoft.com/en-us/library/hh537460.aspx

        :param min_runspaces:
        :param max_runspaces:
        """
        super(ConnectRunspacePool, self).__init__()
        self._extended_properties = (
            ('min_runspaces', ObjectMeta("I32", name="MinRunspaces",
                                         optional=True)),
            ('max_runspaces', ObjectMeta("I32", name="MaxRunspaces",
                                         optional=True)),
        )
        self.min_runspaces = min_runspaces
        self.max_runspaces = max_runspaces


class RunspacePoolInitData(ComplexObject):
    MESSAGE_TYPE = MessageType.RUNSPACEPOOL_INIT_DATA

    def __init__(self, min_runspaces=None, max_runspaces=None):
        """
        [MS-PSRP] 2.2.2.30 RUNSPACEPOOL_INIT_DATA Message
        https://msdn.microsoft.com/en-us/library/hh537788.aspx

        :param min_runspaces:
        :param max_runspaces:
        """
        super(RunspacePoolInitData, self).__init__()
        self._extended_properties = (
            ('min_runspaces', ObjectMeta("I32", name="MinRunspaces")),
            ('max_runspaces', ObjectMeta("I32", name="MaxRunspaces")),
        )
        self.min_runspaces = min_runspaces
        self.max_runspaces = max_runspaces


class ResetRunspaceState(ComplexObject):
    MESSAGE_TYPE = MessageType.RESET_RUNSPACE_STATE

    def __init__(self, ci=None):
        """
        [MS-PSRP] 2.2.2.31 RESET_RUNSPACE_STATE Message
        https://msdn.microsoft.com/en-us/library/mt224027.aspx

        :param ci: The call identifier
        """
        super(ResetRunspaceState, self).__init__()
        self._extended_properties = (
            ('ci', ObjectMeta("I64", name="ci")),
        )
        self.ci = ci
