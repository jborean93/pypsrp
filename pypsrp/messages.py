# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import struct
import sys
import uuid

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET


class ApartmentState(object):

    STA = 0
    MTA = 1
    UNKNOWN = 2

    @staticmethod
    def pack(reference_map, apartment_state):
        to_string = {
            0: "STA",
            1: "MTA",
            2: "Unknown"
        }[apartment_state]
        types = [
            "System.Threading.ApartmentState",
            "System.Enum",
            "System.ValueType",
            "System.Object"
        ]

        obj = ET.Element("Obj", N="ApartmentState",
                         RefId=reference_map.get_obj_id())
        reference_map.create_tn(obj, types)
        ET.SubElement(obj, "ToString").text = to_string
        ET.SubElement(obj, "I32").text = str(apartment_state)

        return obj


class PipelineResultTypes(object):

    NONE = 0x00
    OUTPUT = 0x01
    ERROR = 0x02
    WARNING = 0x04
    VERBOSE = 0x08
    DEBUG = 0x10
    ALL = 0x20
    NULL = 0x40

    @staticmethod
    def pack(reference_map, pipeline_result_type):
        if pipeline_result_type == 0:
            to_string = "None"
        elif pipeline_result_type == 0x20:
            to_string = "All"
        elif pipeline_result_type == 0x40:
            to_string = "Null"
        else:
            string_map = {
                "None": 0x01,
                "Error": 0x02,
                "Warning": 0x04,
                "Verbose": 0x08,
                "Debug": 0x10,
            }
            values = []
            for name, flag in string_map.items():
                if pipeline_result_type & flag == flag:
                    values.append(name)

            to_string = ", ".join(values)
        types = [
            "System.Management.Automation.Runspaces.PipelineResultTypes",
            "System.Enum",
            "System.ValueType",
            "System.Object"
        ]

        obj = ET.Element("Obj", N="PipelineResultTypes",
                         RefId=reference_map.get_obj_id())
        reference_map.create_tn(obj, types)
        ET.SubElement(obj, "ToString").text = to_string
        ET.SubElement(obj, "I32").text = str(pipeline_result_type)

        return obj


class PSThreadOptions(object):

    DEFAULT = 0
    USE_NEW_THREAD = 1
    REUSE_THREAD = 2
    USE_CURRENT_THREAD = 3

    @staticmethod
    def pack(reference_map, thread_option):
        to_string = {
            0: "Default",
            1: "UseNewThread",
            2: "ReuseThread",
            3: "UseCurrentThread"
        }[thread_option]
        types = [
            "System.Management.Automation.Runspaces.PSThreadOptions",
            "System.Enum",
            "System.ValueType",
            "System.Object"
        ]

        obj = ET.Element("Obj", N="PSThreadOptions",
                         RefId=reference_map.get_obj_id())
        reference_map.create_tn(obj, types)
        ET.SubElement(obj, "ToString").text = to_string
        ET.SubElement(obj, "I32").text = str(thread_option)

        return obj


class RemoteStreamOptions(object):

    ADD_INVOCATION_INFO_TO_ERROR_RECORD = 1
    ADD_INVOCATION_INFO_TO_WARNING_RECORD = 2
    ADD_INVOCATION_INFO_TO_DEBUG_RECORD = 4
    ADD_INVOCATION_INFO_TO_VERBOSE_RECORD = 8
    ADD_INVOCATION_INFO = 15

    @staticmethod
    def pack(reference_map, remote_stream_option):
        if remote_stream_option == 15:
            to_string = "AddInvocationInfo"
        else:
            values = []
            if remote_stream_option & 1 == 1:
                values.append("AddInvocationInfoToErrorRecord")
            if remote_stream_option & 2 == 2:
                values.append("AddInvocationInfoToWarningRecord")
            if remote_stream_option & 4 == 4:
                values.append("AddInvocationInfoToDebugRecord")
            if remote_stream_option & 8 == 8:
                values.append("AddInvocationInfoToVerboseRecord")

            to_string = ", ".join(values)
        types = [
            "System.Management.Automation.RemoteStreamOptions",
            "System.Enum",
            "System.ValueType",
            "System.Object"
        ]

        obj = ET.Element("Obj", N="RemoteStreamOptions",
                         RefId=reference_map.get_obj_id())
        reference_map.create_tn(obj, types)
        ET.SubElement(obj, "ToString").text = to_string
        ET.SubElement(obj, "I32").text = str(remote_stream_option)

        return obj


class PSPrimitiveDictionary(object):

    def __init__(self):
        pass

    def pack(self):
        pass


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


class Color(object):
    """
    [MS-PSRP] 2.2.3.3 Color
    https://msdn.microsoft.com/en-us/library/dd360026.aspx

    Represents a color used in a user interface
    """
    DARK_BLUE = 1
    DARK_GREEN = 2
    DARK_CYAN = 3
    DARK_RED = 4
    DARK_MAGENTA = 5
    DARK_YELLOW = 6
    GRAY = 7
    DARK_GRAY = 8
    BLUE = 9
    GREEN = 10
    CYAN = 11
    RED = 12
    MAGENTA = 13
    YELLOW = 14
    WHITE = 15


class Coordinates(object):

    def __init__(self, x, y):
        """
        [MS-PSRP] 2.2.3.1 Coordinates
        https://msdn.microsoft.com/en-us/library/dd302883.aspx

        :param x: Int that indicates the coordinate on the x-axis
        :param y: Int that indicates the coordinate on the y-axis
        """
        self.x = x
        self.y = y

    def pack(self, reference_map):
        ms = ET.Element("MS")
        ET.SubElement(ms, "S", N="T").text = \
            "System.Management.Automation.Host.Coordinates"

        coordinate = ET.SubElement(ms, "Obj", N="V",
                                   RefId=reference_map.get_obj_id())
        coordinate_ms = ET.SubElement(coordinate, "MS")
        ET.SubElement(coordinate_ms, "I32", N="x").text = str(self.x)
        ET.SubElement(coordinate_ms, "I32", N="y").text = str(self.y)

        return ms


class Size(object):

    def __init__(self, width, height):
        """
        [MS-PSRP] 2.2.3.2 Size
        https://msdn.microsoft.com/en-us/library/dd305083.aspx

        :param width:
        :param height:
        """
        self.width = width
        self.height = height

    def pack(self, reference_map):
        ms = ET.Element("MS")
        ET.SubElement(ms, "S", N="T").text = \
            "System.Management.Automation.Host.Size"

        size = ET.SubElement(ms, "Obj", N="V",
                             RefId=reference_map.get_obj_id())
        size_ms = ET.SubElement(size, "MS")
        ET.SubElement(size_ms, "I32", N="width").text = str(self.width)
        ET.SubElement(size_ms, "I32", N="height").text = str(self.height)

        return ms


class Pipeline(object):

    def __init__(self, is_nested, commands, history,
                 redirect_shell_error_output_pipe):
        """
        [MS-PSRP] 2.2.3.11 Pipeline
        https://msdn.microsoft.com/en-us/library/dd358182.aspx

        :param is_nested:
        :param commands:
        :param history:
        :param redirect_shell_error_output_pipe:
        """
        self.is_nested = is_nested
        self.commands = commands
        self.history = history
        self.redirect_shell_error_output_pipe = \
            redirect_shell_error_output_pipe


class Command(object):

    def __init__(self, cmd, is_script, use_local_scope, merge_my_results,
                 merge_to_results, merge_previous_results, merge_error,
                 merge_warning, merge_verbose, merge_debug, args):
        """
        [MS-PSRP] 2.2.3.12 Command
        https://msdn.microsoft.com/en-us/library/dd339976.aspx

        :param cmd:
        :param is_script:
        :param use_local_scope:
        :param merge_my_results:
        :param merge_to_results:
        :param merge_previous_results:
        :param merge_error:
        :param merge_warning:
        :param merge_verbose:
        :param merge_debug:
        :param args:
        """
        self.cmd = cmd
        self.is_script = is_script
        self.use_local_scope = use_local_scope
        self.merge_my_results = merge_my_results
        self.merge_to_results = merge_to_results
        self.merge_previous_results = merge_previous_results
        self.merge_error = merge_error
        self.merge_warning = merge_warning
        self.merge_verbose = merge_verbose
        self.merge_debug = merge_debug
        self.args = args


class HostInfo(object):

    def __init__(self, foreground_color, background_color, cursor_position,
                 window_position, cursor_size, buffer_size, window_size,
                 max_window_size, max_physical_window_size, window_title):
        """
        [MS-PSRP] 2.2.3.14 HostInfo
        https://msdn.microsoft.com/en-us/library/dd340936.aspx

        :param foreground_color:
        :param background_color:
        :param cursor_position:
        :param window_position:
        :param cursor_size:
        :param buffer_size:
        :param window_size:
        :param max_window_size:
        :param max_physical_window_size:
        :param window_title:
        """
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

    def pack(self, reference_map):
        element = ET.Element("Obj", N="HostInfo",
                             RefId=reference_map.get_obj_id())
        ms = ET.SubElement(element, "MS")

        host_default_data = self._pack_default_data(reference_map)
        ms.append(host_default_data)

        ET.SubElement(ms, "B", N="_isHostNull").text = "false"
        ET.SubElement(ms, "B", N="_isHostUINull").text = "false"
        ET.SubElement(ms, "B", N="_isHostRawUINull").text = "false"
        ET.SubElement(ms, "B", N="_useRunspaceHost").text = "false"

        return element

    def _pack_default_data(self, reference_map):
        host_default_data = [
            self._pack_primitive_type("System.ConsoleColor", "I32",
                                      self.foreground_color),
            self._pack_primitive_type("System.ConsoleColor", "I32",
                                      self.background_color),
            self.cursor_position.pack(reference_map),
            self.window_position.pack(reference_map),
            self._pack_primitive_type("System.Int32", "I32", self.cursor_size),
            self.buffer_size.pack(reference_map),
            self.window_size.pack(reference_map),
            self.max_window_size.pack(reference_map),
            self.max_physical_window_size.pack(reference_map),
            self._pack_primitive_type("System.String", "S", self.window_title)
        ]

        default_data = ET.Element("Obj", N="_hostDefaultData",
                                  RefId=reference_map.get_obj_id())
        ms = ET.SubElement(default_data, "MS")
        data = ET.SubElement(ms, "Obj", N="data",
                             RefId=reference_map.get_obj_id())
        reference_map.create_tn(data, ["System.Collections.Hashtable",
                                       "System.Object"])

        dct = ET.SubElement(data, "DCT")
        counter = 0
        for dict_value in host_default_data:
            en = ET.SubElement(dct, "En")
            ET.SubElement(en, "I32", N="Key").text = str(counter)
            value = ET.SubElement(en, "Obj", N="Value", RefId="0")
            value.append(dict_value)
            counter += 1

        return default_data

    def _pack_primitive_type(self, type_name, element_name, value):
        ms = ET.Element("MS")
        ET.SubElement(ms, "S", N="T").text = type_name
        ET.SubElement(ms, element_name, N="V").text = str(value)
        return ms


class SessionCapability(object):

    MESSAGE_TYPE = MessageType.SESSION_CAPABILITY

    def __init__(self, protocol_version, ps_version, serialization_version,
                 time_zone=None):
        """
        [MS-PSRP] 2.2.2.1 SESSION_CAPABILITY Message
        https://msdn.microsoft.com/en-us/library/dd340636.aspx

        :param protocol_version: The PSRP version
        :param ps_version: The PowerShell version
        :param serialization_version: The serialization version
        :param time_zone: Time Zone information of the host, should be a byte
            string
        """
        self.protocol_version = protocol_version
        self.ps_version = ps_version
        self.serialization_version = serialization_version
        self.time_zone = time_zone

    def pack(self):
        reference_map = ReferenceMap()
        obj = ET.Element("Obj", RefId=str(reference_map.get_obj_id()))
        ms = ET.SubElement(obj, "MS")
        ET.SubElement(ms, "Version",
                      N="protocolversion").text = self.protocol_version
        ET.SubElement(ms, "Version", N="PSVersion").text = self.ps_version
        ET.SubElement(
            ms,
            "Version",
            N="SerializationVersion"
        ).text = self.serialization_version

        if self.time_zone:
            time_zone = ET.SubElement(ms, "BA", N="TimeZone")
            time_zone.text = base64.b64encode(self.time_zone).decode('utf-8')

        return ET.tostring(obj, encoding='utf-8', method='xml')

    @staticmethod
    def unpack(data):
        data = ET.fromstring(data)

        protocol_version = data.find("MS/Version[@N='protocolversion']").text
        ps_version = data.find("MS/Version[@N='PSVersion']").text
        serialization_version = data.find("MS/Version"
                                          "[@N='SerializationVersion']").text
        time_zone = data.find("MS/BA[@N='TimeZone']")
        if time_zone is not None:
            time_zone = base64.b64decode(time_zone.text)

        session_capability = SessionCapability(protocol_version, ps_version,
                                               serialization_version,
                                               time_zone)
        return session_capability


class InitRunspacePool(object):

    MESSAGE_TYPE = MessageType.INIT_RUNSPACEPOOL

    def __init__(self, minimum_runspaces, maximum_runspaces, ps_thread_option,
                 apartment_state, host_info, arguments=None):
        """
        [MS-PSRP] 2.2.2.2 INIT_RUNSPACEPOOL Message
        https://msdn.microsoft.com/en-us/library/dd359645.aspx

        :param minimum_runspaces: The minimum number of Runspaces that should
            exist in the pool, should be greater than 1
        :param maximum_runspaces: The maximum number of Runspaces that should
            exist in the pool, should be greater than 1
        :param ps_thread_option: The PSThreadOption value that defines the
            threading behaviour of the runspace pool
        :param apartment_state: The ApartmentState of the runspace pool
        :param host_info: The HostInfo object that defines the local host the
            runspace is created with
        :param arguments: A PSPrimitiveDictionary object that contains the
            arguments that are sent to the server and stored in the
            $PSSenderInfo variable in the runspace.
        """
        self.minimum_runspaces = minimum_runspaces
        self.maximum_runspaces = maximum_runspaces
        self.ps_thread_option = ps_thread_option
        self.apartment_state = apartment_state
        self.host_info = host_info
        self.arguments = arguments

    def pack(self):
        reference_map = ReferenceMap()

        obj = ET.Element("Obj", RefId=reference_map.get_obj_id())
        ms = ET.SubElement(obj, "MS")
        ET.SubElement(ms, "I32",
                      N="MinRunspaces").text = str(self.minimum_runspaces)
        ET.SubElement(ms, "I32",
                      N="MaxRunspaces").text = str(self.maximum_runspaces)

        ms.append(PSThreadOptions.pack(reference_map, self.ps_thread_option))
        ms.append(ApartmentState.pack(reference_map, self.apartment_state))
        ms.append(self.host_info.pack(reference_map))

        application_arguments = ET.SubElement(ms, "Obj",
                                              N="ApplicationArguments",
                                              RefId="3")
        if self.arguments is not None:
            application_arguments.append(self.arguments.pack())
        else:
            tn = ET.SubElement(application_arguments, "TN", RefId="5")
            ET.SubElement(tn, "T").text = \
                "System.Management.Automation.PSPrimitiveDictionary"
            ET.SubElement(tn, "T").text = "System.Collections.Hashtable"
            ET.SubElement(tn, "T").text = "System.Object"
            ET.SubElement(application_arguments, "DCT")

        return ET.tostring(obj, encoding='utf-8', method='xml')

    @staticmethod
    def unpack(data):
        data = ET.fromstring(data)
        init_runspace_pool = InitRunspacePool(None, None, None, None, None)
        return init_runspace_pool


class RunspacePoolStateMessage(object):

    MESSAGE_TYPE = MessageType.RUNSPACEPOOL_STATE

    def __init__(self, state, error_record=None):
        """
        [MS-PSRP] 2.2.2.9 RUNSPACEPOOL_STATE Message
        https://msdn.microsoft.com/en-us/library/dd303020.aspx

        :param state: The state of the runspace pool
        :param error_record:
        """
        # TODO: support parsing or error_record
        self.state = state

    def pack(self):
        reference_map = ReferenceMap()
        obj = ET.Element("Obj", RefId=reference_map.get_obj_id())
        ms = ET.SubElement(obj, "MS")
        ET.SubElement(ms, "I32", N="RunspaceState").text = str(self.state)

        return ET.tostring(obj, encoding='utf-8', method='xml')

    @staticmethod
    def unpack(data):
        data = ET.fromstring(data)
        state = int(data.find("MS/I32[@N='RunspaceState']").text)
        runspace_pool_state = RunspacePoolStateMessage(state)
        return runspace_pool_state


class CreatePipeline(object):

    MESSAGE_TYPE = MessageType.CREATE_PIPELINE

    def __init__(self, no_input, apartment_state, remote_stream_options,
                 add_to_history, host_info, pipeline, is_nested):
        """
        [MS-PSRP] 2.2.2.10 CREATE_PIPELINE Message
        https://msdn.microsoft.com/en-us/library/dd340567.aspx

        :param no_input:
        :param apartment_state:
        :param remote_stream_options:
        :param add_to_history:
        :param host_info:
        :param pipeline:
        :param is_nested:
        """
        self.no_input = no_input
        self.apartment_state = apartment_state
        self.remote_stream_options = remote_stream_options
        self.add_to_history = add_to_history
        self.host_info = host_info
        self.pipeline = pipeline
        self.is_nested = is_nested


class RunspacePoolHostResponse(object):

    MESSAGE_TYPE = MessageType.RUNSPACEPOOL_HOST_RESPONSE

    def __init__(self, call_id, id, value, error_record=None):
        """
        [MS-PSRP] 2.2.2.16 RUNSPACEPOOL_HOST_RESPONSE Message
        https://msdn.microsoft.com/en-us/library/dd358453.aspx

        :param call_id:
        :param id:
        :param value:
        :param error_record:
        """
        self.call_id = call_id
        self.id = id
        self.value = value
        self.error_record = error_record


class PipelineInput(object):

    MESSAGE_TYPE = MessageType.PIPELINE_INPUT

    def __init__(self, data):
        """
        [MS-PSRP] 2.2.2.17 PIPELINE_INPUT Message
        https://msdn.microsoft.com/en-us/library/dd340525.aspx

        :param data: The input data to send to the pipeline
        """
        self.data = data


class EndOfPipelineInput(object):

    MESSAGE_TYPE = MessageType.END_OF_PIPELINE_INPUT

    def __init__(self):
        """
        [MS-PSRP] 2.2.2.18 END_OF_PIPELINE_INPUT Message
        https://msdn.microsoft.com/en-us/library/dd342785.aspx
        """
        pass


class PipelineState(object):

    MESSAGE_TYPE = MessageType.PIPELINE_STATE

    def __init__(self, state, error_record=None):
        """
        [MS-PSRP] 2.2.2.21 PIPELINE_STATE Message
        https://msdn.microsoft.com/en-us/library/dd304923.aspx

        :param state: The state of the pipeline
        :param error_record:
        """
        self.state = state
        # TODO: work with error_record


class PipelineHostResponse(RunspacePoolHostResponse):

    MESSAGE_TYPE = MessageType.PIPELINE_HOST_RESPONSE


class ReferenceMap(object):

    def __init__(self):
        self.obj_id = 0
        self.tn = {}
        self.tn_id = 0

    def get_obj_id(self):
        ref_id = self.obj_id
        self.obj_id += 1
        return str(ref_id)

    def create_tn(self, parent, types):
        main_type = types[0]
        ref_id = self.tn.get(main_type, None)
        if ref_id is None:
            ref_id = self.tn_id
            self.tn_id += 1
            self.tn[ref_id] = types[0]

            tn = ET.SubElement(parent, "TN", RefId=str(ref_id))
            for type in types:
                ET.SubElement(tn, "T").text = type
        else:
            ET.SubElement(parent, "TNRef", RefId=str(ref_id))


class Message(object):

    def __init__(self, destination, message_type, rpid, pid, data):
        self.destination = destination
        self.message_type = message_type
        self.rpid = rpid or uuid.UUID(bytes=b"\x00" * 16)
        self.pid = pid or uuid.UUID(bytes=b"\x00" * 16)
        self.data = data

    def pack(self):
        data = struct.pack("<I", self.destination)
        data += struct.pack("<I", self.message_type)
        data += self.rpid.bytes
        data += self.pid.bytes
        data += self.data.pack()
        return data

    @staticmethod
    def unpack(data):
        destination = struct.unpack("<I", data[0:4])[0]
        message_type = struct.unpack("<I", data[4:8])[0]
        rpid = uuid.UUID(bytes=data[8:24])
        pid = uuid.UUID(bytes=data[24:40])
        message_data = data[40:]

        message = Message(destination, message_type, rpid, pid, message_data)
        return message
