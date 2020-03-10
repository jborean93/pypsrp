# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from copy import deepcopy

try:
    from queue import Queue
except ImportError:  # pragma: no cover
    from Queue import Queue

from pypsrp.dotnet import (
    NoToString,
    PSBool,
    PSByteArray,
    PSDict,
    PSEnumBase,
    PSInt,
    PSInt64,
    PSList,
    PSObject,
    PSPropertyInfo,
    PSString,
    PSVersion,
)

from pypsrp._utils import (
    to_string,
    version_equal_or_newer,
)


### Deprecated, V1 Serializer ###
class ObjectMeta(object):

    def __init__(self, tag="*", name=None, optional=False, object=None):
        self.tag = tag
        self.name = name
        self.optional = optional
        self.object = object


class ListMeta(ObjectMeta):

    def __init__(self, obj_type="LST", name=None, optional=False,
                 list_value_meta=None, list_types=None):
        super(ListMeta, self).__init__(obj_type, name, optional)

        if list_value_meta is None:
            self.list_value_meta = ObjectMeta()
        else:
            self.list_value_meta = list_value_meta

        if list_types is None:
            self.list_types = [
                "System.Object[]",
                "System.Array",
                "System.Object"
            ]
        else:
            self.list_types = list_types


class StackMeta(ListMeta):

    def __init__(self, name=None, optional=False, list_value_meta=None,
                 list_types=None):
        if list_types is None:
            list_types = [
                "System.Collections.Stack",
                "System.Object"
            ]
        super(StackMeta, self).__init__("STK", name, optional, list_value_meta,
                                        list_types)


class QueueMeta(ListMeta):
    def __init__(self, name=None, optional=False, list_value_meta=None,
                 list_types=None):
        if list_types is None:
            list_types = [
                "System.Collections.Queue",
                "System.Object"
            ]
        super(QueueMeta, self).__init__("QUE", name, optional, list_value_meta,
                                        list_types)


class DictionaryMeta(ObjectMeta):

    def __init__(self, name=None, optional=False, dict_key_meta=None,
                 dict_value_meta=None, dict_types=None):
        super(DictionaryMeta, self).__init__("DCT", name, optional)
        if dict_key_meta is None:
            self.dict_key_meta = ObjectMeta(name="Key")
        else:
            self.dict_key_meta = dict_key_meta

        if dict_value_meta is None:
            self.dict_value_meta = ObjectMeta(name="Value")
        else:
            self.dict_value_meta = dict_value_meta

        if dict_types is None:
            self.dict_types = [
                "System.Collections.Hashtable",
                "System.Object"
            ]
        else:
            self.dict_types = dict_types


class ComplexObject(object):

    def __init__(self):
        self._adapted_properties = ()
        self._extended_properties = ()
        self._property_sets = ()
        self._types = []
        self._to_string = None
        self._xml = None  # only populated on deserialization

    def __str__(self):
        return to_string(self._to_string)


class GenericComplexObject(ComplexObject):

    def __init__(self):
        super(GenericComplexObject, self).__init__()
        self.property_sets = []
        self.extended_properties = {}
        self.adapted_properties = {}
        self.to_string = None
        self.types = []

    def __str__(self):
        return to_string(self.to_string)


class Enum(ComplexObject):

    def __init__(self, enum_type, string_map, **kwargs):
        super(Enum, self).__init__()
        self._types = [
            "System.Enum",
            "System.ValueType",
            "System.Object"
        ]
        if enum_type is not None:
            self._types.insert(0, enum_type)

        self._property_sets = (
            ('value', ObjectMeta("I32")),
        )
        self._string_map = string_map

        self.value = kwargs.get('value')

    @property
    def _to_string(self):
        try:
            return self._string_map[self.value]
        except KeyError as err:
            raise KeyError("%s is not a valid enum value for %s, valid values "
                           "are %s" % (err, self._types[0], self._string_map))

    @_to_string.setter
    def _to_string(self, value):
        pass

### End deprecation ###


# PSRP Complex Objects - https://msdn.microsoft.com/en-us/library/dd302883.aspx
class Coordinates(PSObject):

    def __init__(self, x=None, y=None):
        """
        [MS-PSRP] 2.2.3.1 Coordinates
        https://msdn.microsoft.com/en-us/library/dd302883.aspx

        :param x: The X coordinate (0 is the leftmost column)
        :param y: The Y coordinate (0 is the topmost row)
        """
        super(Coordinates, self).__init__()
        self.psobject.adapted_properties = [
            PSPropertyInfo('x', clixml_name='X', ps_type=PSInt),
            PSPropertyInfo('y', clixml_name='Y', ps_type=PSInt),
        ]
        self.psobject.type_names = [
            "System.Management.Automation.Host.Coordinates",
            "System.ValueType",
            "System.Object"
        ]
        self.psobject.to_string = NoToString

        self.x = x
        self.y = y


class Size(PSObject):

    def __init__(self, width=None, height=None):
        """
        [MS-PSRP] 2.2.3.2 Size
        https://msdn.microsoft.com/en-us/library/dd305083.aspx

        :param width: The width of the size
        :param height: The height of the size
        """
        super(Size, self).__init__()
        self.psobject.adapted_properties = [
            PSPropertyInfo('width', clixml_name='Width', ps_type=PSInt),
            PSPropertyInfo('height', clixml_name='Height', ps_type=PSInt),
        ]
        self.psobject.type_names = [
            "System.Management.Automation.Host.Size",
            "System.ValueType",
            "System.Object"
        ]
        self.psobject.to_string = NoToString

        self.width = width
        self.height = height


class Color(PSEnumBase):
    BLACK = 0
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

    ENUM_MAP = {
        'Black': 0,
        'DarkBlue': 1,
        'DarkGreen': 2,
        'DarkCyan': 3,
        'DarkRed': 4,
        'DarkMagenta': 5,
        'DarkYellow': 6,
        'Gray': 7,
        'DarkGray': 8,
        'Blue': 9,
        'Green': 10,
        'Cyan': 11,
        'Red': 12,
        'Magenta': 13,
        'Yellow': 14,
        'White': 15,
    }

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.3 Color
        https://msdn.microsoft.com/en-us/library/dd360026.aspx

        :param value: The enum value for Color.
        """
        super(Color, self).__init__(value, 'System.ConsoleColor')

    @property  # TODO: deprecate
    def value(self):
        return int(self)


class RunspacePoolState(PSEnumBase):
    BEFORE_OPEN = 0
    OPENING = 1
    OPENED = 2
    CLOSED = 3
    CLOSING = 4
    BROKEN = 5
    NEGOTIATION_SENT = 6
    NEGOTIATION_SUCCEEDED = 7
    CONNECTING = 8
    DISCONNECTED = 9

    ENUM_MAP = {
        'BeforeOpen': 0,
        'Opening': 1,
        'Opened': 2,
        'Closed': 3,
        'Closing': 4,
        'Broken': 5,
        'NegotiationSent': 6,
        'NegotiationSucceeded': 7,
        'Connecting': 8,
        'Disconnected': 9,
    }

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.4 RunspacePoolState
        https://msdn.microsoft.com/en-us/library/dd341723.aspx

        Represents the state of the RunspacePool.

        :param value: The enum value for RunspacePoolState.
        """
        super(RunspacePoolState, self).__init__(value, 'System.Management.Automation.Runspaces.RunspacePoolState')

    @property  # TODO: deprecate
    def state(self):
        return int(self)


class PSInvocationState(PSEnumBase):
    NOT_STARTED = 0
    RUNNING = 1
    STOPPING = 2
    STOPPED = 3
    COMPLETED = 4
    FAILED = 5
    DISCONNECTED = 6

    ENUM_MAP = {
        'NotStarted': 0,
        'Running': 1,
        'Stopping': 2,
        'Stopped': 3,
        'Completed': 4,
        'Failed': 5,
        'Disconnected': 6,
    }

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.5 PSInvocationState
        https://msdn.microsoft.com/en-us/library/dd341651.aspx

        Represents the state of a pipeline invocation.

        :param value: The enum value for PSInvocationState.
        """
        super(PSInvocationState, self).__init__(value, 'System.Management.Automation.PSInvocationState')

    @property  # TODO: deprecate
    def state(self):
        return int(self)


class PSThreadOptions(PSEnumBase):
    DEFAULT = 0
    USE_NEW_THREAD = 1
    REUSE_THREAD = 2
    USE_CURRENT_THREAD = 3

    ENUM_MAP = {
        'Default': 0,
        'UseNewThread': 1,
        'ReuseThread': 2,
        'UseCurrentThread': 3,
    }

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.6 PSThreadOptions
        https://msdn.microsoft.com/en-us/library/dd305678.aspx

        :param value: The enum value for PS Thread Options.
        """
        super(PSThreadOptions, self).__init__(value, 'System.Management.Automation.Runspaces.PSThreadOptions')

    @property  # TODO: deprecate
    def state(self):
        return int(self)


class ApartmentState(PSEnumBase):
    STA = 0
    MTA = 1
    UNKNOWN = 2

    ENUM_MAP = {
        'STA': 0,
        'MTA': 1,
        'Unknown': 2
    }

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.7 ApartmentState
        https://msdn.microsoft.com/en-us/library/dd304257.aspx

        :param value: The enum value for Apartment State.
        """
        super(ApartmentState, self).__init__(value, 'System.Management.Automation.Runspaces.ApartmentState')

    @property  # TODO: deprecate
    def value(self):
        return int(self)


class RemoteStreamOptions(PSEnumBase):
    ADD_INVOCATION_INFO_TO_ERROR_RECORD = 1
    ADD_INVOCATION_INFO_TO_WARNING_RECORD = 2
    ADD_INVOCATION_INFO_TO_DEBUG_RECORD = 4
    ADD_INVOCATION_INFO_TO_VERBOSE_RECORD = 8
    ADD_INVOCATION_INFO = 15

    ENUM_MAP = {
        'AddInvocationInfoToErrorRecord': 1,
        'AddInvocationInfoToWarningRecord': 2,
        'AddInvocationInfoToDebugRecord': 4,
        'AddInvocationInfoToVerboseRecord': 8,
        'AddInvocationInfo': 15,
    }
    IS_FLAGS = True

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.8 RemoteStreamOptions
        https://msdn.microsoft.com/en-us/library/dd303829.aspx

        :param value: The initial RemoteStreamOption to set.
        """
        super(RemoteStreamOptions, self).__init__(value, 'System.Management.Automation.Runspaces.RemoteStreamOptions')

    @property  # TODO: deprecate
    def value(self):
        return int(self)


class Pipeline(PSObject):

    class _ExtraCmds(PSObject):
        def __init__(self, cmds=None):
            # Used to encapsulate ExtraCmds in the structure required
            super(Pipeline._ExtraCmds, self).__init__()
            self.psobject.extended_properties = [
                PSPropertyInfo('cmds', clixml_name='Cmds', ps_type=PSListPSObject),
            ]
            self.psobject.to_string = NoToString
            self.psobject.type_names = None

            self.cmds = cmds

    def __init__(self, is_nested=None, cmds=None, history=None, redirect_err_to_out=None):
        """
        [MS-PSRP] 2.2.3.11 Pipeline
        https://msdn.microsoft.com/en-us/library/dd358182.aspx

        :param is_nested: Whether the pipeline is a nested pipeline.
        :param cmds: List of commands to run.
        :param history: The history string to add to the pipeline.
        :param redirect_err_to_out: Whether to redirect the global error output pipe to the commands error output pipe.
        """
        super(Pipeline, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('is_nested', clixml_name='IsNested', ps_type=PSBool),
            # ExtraCmds isn't in spec but is value and used to send multiple statements.
            PSPropertyInfo('_extra_cmds', clixml_name='ExtraCmds', ps_type=self._ExtraCmds),
            PSPropertyInfo('_cmds', clixml_name='Cmds', ps_type=Command),
            PSPropertyInfo('history', clixml_name='History', ps_type=PSString),
            PSPropertyInfo('redirect_err_to_out', clixml_name='RedirectShellErrorToOutputPipe', ps_type=PSBool),
        ]
        self.psobject.to_string = NoToString

        self.is_nested = is_nested
        self.commands = cmds
        self.history = history
        self.redirect_err_to_out = redirect_err_to_out

    @property
    def _cmds(self):
        # Cmds is always the first statement
        return self._get_statements()[0]

    @_cmds.setter
    def _cmds(self, value):
        # if commands is already set then that means ExtraCmds was present and
        # has already been set
        if self.commands and len(self.commands) > 0:
            return

        # ExtraCmds wasn't present so we need to unpack it
        self.commands = value

    @property
    def _extra_cmds(self):
        statements = self._get_statements()

        # ExtraCmds is only set if we have more than 1 statement, not present
        # if only 1
        if len(statements) < 2:
            return None
        else:
            extra = [self._ExtraCmds(cmds=c) for c in statements]
            return extra

    @_extra_cmds.setter
    def _extra_cmds(self, value):
        # check if extra_cmds was actually set and return if it wasn't
        if value is None:
            return

        commands = []
        for statement in value:
            for command in statement.cmds:
                commands.append(command)
            commands[-1].end_of_statement = True
        self.commands = commands

    def _get_statements(self):
        statements = []
        current_statement = []

        # set the last command to be the end of the statement
        self.commands[-1].end_of_statement = True
        for command in self.commands:
            # need to use deepcopy as the values can be appended to multiple
            # parents and in lxml that removes it from the original parent,
            # whereas this will create a copy of the statement for each parent
            current_statement.append(deepcopy(command))
            if command.end_of_statement:
                statements.append(current_statement)
                current_statement = []

        return statements


class Command(PSObject):

    def __init__(self, protocol_version="2.3", cmd=None, is_script=None, use_local_scope=None, merge_my_result=None,
                 merge_to_result=None, merge_previous=None, merge_error=None, merge_warning=None, merge_verbose=None,
                 merge_debug=None, merge_information=None, args=None, end_of_statement=False):
        """
        [MS-PSRP] 2.2.3.12 Command
        https://msdn.microsoft.com/en-us/library/dd339976.aspx

        :param protocol_version: The negotiated protocol version of the remote host. This determines what merge_*
            objects are added to the serialized xml.
        :param cmd: The cmdlet or script to run.
        :param is_script: Whether cmd is a script or not.
        :param use_local_scope: Use local or global scope to invoke commands.
        :param merge_my_result: Controls the behaviour of what stream to merge to 'merge_to_result'. Only supports NONE
            or ERROR (only used in protocol 2.1).
        :param merge_to_result: Controls the behaviour of where to merge the 'merge_my_result' stream. Only supports
            NONE or OUTPUT (only used in protocol 2.1).
        :param merge_previous: Controls the behaviour of where to merge the previous Output and Error streams that have
            been unclaimed.
        :param merge_error: The merge behaviour of the Error stream.
        :param merge_warning: The merge behaviour of the Warning stream.
        :param merge_verbose: The merge behaviour of the Verbose stream.
        :param merge_debug: The merge behaviour of the Debug stream.
        :param merge_information: The merge behaviour of the Information stream.
        :param args: List of CommandParameters for the cmdlet being invoked.
        :param end_of_statement: Whether this command is the last in the current statement.
        """
        super(Command, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('cmd', clixml_name='Cmd', ps_type=PSString),
            PSPropertyInfo('is_script', clixml_name='IsScript', ps_type=PSBool),
            PSPropertyInfo('use_local_scope', clixml_name='UseLocalScope', ps_type=PSBool),
            PSPropertyInfo('merge_my_result', clixml_name='MergeMyResult', ps_type=PipelineResultTypes),
            PSPropertyInfo('merge_to_result', clixml_name='MergeToResult', ps_type=PipelineResultTypes),
            PSPropertyInfo('merge_previous', clixml_name='MergePreviousResults', ps_type=PipelineResultTypes),
            PSPropertyInfo('args', clixml_name='Args', ps_type=PSListPSObject),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        if version_equal_or_newer(protocol_version, "2.2"):
            self.psobject.extended_properties.extend([
                PSPropertyInfo('merge_error', clixml_name='MergeError', ps_type=PipelineResultTypes, optional=True),
                PSPropertyInfo('merge_warning', clixml_name='MergeWarning', ps_type=PipelineResultTypes,
                               optional=True),
                PSPropertyInfo('merge_verbose', clixml_name='MergeVerbose', ps_type=PipelineResultTypes,
                               optional=True),
                PSPropertyInfo('merge_debug', clixml_name='MergeDebug', ps_type=PipelineResultTypes, optional=True),
            ])

        if version_equal_or_newer(protocol_version, "2.3"):
            self.psobject.extended_properties.extend([
                PSPropertyInfo('merge_information', clixml_name='MergeInformation', ps_type=PipelineResultTypes,
                               optional=True),
            ])

        self.protocol_version = protocol_version
        self.cmd = cmd
        self.is_script = is_script
        self.use_local_scope = use_local_scope

        # valid in all protocols, only really used in 2.1 (PowerShell 2.0)
        is_v2 = protocol_version == "2.2"
        self.merge_my_result = merge_my_result or PipelineResultTypes('None', protocol_version_2=is_v2)
        self.merge_to_result = merge_to_result or PipelineResultTypes('None', protocol_version_2=is_v2)
        self.merge_previous = merge_previous or PipelineResultTypes('None', protocol_version_2=is_v2)

        # only valid for 2.2+ (PowerShell 3.0+)
        self.merge_error = merge_error or PipelineResultTypes('None', protocol_version_2=is_v2)
        self.merge_warning = merge_warning or PipelineResultTypes('None', protocol_version_2=is_v2)
        self.merge_verbose = merge_verbose or PipelineResultTypes('None', protocol_version_2=is_v2)
        self.merge_debug = merge_debug or PipelineResultTypes('None', protocol_version_2=is_v2)

        # only valid for 2.3+ (PowerShell 5.0+)
        self.merge_information = merge_information or PipelineResultTypes('None', protocol_version_2=is_v2)

        self.args = args or []

        # not used in the serialized message but controls how Pipeline is packed (Cmds/ExtraCmds).
        self.end_of_statement = end_of_statement


class CommandParameter(PSObject):

    def __init__(self, name=None, value=None):
        """
        [MS-PSRP] 2.2.3.13 Command Parameter
        https://msdn.microsoft.com/en-us/library/dd359709.aspx

        :param name: The name of the parameter, otherwise None.
        :param value: The value of the parameter, can be any primitive type or Complex Object, Null for no value.
        """
        super(CommandParameter, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('name', clixml_name='N', ps_type=PSString),
            PSPropertyInfo('value', clixml_name='V'),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.name = name
        self.value = value


# The host default data is serialized quite differently from the normal rules
# this contains some sub classes that are specific to the serialized form
class _HostDataDictValue(PSObject):

    def __init__(self, value, value_type, ps_value_type=None):
        super(_HostDataDictValue, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('value_type', clixml_name='T', ps_type=PSString),
            PSPropertyInfo('value', clixml_name='V', ps_type=ps_value_type),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.value_type = value_type
        self.value = value


class _HostDataColor(_HostDataDictValue):
    def __init__(self, color):
        super(_HostDataColor, self).__init__(color.value, 'System.ConsoleColor', ps_value_type=PSInt)


class _HostDataCoordinates(_HostDataDictValue):

    class _Coordinates(PSObject):
        def __init__(self, x, y):
            super(_HostDataCoordinates._Coordinates, self).__init__()
            self.psobject.extended_properties = [
                PSPropertyInfo('x', ps_type=PSInt),
                PSPropertyInfo('y', ps_type=PSInt),
            ]
            self.psobject.to_string = NoToString
            self.psobject.type_names = None

            self.x = x
            self.y = y

    def __init__(self, coordinates):
        super(_HostDataCoordinates, self).__init__(self._Coordinates(coordinates.x, coordinates.y),
                                                   'System.Management.Automation.Host.Coordinates',
                                                   ps_value_type=self._Coordinates)


class _HostDataSize(_HostDataDictValue):

    class _Size(PSObject):
        def __init__(self, width, height):
            super(_HostDataSize._Size, self).__init__()
            self.psobject.extended_properties = [
                PSPropertyInfo('width', ps_type=PSInt),
                PSPropertyInfo('height', ps_type=PSInt),
            ]
            self.psobject.to_string = NoToString
            self.psobject.type_names = None

            self.width = width
            self.height = height

    def __init__(self, size):
        super(_HostDataSize, self).__init__(self._Size(size.width, size.height),
                                            'System.Management.Automation.Host.Size', ps_value_type=self._Size)


class _HostDefaultData(PSObject):

    def __init__(self, raw_ui):
        # Used by HostInfo to encapsulate the host info values inside a special object required by PSRP.
        super(_HostDefaultData, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('_host_dict', 'data', ps_type=PSDict),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.raw_ui = raw_ui

    @property
    def _host_dict(self):
        return (
            (0, _HostDataColor(self.raw_ui.foreground_color)),
            (1, _HostDataColor(self.raw_ui.background_color)),
            (2, _HostDataCoordinates(self.raw_ui.cursor_position)),
            (3, _HostDataCoordinates(self.raw_ui.window_position)),
            (4, _HostDataDictValue(self.raw_ui.cursor_size, 'System.Int32', ps_value_type=PSInt)),
            (5, _HostDataSize(self.raw_ui.buffer_size)),
            (6, _HostDataSize(self.raw_ui.window_size)),
            (7, _HostDataSize(self.raw_ui.max_window_size)),
            (8, _HostDataSize(self.raw_ui.max_physical_window_size)),
            (9, _HostDataDictValue(self.raw_ui.window_title, 'System.String', ps_value_type=PSString)),
        )


class HostInfo(PSObject):

    def __init__(self, host=None):
        """
        [MS-PSRP] 2.2.3.14 HostInfo
        https://msdn.microsoft.com/en-us/library/dd340936.aspx

        :param host: An implementation of pypsrp.host.PSHost that defines the local host.
        """
        super(HostInfo, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('_host_data', clixml_name='_hostDefaultData', ps_type=_HostDefaultData, optional=True),
            PSPropertyInfo('_is_host_null', clixml_name='_isHostNull', ps_type=PSBool),
            PSPropertyInfo('_is_host_ui_null', clixml_name='_isHostUINull', ps_type=PSBool),
            PSPropertyInfo('_is_host_raw_ui_null', clixml_name='_isHostRawUINull', ps_type=PSBool),
            PSPropertyInfo('_use_runspace_host', clixml_name='_use_runspaceHost', ps_type=PSBool),
        ]
        self.psobject.to_string = NoToString
        self.psobject.type_names = None

        self.host = host

    @property
    def _is_host_null(self):
        return self.host is None

    @property
    def _is_host_ui_null(self):
        if self.host is not None:
            return self.host.ui is None
        else:
            return True

    @property
    def _is_host_raw_ui_null(self):
        if self.host is not None and self.host.ui is not None:
            return self.host.ui.raw_ui is None
        else:
            return True

    @property
    def _use_runspace_host(self):
        return self.host is None

    @property
    def _host_data(self):
        if self._is_host_raw_ui_null:
            return None
        else:
            host_data = _HostDefaultData(raw_ui=self.host.ui.raw_ui)
            return host_data


class ErrorRecord(PSObject):

    def __init__(self, exception=None, target_object=None, invocation_info=None, fq_error=None, category=None,
                 activity=None, reason=None, target_name=None, target_type=None, message=None, details_message=None,
                 action=None, script_stacktrace=None, extended_info_present=None, invocation_name=None,
                 invocation_bound_parameters=None, invocation_unbound_arguments=None, invocation_command_origin=None,
                 invocation_expecting_input=None, invocation_line=None, invocation_offset_in_line=None,
                 invocation_position_message=None, invocation_script_name=None, invocation_script_line_number=None,
                 invocation_history_id=None, invocation_pipeline_length=None, invocation_pipeline_position=None,
                 invocation_pipeline_iteration_info=None, command_type=None, command_definition=None,
                 command_name=None, command_visibility=None, pipeline_iteration_info=None):
        """
        [MS-PSRP] 2.2.3.15 ErrorRecord
        https://msdn.microsoft.com/en-us/library/dd340106.aspx
        """
        super(ErrorRecord, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('exception', clixml_name='Exception', optional=True),
            PSPropertyInfo('target_object', clixml_name='TargetObject', optional=True),
            PSPropertyInfo('invocation', clixml_name='SerializeExtendedInfo', ps_type=PSBool, optional=True),
            PSPropertyInfo('invocation_info', clixml_name='InvocationInfo', optional=True),
            PSPropertyInfo('fq_error', clixml_name='FullyQualifiedErrorId', ps_type=PSString),
            PSPropertyInfo('category', clixml_name='ErrorCategory_Category', ps_type=PSInt),
            PSPropertyInfo('activity', clixml_name='ErrorCategory_Activity', ps_type=PSString, optional=True),
            PSPropertyInfo('reason', clixml_name='ErrorCategory_Reason', ps_type=PSString, optional=True),
            PSPropertyInfo('target_name', clixml_name='ErrorCategory_TargetName', ps_type=PSString, optional=True),
            PSPropertyInfo('target_type', clixml_name='ErrorCategory_TargetType', ps_type=PSString, optional=True),
            PSPropertyInfo('message', clixml_name='ErrorCategory_Message', ps_type=PSString, optional=True),
            PSPropertyInfo('details_message', clixml_name='ErrorDetails_Message', ps_type=PSString, optional=True),
            PSPropertyInfo('action', clixml_name='ErrorDetails_RecommendedAction', ps_type=PSString, optional=True),
            PSPropertyInfo('script_stacktrace', clixml_name='ErrorDetails_ScriptStackTrace', ps_type=PSString,
                           optional=True),
            PSPropertyInfo('extended_info_present', clixml_name='SerializeExtendedInfo', ps_type=PSBool),
            PSPropertyInfo('invocation_name', clixml_name='InvocationInfo_InvocationName', ps_type=PSString,
                           optional=True),
            PSPropertyInfo('invocation_bound_parameters', clixml_name='InvocationInfo_BoundParameters',
                           ps_type=PSBoundParametersDictionary, optional=True),
            PSPropertyInfo('invocation_unbound_arguments', clixml_name='InvocationInfo_UnboundArguments',
                           ps_type=PSList, optional=True),
            PSPropertyInfo('invocation_command_origin', clixml_name='InvocationInfo_CommandOrigin',
                           ps_type=CommandOrigin, optional=True),
            PSPropertyInfo('invocation_expecting_input', clixml_name='InvocationInfo_ExpectingInput', ps_type=PSBool,
                           optional=True),
            PSPropertyInfo('invocation_line', clixml_name='InvocationInfo_Line', ps_type=PSString, optional=True),
            PSPropertyInfo('invocation_offset_in_line', clixml_name='InvocationInfo_OffsetInLine', ps_type=PSInt,
                           optional=True),
            PSPropertyInfo('invocation_position_message', clixml_name='InvocationInfo_PositionMessage',
                           ps_type=PSString, optional=True),
            PSPropertyInfo('invocation_script_name', clixml_name='InvocationInfo_ScriptName', ps_type=PSString,
                           optional=True),
            PSPropertyInfo('invocation_script_line_number', clixml_name='InvocationInfo_ScriptLineNumber',
                           ps_type=PSInt, optional=True),
            PSPropertyInfo('invocation_history_id', clixml_name='InvocationInfo_HistoryId', ps_type=PSInt64,
                           optional=True),
            PSPropertyInfo('invocation_pipeline_length', clixml_name='InvocationInfo_PipelineLength', ps_type=PSInt,
                           optional=True),
            PSPropertyInfo('invocation_pipeline_position', clixml_name='InvocationInfo_PipelinePosition',
                           ps_type=PSInt, optional=True),
            PSPropertyInfo('invocation_pipeline_iteration_info', clixml_name='InvocationInfo_PipelineIterationInfo',
                           ps_type=PSIntArray, optional=True),
            PSPropertyInfo('command_type', clixml_name='CommandInfo_CommandType', ps_type=CommandType, optional=True),
            PSPropertyInfo('command_definition', clixml_name='CommandInfo_Definition', ps_type=PSString, optional=True),
            PSPropertyInfo('command_name', clixml_name='CommandInfo_Name', ps_type=PSString, optional=True),
            PSPropertyInfo('command_visibility', clixml_name='CommandInfo_Visibility',
                           ps_type=SessionStateEntryVisibility, optional=True),
            PSPropertyInfo('pipeline_iteration_info', clixml_name='PipelineIterationInfo',
                           ps_type=PSObjectModelReadOnlyCollectionInt, optional=True),
        ]
        self.psobject.type_names = [
            'System.Management.Automation.ErrorRecord',
            'System.Object',
        ]

        self.exception = exception
        self.target_info = target_object
        self.invocation = False
        self.invocation_info = invocation_info
        self.fq_error = fq_error
        self.category = category
        self.activity = activity
        self.reason = reason
        self.target_name = target_name
        self.target_type = target_type
        self.message = message
        self.details_message = details_message
        self.action = action
        self.script_stacktrace = script_stacktrace
        self.extended_info_present = extended_info_present
        self.pipeline_iteration_info = pipeline_iteration_info
        self.invocation_name = invocation_name
        self.invocation_bound_parameters = invocation_bound_parameters
        self.invocation_unbound_arguments = invocation_unbound_arguments
        self.invocation_command_origin = invocation_command_origin
        self.invocation_expecting_input = invocation_expecting_input
        self.invocation_line = invocation_line
        self.invocation_offset_in_line = invocation_offset_in_line
        self.invocation_position_message = invocation_position_message
        self.invocation_script_name = invocation_script_name
        self.invocation_script_line_number = invocation_script_line_number
        self.invocation_history_id = invocation_history_id
        self.invocation_pipeline_length = invocation_pipeline_length
        self.invocation_pipeline_position = invocation_pipeline_position
        self.invocation_pipeline_iteration_info = invocation_pipeline_iteration_info
        self.command_type = command_type
        self.command_definition = command_definition
        self.command_name = command_name
        self.command_visibility = command_visibility
        self.extended_info_present = self.invocation is not None


class InformationalRecord(PSObject):

    def __init__(self, message=None, invocation_name=None, invocation_bound_parameters=None,
                 invocation_unbound_arguments=None, invocation_command_origin=None, invocation_expecting_input=None,
                 invocation_line=None, invocation_offset_in_line=None, invocation_position_message=None,
                 invocation_script_name=None, invocation_script_line_number=None, invocation_history_id=None,
                 invocation_pipeline_length=None, invocation_pipeline_position=None,
                 invocation_pipeline_iteration_info=None, command_type=None, command_definition=None,
                 command_name=None, command_visibility=None, pipeline_iteration_info=None):
        """
        [MS-PSRP] 2.2.3.16 InformationalRecord (Debug/Warning/Verbose)
        https://msdn.microsoft.com/en-us/library/dd305072.aspx
        """
        super(InformationalRecord, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('message', clixml_name='InformationalRecord_Message', ps_type=PSString),
            PSPropertyInfo('invocation', clixml_name='InformationalRecord_SerializeInvocationInfo', ps_type=PSBool),
            PSPropertyInfo('invocation_name', clixml_name='InvocationInfo_InvocationName', ps_type=PSString,
                           optional=True),
            PSPropertyInfo('invocation_bound_parameters', clixml_name='InvocationInfo_BoundParameters',
                           ps_type=PSBoundParametersDictionary, optional=True),
            PSPropertyInfo('invocation_unbound_arguments', clixml_name='InvocationInfo_UnboundArguments',
                           ps_type=PSList, optional=True),
            PSPropertyInfo('invocation_command_origin', clixml_name='InvocationInfo_CommandOrigin',
                           ps_type=CommandOrigin, optional=True),
            PSPropertyInfo('invocation_expecting_input', clixml_name='InvocationInfo_ExpectingInput', ps_type=PSBool,
                           optional=True),
            PSPropertyInfo('invocation_line', clixml_name='InvocationInfo_Line', ps_type=PSString, optional=True),
            PSPropertyInfo('invocation_offset_in_line', clixml_name='InvocationInfo_OffsetInLine', ps_type=PSInt,
                           optional=True),
            PSPropertyInfo('invocation_position_message', clixml_name='InvocationInfo_PositionMessage',
                           ps_type=PSString, optional=True),
            PSPropertyInfo('invocation_script_name', clixml_name='InvocationInfo_ScriptName', ps_type=PSString,
                           optional=True),
            PSPropertyInfo('invocation_script_line_number', clixml_name='InvocationInfo_ScriptLineNumber',
                           ps_type=PSInt, optional=True),
            PSPropertyInfo('invocation_history_id', clixml_name='InvocationInfo_HistoryId', ps_type=PSInt64,
                           optional=True),
            PSPropertyInfo('invocation_pipeline_length', clixml_name='InvocationInfo_PipelineLength', ps_type=PSInt,
                           optional=True),
            PSPropertyInfo('invocation_pipeline_position', clixml_name='InvocationInfo_PipelinePosition',
                           ps_type=PSInt, optional=True),
            PSPropertyInfo('invocation_pipeline_iteration_info', clixml_name='InvocationInfo_PipelineIterationInfo',
                           ps_type=PSIntArray, optional=True),
            PSPropertyInfo('command_type', clixml_name='CommandInfo_CommandType', ps_type=CommandType, optional=True),
            PSPropertyInfo('command_definition', clixml_name='CommandInfo_Definition', ps_type=PSString,
                           optional=True),
            PSPropertyInfo('command_name', clixml_name='CommandInfo_Name', ps_type=PSString, optional=True),
            PSPropertyInfo('command_visibility', clixml_name='CommandInfo_Visibility',
                           ps_type=SessionStateEntryVisibility, optional=True),
            PSPropertyInfo('pipeline_iteration_info', clixml_name='InformationalRecord_PipelineIterationInfo',
                           ps_type=PSObjectModelReadOnlyCollectionInt, optional=True),
        ]
        self.psobject.type_names = [
            'System.Management.Automation.InformationRecord',
            'System.Object',
        ]

        self.message = message
        self.invocation = False
        self.invocation_name = invocation_name
        self.invocation_bound_parameters = invocation_bound_parameters
        self.invocation_unbound_arguments = invocation_unbound_arguments
        self.invocation_command_origin = invocation_command_origin
        self.invocation_expecting_input = invocation_expecting_input
        self.invocation_line = invocation_line
        self.invocation_offset_in_line = invocation_offset_in_line
        self.invocation_position_message = invocation_position_message
        self.invocation_script_name = invocation_script_name
        self.invocation_script_line_number = invocation_script_line_number
        self.invocation_history_id = invocation_history_id
        self.invocation_pipeline_length = invocation_pipeline_length
        self.invocation_pipeline_position = invocation_pipeline_position
        self.invocation_pipeline_iteration_info = invocation_pipeline_iteration_info
        self.command_type = command_type
        self.command_definition = command_definition
        self.command_name = command_name
        self.command_visibility = command_visibility
        self.pipeline_iteration_info = pipeline_iteration_info


class HostMethodIdentifier(PSEnumBase):
    
    ENUM_MAP = {
        'GetName': 1,
        'GetVersion': 2,
        'GetInstanceId': 3,
        'GetCurrentCulture': 4,
        'GetCurrentUICulture': 5,
        'SetShouldExit': 6,
        'EnterNestedPrompt': 7,
        'ExitNestedPrompt': 8,
        'NotifyBeginApplication': 9,
        'NotifyEndApplication': 10,
        'ReadLine': 11,
        'ReadLineAsSecureString': 12,
        'Write1': 13,
        'Write2': 14,
        'WriteLine1': 15,
        'WriteLine2': 16,
        'WriteLine3': 17,
        'WriteErrorLine': 18,
        'WriteDebugLine': 19,
        'WriteProgress': 20,
        'WriteVerboseLine': 21,
        'WriteWarningLine': 22,
        'Prompt': 23,
        'PromptForCredential1': 24,
        'PromptForCredential2': 25,
        'PromptForChoice': 26,
        'GetForegroundColor': 27,
        'SetForegroundColor': 28,
        'GetBackgroundColor': 29,
        'SetBackgroundColor': 30,
        'GetCursorPosition': 31,
        'SetCursorPosition': 32,
        'GetWindowPosition': 33,
        'SetWindowPosition': 34,
        'GetCursorSize': 35,
        'SetCursorSize': 36,
        'GetBufferSize': 37,
        'SetBufferSize': 38,
        'GetWindowSize': 39,
        'SetWindowSize': 40,
        'GetWindowTitle': 41,
        'SetWindowTitle': 42,
        'GetMaxWindowSize': 43,
        'GetMaxPhysicalWindowSize': 44,
        'GetKeyAvailable': 45,
        'ReadKey': 46,
        'FlushInputBuffer': 47,
        'SetBufferContents1': 48,
        'SetBufferContents2': 49,
        'GetBufferContents': 50,
        'ScrollBufferContents': 51,
        'PushRunspace': 52,
        'PopRunspace': 53,
        'GetIsRunspacePushed': 54,
        'GetRunspce': 55,
        'PromptForChoiceMultipleSelection': 56,
    }

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.17 Host Method Identifier
        https://msdn.microsoft.com/en-us/library/dd306624.aspx

        Represents methods to be executed on a host.

        :param value: The method identifier to execute
        """
        super(HostMethodIdentifier, self).__init__(value, 'System.Management.Automation.Remoting.RemoteHostMethodId')


class CommandType(PSEnumBase):
    ALIAS = 0x0001
    FUNCTION = 0x0002
    FILTER = 0x0004
    CMDLET = 0x0008
    EXTERNAL_SCRIPT = 0x0010
    APPLICATION = 0x0020
    SCRIPT = 0x0040
    WORKFLOW = 0x0080
    CONFIGURATION = 0x0100
    ALL = 0x01FF

    ENUM_MAP = {
        'Alias': 0x0001,
        'Function': 0x0002,
        'Filter': 0x0004,
        'Cmdlet': 0x0008,
        'ExternalScript': 0x0010,
        'Application': 0x0020,
        'Script': 0x0040,
        'Workflow': 0x0080,
        'Configuration': 0x0100,
        'All': 0x01FF,
    }
    IS_FLAGS = True

    def __init__(self, value):
        """
        [MS-PSRP] 2.2.3.19 CommandType
        https://msdn.microsoft.com/en-us/library/ee175965.aspx

        :param value: The initial flag value for CommandType
        """
        super(CommandType, self).__init__(value, 'System.Management.Automation.CommandTypes')


class CommandMetadataCount(PSObject):

    def __init__(self, count=None):
        """
        [MS-PSRP] 2.2.3.21 CommandMetadataCount
        https://msdn.microsoft.com/en-us/library/ee175881.aspx

        :param count: The number of CommandMetadata messages in the pipeline output.
        """
        super(CommandMetadataCount, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('count', clixml_name='Count', ps_type=PSInt),
        ]
        self.psobject.type_names = [
            'Selected.Microsoft.PowerShell.Commands.GenericMeasureInfo',
            'System.Management.Automation.PSCustomObject',
            'System.Object',
        ]
        self.psobject.to_string = NoToString

        self.count = count


class CommandMetadata(PSObject):

    def __init__(self, name=None, namespace=None, help_url=None, command_type=None, output_type=None, parameters=None):
        """
        [MS-PSRP] 2.2.3.22 CommandMetadata
        https://msdn.microsoft.com/en-us/library/ee175993.aspx

        :param name: The name of a command
        :param namespace: The namespace of the command
        :param help_uri: The URI to the documentation of the command
        :param command_type: The CommandType of the command
        :param output_type: The types of objects that a command can send as
            output
        :param parameters: Metadata of parameters that the command can accept
            as Command Parameters
        """
        super(CommandMetadata, self).__init__()
        self.psobject.extended_properties = [
            PSPropertyInfo('name', clixml_name='Name', ps_type=PSString),
            PSPropertyInfo('namespace', clixml_name='Namespace', ps_type=PSString),
            PSPropertyInfo('help_uri', clixml_name='HelpUri', ps_type=PSString),
            PSPropertyInfo('command_type', clixml_name='CommandType', ps_type=CommandType),
            PSPropertyInfo('output_type', clixml_name='OutputType', ps_type=PSObjectModelReadOnlyCollectionPSTypeName),
            PSPropertyInfo('parameters', clixml_name='Parameters', ps_type=ParameterMetadata)
        ]
        self.psobject.type_names = [
            'System.Management.Automation.PSCustomObject',
            'System.Object',
        ]
        self.psobject.to_string = NoToString
        self._extended_properties = (
            ('name', ObjectMeta("S", name="Name")),
            ('namespace', ObjectMeta("S", name="Namespace")),
            ('help_uri', ObjectMeta("S", name="HelpUri")),
            ('command_type', ObjectMeta("Obj", name="CommandType",
                                        object=CommandType)),
            ('output_type', ListMeta(
                name="OutputType",
                list_value_meta=ObjectMeta("S"),
                list_types=[
                    "System.Collections.ObjectModel.ReadOnlyCollection`1[["
                    "System.Management.Automation.PSTypeName, "
                    "System.Management.Automation, Version=3.0.0.0, "
                    "Culture=neutral, PublicKeyToken=31bf3856ad364e35]]",
                ]
            )),
            ('parameters', DictionaryMeta(
                name="Parameters",
                dict_key_meta=ObjectMeta("S"),
                dict_value_meta=ObjectMeta("Obj", object=ParameterMetadata))
             ),
        )
        self.name = name
        self.namespace = namespace
        self.help_uri = help_url
        self.command_type = command_type
        self.output_type = output_type
        self.parameters = parameters


class ParameterMetadata(ComplexObject):

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.3.23 ParameterMetadata
        https://msdn.microsoft.com/en-us/library/ee175918.aspx

        :param name: The name of a parameter
        :param parameter_type: The type of the parameter
        :param alises: List of alternative names of the parameter
        :param switch_parameter: True if param is a switch parameter
        :param dynamic: True if param is included as a consequence of the data
            specified in the ArgumentList property
        """
        super(ParameterMetadata, self).__init__()
        self.types = [
            "System.Management.Automation.ParameterMetadata",
            "System.Object"
        ]
        self._adapted_properties = (
            ('name', ObjectMeta("S", name="Name")),
            ('parameter_type', ObjectMeta("S", name="ParameterType")),
            ('aliases', ListMeta(
                name="Aliases",
                list_value_meta=ObjectMeta("S"),
                list_types=[
                    "System.Collections.ObjectModel.Collection`1"
                    "[[System.String, mscorlib, Version=4.0.0.0, "
                    "Culture=neutral, PublicKeyToken=b77a5c561934e089]]",
                    "System.Object"
                ])
             ),
            ('switch_parameter', ObjectMeta("B", name="SwitchParameter")),
            ('dynamic', ObjectMeta("B", name="IsDynamic")),
        )
        self.name = kwargs.get('name')
        self.parameter_type = kwargs.get('parameter_type')
        self.aliases = kwargs.get('aliases')
        self.switch_parameter = kwargs.get('switch_parameter')
        self.dynamic = kwargs.get('dynamic')


class PSCredential(ComplexObject):

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.3.25 PSCredential
        https://msdn.microsoft.com/en-us/library/ee442231.aspx

        Represents a username and a password. As the password is a secure
        string, the RunspacePool must have already exchanged keys with
        .exchange_keys() method.

        :param username: The username (including the domain if required)
        :param password: The password for the user, this should be a unicode
            string in order to make sure the encoding is correct
        """
        super(PSCredential, self).__init__()
        self._types = [
            "System.Management.Automation.PSCredential",
            "System.Object"
        ]
        self._adapted_properties = (
            ('username', ObjectMeta("S", name="UserName")),
            ('password', ObjectMeta("SS", name="Password")),
        )
        self._to_string = "System.Management.Automation.PSCredential"

        self.username = kwargs.get('username')
        self.password = kwargs.get('password')


class KeyInfo(ComplexObject):

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.3.26 KeyInfo
        https://msdn.microsoft.com/en-us/library/ee441795.aspx

        Represents information about a keyboard event, this is used for the
        serialized of a ReadKey host method and is not the same as the
        serialized form of KeyInfo in .NET (see KeyInfoDotNet).

        :param code: The int value for the virtual key code
        :param character: The character
        :param state: The ControlKeyState int value
        :param key_down: Whether the key is pressed or released
        """
        super(KeyInfo, self).__init__()
        self._extended_properties = (
            ('code', ObjectMeta("I32", name="virtualKeyCode", optional=True)),
            ('character', ObjectMeta("C", name="character")),
            ('state', ObjectMeta("I32", name="controlKeyState")),
            ('key_down', ObjectMeta("B", name="keyDown")),
        )
        self.code = kwargs.get('code')
        self.character = kwargs.get('character')
        self.state = kwargs.get('state')
        self.key_down = kwargs.get('key_down')


class KeyInfoDotNet(ComplexObject):

    def __init__(self, **kwargs):
        """
        System.Management.Automation.Host.KeyInfo
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.keyinfo

        This is the proper serialized form of KeyInfo from .NET, it is
        returned in a PipelineOutput message.

        :param code: The int value for the virtual key code
        :param character: The character
        :param state: The ControlKeyState as a string value
        :param key_down: Whether the key is pressed or released
        """
        super(KeyInfoDotNet, self).__init__()
        self._types = [
            "System.Management.Automation.Host.KeyInfo",
            "System.ValueType",
            "System.Object"
        ]
        self._adapted_properties = (
            ('code', ObjectMeta("I32", name="VirtualKeyCode")),
            ('character', ObjectMeta("C", name="Character")),
            ('state', ObjectMeta("S", name="ControlKeyState")),
            ('key_down', ObjectMeta("B", name="KeyDown")),
        )
        self.code = kwargs.get('code')
        self.character = kwargs.get('character')
        self.state = kwargs.get('state')
        self.key_down = kwargs.get('key_down')


class ControlKeyState(object):
    """
    [MS-PSRP] 2.2.3.27 ControlKeyStates
    https://msdn.microsoft.com/en-us/library/ee442685.aspx
    https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.controlkeystates

    A set of zero or more control keys that are help down.
    """
    RightAltPressed = 0x0001
    LeftAltPressed = 0x0002
    RightCtrlPressed = 0x0004
    LeftCtrlPressed = 0x0008
    ShiftPressed = 0x0010
    NumLockOn = 0x0020
    ScrollLockOn = 0x0040
    CapsLockOn = 0x0080
    EnhancedKey = 0x0100


class BufferCell(ComplexObject):

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.3.28 BufferCell
        https://msdn.microsoft.com/en-us/library/ee443291.aspx

        The contents of a cell of a host's screen buffer.

        :param character: The chracter visibile in the cell
        :param foreground_color: The Color of the foreground
        :param background_color: The Color of the background
        :param cell_type: The int value of BufferCellType
        """
        super(BufferCell, self).__init__()
        self._adapted_properties = (
            ('character', ObjectMeta("C", name="character")),
            ('foreground_color', ObjectMeta("Obj", name="foregroundColor",
                                            object=Color)),
            ('background_color', ObjectMeta("Obj", name="backgroundColor",
                                            object=Color)),
            ('cell_type', ObjectMeta("I32", name="bufferCellType")),
        )
        self.character = kwargs.get('character')
        self.foreground_color = kwargs.get('foreground_color')
        self.background_color = kwargs.get('background_color')
        self.cell_type = kwargs.get('cell_type')


class BufferCellType(object):
    """
    [MS-PSRP] 2.2.3.29 BufferCellType
    https://msdn.microsoft.com/en-us/library/ee442184.aspx

    The type of a cell of a screen buffer.
    """
    COMPLETE = 0
    LEADING = 1
    TRAILING = 2


class Array(ComplexObject):

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.6.1.4 Array
        https://msdn.microsoft.com/en-us/library/dd340684.aspx

        Represents a (potentially multi-dimensional) array of elements.

        :param array: The array (list) that needs to be serialised. This can
            be a multidimensional array (lists in a list)
        """
        super(Array, self).__init__()
        self._extended_properties = (
            ('mae', ListMeta(name="mae")),
            ('mal', ListMeta(name="mal", list_value_meta=ObjectMeta("I32"))),
        )
        self._array = None
        self._mae = None
        self._mal = None
        self._array = kwargs.get('array')

    @property
    def array(self):
        if self._array is None:
            self._array = self._build_array(self._mae, self._mal)

        return self._array

    @array.setter
    def array(self, value):
        self._array = value

    @property
    def mae(self):
        # elements of the array are flattened into a list and ordered by first
        # listing the deepest elements
        mae = self._get_list_entries(self._array)
        return mae

    @mae.setter
    def mae(self, value):
        self._mae = value

    @property
    def mal(self):
        mal = self._get_list_count(self.array)
        return mal

    @mal.setter
    def mal(self, value):
        self._mal = value

    def _build_array(self, mae, mal):
        values = []

        length = mal.pop(-1)
        while True:
            entry = []
            for i in range(0, length):
                entry.append(mae.pop(0))
            values.append(entry)
            if len(mae) == 0:
                break

        if len(mal) == 0:
            values = values[0]
        elif len(mal) > 1:
            values = self._build_array(values, mal)

        return values

    def _get_list_entries(self, list_value):
        values = []
        for value in list_value:
            if isinstance(value, list):
                values.extend(self._get_list_entries(value))
            else:
                values.append(value)

        return values

    def _get_list_count(self, list_value):
        count = []

        current_entry = list_value
        while True:
            if isinstance(current_entry, list):
                count.append(len(current_entry))
                current_entry = current_entry[0]
            else:
                break

        return count


class CommandOrigin(Enum):
    RUNSPACE = 0
    INTERNAL = 1

    def __init__(self, **kwargs):
        """
        [MS-PSRP] 2.2.2.30 CommandOrigin
        https://msdn.microsoft.com/en-us/library/ee441964.aspx

        :param value: The command origin flag to set
        """
        string_map = {
            0: 'Runspace',
            1: 'Internal',
        }
        super(CommandOrigin, self).__init__(
            "System.Management.Automation.CommandOrigin",
            string_map, **kwargs
        )


class PipelineResultTypes(PSEnumBase):
    NONE = 0  # default streaming behaviour
    OUTPUT = 1
    ERROR = 2
    WARNING = 3  # also output and error for MergePreviousResults (PS v2)
    VERBOSE = 4
    DEBUG = 5
    INFORMATION = 6
    ALL = 7  # Error, Warning, Verbose, Debug, Information streams
    NULL = 8  # redirect to nothing - pretty much the same as null

    def __init__(self, value, protocol_version_2=False):
        """
        [MS-PSRP] 2.2.3.31 PipelineResultTypes
        https://msdn.microsoft.com/en-us/library/ee938207.aspx

        :param value: The initial PipelineResultType flag to set
        :param protocol_version_2: PSv2 uses a bitwise enum flags with a limited set of streams whereas PSv3+ is just
            a plain enum. This controls the ENUM_MAP behaviour of the initialised ENUM.
        """
        super(PipelineResultTypes, self).__init__(value, 'System.Management.Automation.Runspaces.PipelineResultTypes')

    def __new__(cls, value, protocol_version_2=False):
        """
                :param protocol_version_2: Whether to use the original string map or just None, Output, and Error that are a
            bitwise combination. This is only really relevant for MergePreviousResults in a Command obj.
        """
        if protocol_version_2:
            cls.ENUM_MAP = {
                'None': 0,
                'Output': 1,
                'Error': 2,
            }
            cls.IS_FLAGS = True
        else:
            cls.ENUM_MAP = {
                'None': 0,
                'Output': 1,
                'Error': 2,
                'Warning': 3,
                'Verbose': 4,
                'Debug': 5,
                'Information': 6,
                'All': 7,
                'Null': 8,
            }
            cls.IS_FLAGS = False
        instance = super(PipelineResultTypes, cls).__new__(cls, value)
        instance.ENUM_MAP = cls.ENUM_MAP.copy()  # Make sure the instance has it's own ENUM_MAP copy.
        instance.IS_FLAGS = cls.IS_FLAGS
        return instance


class CultureInfo(ComplexObject):

    def __init__(self, **kwargs):
        super(CultureInfo, self).__init__()

        self._adapted_properties = (
            ('lcid', ObjectMeta("I32", name="LCID")),
            ('name', ObjectMeta("S", name="Name")),
            ('display_name', ObjectMeta("S", name="DisplayName")),
            ('ietf_language_tag', ObjectMeta("S", name="IetfLanguageTag")),
            ('three_letter_iso_name', ObjectMeta(
                "S", name="ThreeLetterISOLanguageName"
            )),
            ('three_letter_windows_name', ObjectMeta(
                "S", name="ThreeLetterWindowsLanguageName"
            )),
            ('two_letter_iso_language_name', ObjectMeta(
                "S", name="TwoLetterISOLanguageName"
            )),
        )
        self.lcid = kwargs.get('lcid')
        self.name = kwargs.get('name')
        self.display_name = kwargs.get('display_name')
        self.ieft_language_tag = kwargs.get('ietf_language_tag')
        self.three_letter_iso_name = kwargs.get('three_letter_iso_name')
        self.three_letter_windows_name = \
            kwargs.get('three_letter_windows_name')
        self.two_letter_iso_language_name = \
            kwargs.get('two_letter_iso_language_name')


class ProgressRecordType(Enum):
    PROCESSING = 0
    COMPLETED = 1

    def __init__(self, **kwargs):
        """
        System.Management.Automation.ProgressRecordType Enum
        This isn't in MS-PSRP but is used in the InformationRecord message and
        so we need to define it here.

        :param value: The initial ProgressRecordType value to set
        """
        string_map = {
            0: 'Processing',
            1: 'Completed',
        }
        super(ProgressRecordType, self).__init__(
            "System.Management.Automation.ProgressRecordType",
            string_map, **kwargs
        )


class SessionStateEntryVisibility(Enum):
    PUBLIC = 0
    PRIVATE = 1

    def __init__(self, **kwargs):
        """
        System.Management.Automation.SessionStateEntryVisibility Enum
        This isn't in MS-PSRP but is used in the InformationalRecord object so
        we need to define it here

        :param value: The initial SessionStateEntryVisibility value to set
        """
        string_map = {
            0: 'Public',
            1: 'Private'
        }
        super(SessionStateEntryVisibility, self).__init__(
            "System.Management.Automation.SessionStateEntryVisibility",
            string_map, **kwargs
        )


class PSListPSObject(PSList):

    def __init__(self, *args, **kwargs):
        PSList.__init__(self, *args, **kwargs)
        self.psobject.type_names = [
            "System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, "
            "Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]",
            "System.Object",
        ]


class PSBoundParametersDictionary(PSDict):

    def __init__(self, *args, **kwargs):
        super(PSBoundParametersDictionary, self).__init__(*args, **kwargs)
        self.psobject.type_names = [
            "System.Management.Automation.PSBoundParametersDictionary",
            "System.Collections.Generic.Dictionary`2[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, "
            "PublicKeyToken=b77a5c561934e089],[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, "
            "PublicKeyToken=b77a5c561934e089]]",
            "System.Object"
        ]


class PSIntArray(PSList):

    def __init__(self, *args, **kwargs):
        super(PSIntArray, self).__init__(*args, **kwargs)
        self.psobject.type_names = [
            'System.Int32[]',
            'System.Array',
            'System.Object',
        ]


class PSObjectModelReadOnlyCollectionInt(PSList):

    def __init__(self, *args, **kwargs):
        super(PSObjectModelReadOnlyCollectionInt, self).__init__(*args, **kwargs)
        self.psobject.type_names = [
            "System.Collections.ObjectModel.ReadOnlyCollection`1[[System.Int32, mscorlib, Version=4.0.0.0, "
            "Culture=neutral, PublicKeyToken=b77a5c561934e089]]",
            "System.Object"
        ]
