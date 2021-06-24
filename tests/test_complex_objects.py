import xml.etree.ElementTree as ET

import pytest

from . import assert_xml_diff

from pypsrp.complex_objects import Array, BufferCell, BufferCellType, Color, \
    Command, CommandParameter, CommandType, Coordinates, HostInfo, \
    ObjectMeta, Pipeline, PipelineResultTypes, PSThreadOptions, \
    RemoteStreamOptions, Size
from pypsrp.host import PSHost, PSHostRawUserInterface, PSHostUserInterface
from pypsrp.serializer import Serializer
from pypsrp._utils import to_unicode


def normalise_xml(xml_string):
    xml = "".join([l.lstrip() for l in to_unicode(xml_string).splitlines()])
    xml = ET.fromstring(xml)
    return to_unicode(ET.tostring(xml))


class TestEnum(object):

    def test_enum_invalid_value(self):
        state = PSThreadOptions(value=PSThreadOptions.DEFAULT)
        assert str(state) == "Default"
        state.value = 15
        with pytest.raises(KeyError) as err:
            str(state)
        assert "15 is not a valid enum value for System.Management." \
               "Automation.Runspaces.PSThreadOptions" in str(err.value)


class TestHostInfo(object):

    HOST_XML = '''<Obj RefId="0">
            <MS>
                <Obj N="_hostDefaultData" RefId="1">
                    <MS>
                        <Obj N="data" RefId="2">
                            <TN RefId="0">
                                <T>System.Collections.Hashtable</T>
                                <T>System.Object</T>
                            </TN>
                            <DCT>
                                <En>
                                    <I32 N="Key">0</I32>
                                    <Obj N="Value" RefId="3">
                                        <MS>
                                            <S N="T">System.ConsoleColor</S>
                                            <I32 N="V">11</I32>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">1</I32>
                                    <Obj N="Value" RefId="4">
                                        <MS>
                                            <S N="T">System.ConsoleColor</S>
                                            <I32 N="V">12</I32>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">2</I32>
                                    <Obj N="Value" RefId="5">
                                        <MS>
                                            <S N="T">System.Management.Automation.Host.Coordinates</S>
                                            <Obj N="V" RefId="6">
                                                <MS>
                                                    <I32 N="x">1</I32>
                                                    <I32 N="y">2</I32>
                                                </MS>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">3</I32>
                                    <Obj N="Value" RefId="7">
                                        <MS>
                                            <S N="T">System.Management.Automation.Host.Coordinates</S>
                                            <Obj N="V" RefId="8">
                                                <MS>
                                                    <I32 N="x">3</I32>
                                                    <I32 N="y">4</I32>
                                                </MS>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">4</I32>
                                    <Obj N="Value" RefId="9">
                                        <MS>
                                            <S N="T">System.Int32</S>
                                            <I32 N="V">10</I32>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">5</I32>
                                    <Obj N="Value" RefId="10">
                                        <MS>
                                            <S N="T">System.Management.Automation.Host.Size</S>
                                            <Obj N="V" RefId="11">
                                                <MS>
                                                    <I32 N="height">10</I32>
                                                    <I32 N="width">20</I32>
                                                </MS>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">6</I32>
                                    <Obj N="Value" RefId="12">
                                        <MS>
                                            <S N="T">System.Management.Automation.Host.Size</S>
                                            <Obj N="V" RefId="13">
                                                <MS>
                                                    <I32 N="height">30</I32>
                                                    <I32 N="width">40</I32>
                                                </MS>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">7</I32>
                                    <Obj N="Value" RefId="14">
                                        <MS>
                                            <S N="T">System.Management.Automation.Host.Size</S>
                                            <Obj N="V" RefId="15">
                                                <MS>
                                                    <I32 N="height">50</I32>
                                                    <I32 N="width">60</I32>
                                                </MS>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">8</I32>
                                    <Obj N="Value" RefId="16">
                                        <MS>
                                            <S N="T">System.Management.Automation.Host.Size</S>
                                            <Obj N="V" RefId="17">
                                                <MS>
                                                    <I32 N="height">70</I32>
                                                    <I32 N="width">80</I32>
                                                </MS>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </En>
                                <En>
                                    <I32 N="Key">9</I32>
                                    <Obj N="Value" RefId="18">
                                        <MS>
                                            <S N="T">System.String</S>
                                            <S N="V">Random Window Title</S>
                                        </MS>
                                    </Obj>
                                </En>
                            </DCT>
                        </Obj>
                    </MS>
                </Obj>
                <B N="_isHostNull">false</B>
                <B N="_isHostUINull">false</B>
                <B N="_isHostRawUINull">false</B>
                <B N="_useRunspaceHost">false</B>
            </MS>
        </Obj>'''

    def test_create_host_info(self):
        serializer = Serializer()

        foreground_color = Color(value=Color.CYAN)
        background_color = Color(value=Color.RED)
        cursor_position = Coordinates(x=1, y=2)
        window_position = Coordinates(x=3, y=4)
        cursor_size = 10
        buffer_size = Size(height=10, width=20)
        window_size = Size(height=30, width=40)
        max_window_size = Size(height=50, width=60)
        max_physical_window_size = Size(height=70, width=80)
        window_title = "Random Window Title"

        ps_raw_ui = PSHostRawUserInterface(
            window_title, cursor_size, foreground_color, background_color,
            cursor_position, window_position, buffer_size,
            max_physical_window_size, max_window_size, window_size
        )
        ps_ui = PSHostUserInterface(raw_ui=ps_raw_ui)
        ps_host = PSHost(None, None, False, None, None, ps_ui, None)

        host_info = HostInfo(host=ps_host)
        expected_xml = normalise_xml(self.HOST_XML)

        actual = serializer.serialize(host_info)
        actual_xml = normalise_xml(ET.tostring(actual))
        assert_xml_diff(actual_xml, expected_xml)


class TestRemoteStreamOptions(object):

    def test_to_string_one_value(self):
        options = RemoteStreamOptions(value=1)
        expected = "AddInvocationInfoToErrorRecord"
        actual = str(options)
        assert actual == expected

    def test_to_string_multiple_values(self):
        options = RemoteStreamOptions(value=3)
        expected = \
            "AddInvocationInfoToErrorRecord, AddInvocationInfoToWarningRecord"
        actual = str(options)
        assert actual == expected


class TestPipeline(object):

    PIPE_SINGLE = '''<Obj RefId="0">
        <MS>
            <B N="IsNested">false</B>
            <Nil N="ExtraCmds"/>
            <Obj N="Cmds" RefId="1">
                <TN RefId="0">
                    <T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T>
                    <T>System.Object</T>
                </TN>
                <LST>
                    <Obj RefId="2">
                        <MS>
                            <S N="Cmd">Set-Variable</S>
                            <B N="IsScript">false</B>
                            <B N="UseLocalScope">false</B>
                            <Obj N="MergeMyResult" RefId="3">
                                <TN RefId="1">
                                    <T>System.Management.Automation.Runspaces.PipelineResultTypes</T>
                                    <T>System.Enum</T>
                                    <T>System.ValueType</T>
                                    <T>System.Object</T>
                                </TN>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeToResult" RefId="4">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergePreviousResults" RefId="5">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="Args" RefId="6">
                                <TNRef RefId="0"/>
                                <LST>
                                    <Obj RefId="7">
                                        <MS>
                                            <S N="N">Name</S>
                                            <S N="V">var</S>
                                        </MS>
                                    </Obj>
                                    <Obj RefId="8">
                                        <MS>
                                            <S N="N">Value</S>
                                            <S N="V">abc</S>
                                        </MS>
                                    </Obj>
                                </LST>
                            </Obj>
                            <Obj N="MergeError" RefId="9">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeWarning" RefId="10">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeVerbose" RefId="11">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeDebug" RefId="12">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                        </MS>
                    </Obj>
                </LST>
            </Obj>
            <Nil N="History"/>
            <B N="RedirectShellErrorOutputPipe">false</B>
        </MS>
    </Obj>'''

    PIPE_MULTIPLE = '''<Obj RefId="0">
        <MS>
            <B N="IsNested">false</B>
            <Obj N="ExtraCmds" RefId="1">
                <TN RefId="0">
                    <T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T>
                    <T>System.Object</T>
                </TN>
                <LST>
                    <Obj RefId="2">
                        <MS>
                            <Obj N="Cmds" RefId="3">
                                <TNRef RefId="0"/>
                                <LST>
                                    <Obj RefId="4">
                                        <MS>
                                            <S N="Cmd">Set-Variable</S>
                                            <B N="IsScript">false</B>
                                            <B N="UseLocalScope">false</B>
                                            <Obj N="MergeMyResult" RefId="5">
                                                <TN RefId="1">
                                                    <T>System.Management.Automation.Runspaces.PipelineResultTypes</T>
                                                    <T>System.Enum</T>
                                                    <T>System.ValueType</T>
                                                    <T>System.Object</T>
                                                </TN>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeToResult" RefId="6">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergePreviousResults" RefId="7">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="Args" RefId="8">
                                                <TNRef RefId="0"/>
                                                <LST>
                                                    <Obj RefId="9">
                                                        <MS>
                                                            <S N="N">Name</S>
                                                            <S N="V">var</S>
                                                        </MS>
                                                    </Obj>
                                                    <Obj RefId="10">
                                                        <MS>
                                                            <S N="N">Value</S>
                                                            <S N="V">abc</S>
                                                        </MS>
                                                    </Obj>
                                                </LST>
                                            </Obj>
                                          <Obj N="MergeError" RefId="11">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeWarning" RefId="12">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeVerbose" RefId="13">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeDebug" RefId="14">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </LST>
                            </Obj>
                        </MS>
                    </Obj>
                    <Obj RefId="15">
                        <MS>
                            <Obj N="Cmds" RefId="16">
                                <TNRef RefId="0"/>
                                <LST>
                                    <Obj RefId="17">
                                        <MS>
                                            <S N="Cmd">Get-Variable</S>
                                            <B N="IsScript">false</B>
                                            <B N="UseLocalScope">false</B>
                                            <Obj N="MergeMyResult" RefId="18">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeToResult" RefId="19">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergePreviousResults" RefId="20">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="Args" RefId="21">
                                                <TNRef RefId="0"/>
                                                <LST>
                                                    <Obj RefId="22">
                                                        <MS>
                                                            <S N="N">Name</S>
                                                            <S N="V">var</S>
                                                        </MS>
                                                    </Obj>
                                                </LST>
                                            </Obj>
                                            <Obj N="MergeError" RefId="23">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeWarning" RefId="24">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeVerbose" RefId="25">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeDebug" RefId="26">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                    <Obj RefId="27">
                                        <MS>
                                            <S N="Cmd">Write-Output</S>
                                            <B N="IsScript">false</B>
                                            <B N="UseLocalScope">false</B>
                                            <Obj N="MergeMyResult" RefId="28">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeToResult" RefId="29">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergePreviousResults" RefId="30">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="Args" RefId="31">
                                                <TNRef RefId="0"/>
                                                <LST/>
                                            </Obj>
                                            <Obj N="MergeError" RefId="32">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeWarning" RefId="33">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeVerbose" RefId="34">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                            <Obj N="MergeDebug" RefId="35">
                                                <TNRef RefId="1"/>
                                                <ToString>None</ToString>
                                                <I32>0</I32>
                                            </Obj>
                                        </MS>
                                    </Obj>
                                </LST>
                            </Obj>
                        </MS>
                    </Obj>
                </LST>
            </Obj>
            <Obj N="Cmds" RefId="36">
                <TNRef RefId="0"/>
                <LST>
                    <Obj RefId="37">
                        <MS>
                            <S N="Cmd">Set-Variable</S>
                            <B N="IsScript">false</B>
                            <B N="UseLocalScope">false</B>
                            <Obj N="MergeMyResult" RefId="38">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeToResult" RefId="39">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergePreviousResults" RefId="40">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="Args" RefId="41">
                                <TNRef RefId="0"/>
                                <LST>
                                    <Obj RefId="42">
                                        <MS>
                                            <S N="N">Name</S>
                                            <S N="V">var</S>
                                        </MS>
                                    </Obj>
                                    <Obj RefId="43">
                                        <MS>
                                            <S N="N">Value</S>
                                            <S N="V">abc</S>
                                        </MS>
                                    </Obj>
                                </LST>
                            </Obj>
                            <Obj N="MergeError" RefId="44">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeWarning" RefId="45">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeVerbose" RefId="46">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                            <Obj N="MergeDebug" RefId="47">
                                <TNRef RefId="1"/>
                                <ToString>None</ToString>
                                <I32>0</I32>
                            </Obj>
                        </MS>
                    </Obj>
                </LST>
            </Obj>
            <Nil N="History"/>
            <B N="RedirectShellErrorOutputPipe">false</B>
        </MS>
    </Obj>'''

    def test_create_pipeline_single(self):
        serializer = Serializer()

        command = Command(protocol_version="2.2")
        command.cmd = "Set-Variable"
        command.is_script = False
        command.use_local_scope = False
        command.args = [
            CommandParameter(name="Name", value="var"),
            CommandParameter(name="Value", value="abc")
        ]

        pipeline = Pipeline()
        pipeline.is_nested = False
        pipeline.commands = [command]
        pipeline.redirect_err_to_out = False

        expected_xml = normalise_xml(self.PIPE_SINGLE)

        actual = serializer.serialize(pipeline)
        actual_xml = normalise_xml(ET.tostring(actual))
        assert_xml_diff(actual_xml, expected_xml)

    def test_create_pipeline_multiple(self):
        serializer = Serializer()

        command1 = Command(protocol_version="2.2")
        command1.cmd = "Set-Variable"
        command1.is_script = False
        command1.use_local_scope = False
        command1.end_of_statement = True
        command1.args = [
            CommandParameter(name="Name", value="var"),
            CommandParameter(name="Value", value="abc")
        ]

        command2 = Command(protocol_version="2.2")
        command2.cmd = "Get-Variable"
        command2.is_script = False
        command2.use_local_scope = False
        command2.args = [
            CommandParameter(name="Name", value="var"),
        ]
        command3 = Command(protocol_version="2.2")
        command3.cmd = "Write-Output"
        command3.is_script = False
        command3.use_local_scope = False

        pipeline = Pipeline()
        pipeline.is_nested = False
        pipeline.commands = [command1, command2, command3]
        pipeline.redirect_err_to_out = False

        expected_xml = normalise_xml(self.PIPE_MULTIPLE)

        actual = serializer.serialize(pipeline)
        actual_xml = normalise_xml(ET.tostring(actual))
        assert_xml_diff(actual_xml, expected_xml)

    def test_parse_pipeline_single(self):
        serializer = Serializer()
        actual = serializer.deserialize(normalise_xml(self.PIPE_SINGLE),
                                        ObjectMeta("Obj", object=Pipeline))
        assert actual.history is None
        assert actual.is_nested is False
        assert actual.redirect_err_to_out is False
        assert len(actual.commands) == 1
        assert len(actual.commands[0].args) == 2
        assert actual.commands[0].args[0].name == "Name"
        assert actual.commands[0].args[0].value == "var"
        assert actual.commands[0].args[1].name == "Value"
        assert actual.commands[0].args[1].value == "abc"
        assert actual.commands[0].cmd == "Set-Variable"
        assert actual.commands[0].end_of_statement is False
        assert actual.commands[0].is_script is False
        assert str(actual.commands[0].merge_debug) == "None"
        assert str(actual.commands[0].merge_error) == "None"
        assert str(actual.commands[0].merge_my_result) == "None"
        assert str(actual.commands[0].merge_previous) == "None"
        assert str(actual.commands[0].merge_verbose) == "None"
        assert str(actual.commands[0].merge_warning) == "None"
        assert actual.commands[0].use_local_scope is False

    def test_parse_pipeline_multiple(self):
        serializer = Serializer()
        actual = serializer.deserialize(normalise_xml(self.PIPE_MULTIPLE),
                                        ObjectMeta("Obj", object=Pipeline))
        assert actual.history is None
        assert actual.is_nested is False
        assert actual.redirect_err_to_out is False
        assert len(actual.commands) == 3
        assert len(actual.commands[0].args) == 2
        assert actual.commands[0].args[0].name == "Name"
        assert actual.commands[0].args[0].value == "var"
        assert actual.commands[0].args[1].name == "Value"
        assert actual.commands[0].args[1].value == "abc"
        assert actual.commands[0].cmd == "Set-Variable"
        assert actual.commands[0].end_of_statement is True
        assert actual.commands[0].is_script is False
        assert str(actual.commands[0].merge_debug) == "None"
        assert str(actual.commands[0].merge_error) == "None"
        assert str(actual.commands[0].merge_my_result) == "None"
        assert str(actual.commands[0].merge_previous) == "None"
        assert str(actual.commands[0].merge_verbose) == "None"
        assert str(actual.commands[0].merge_warning) == "None"
        assert actual.commands[0].use_local_scope is False

        assert len(actual.commands[1].args) == 1
        assert actual.commands[1].args[0].name == "Name"
        assert actual.commands[1].args[0].value == "var"
        assert actual.commands[1].cmd == "Get-Variable"
        assert actual.commands[1].end_of_statement is False
        assert actual.commands[1].is_script is False
        assert str(actual.commands[1].merge_debug) == "None"
        assert str(actual.commands[1].merge_error) == "None"
        assert str(actual.commands[1].merge_my_result) == "None"
        assert str(actual.commands[1].merge_previous) == "None"
        assert str(actual.commands[1].merge_verbose) == "None"
        assert str(actual.commands[1].merge_warning) == "None"
        assert actual.commands[1].use_local_scope is False

        assert len(actual.commands[2].args) == 0
        assert actual.commands[2].cmd == "Write-Output"
        assert actual.commands[2].end_of_statement is True
        assert actual.commands[2].is_script is False
        assert str(actual.commands[2].merge_debug) == "None"
        assert str(actual.commands[2].merge_error) == "None"
        assert str(actual.commands[2].merge_my_result) == "None"
        assert str(actual.commands[2].merge_previous) == "None"
        assert str(actual.commands[2].merge_verbose) == "None"
        assert str(actual.commands[2].merge_warning) == "None"
        assert actual.commands[2].use_local_scope is False


class TestCommandType(object):

    def test_to_string_one_value(self):
        command_type = CommandType(value=1)
        expected = "Alias"
        actual = str(command_type)
        assert actual == expected

    def test_to_string_multiple_values(self):
        command_type = CommandType(value=3)
        expected = "Alias, Function"
        actual = str(command_type)
        assert actual == expected

    def test_to_string_all(self):
        command_type = CommandType(value=CommandType.ALL)
        expected = "All"
        actual = str(command_type)
        assert actual == expected


class TestPipelineResultTypes(object):

    def test_to_string_one_value(self):
        result_type = PipelineResultTypes(value=1)
        expected = "Output"
        actual = str(result_type)
        assert actual == expected

    def test_to_string_multiple_values(self):
        result_type = PipelineResultTypes(value=3)
        expected = "Warning"
        actual = str(result_type)
        assert actual == expected

    def test_to_string_multiple_values_protocol_v2(self):
        result_type = PipelineResultTypes(protocol_version_2=True, value=3)
        expected = "Output, Error"
        actual = str(result_type)
        assert actual == expected

    def test_to_string_none(self):
        result_type = PipelineResultTypes(value=PipelineResultTypes.NONE)
        expected = "None"
        actual = str(result_type)
        assert actual == expected

    def test_to_string_all(self):
        result_type = PipelineResultTypes(value=PipelineResultTypes.ALL)
        expected = "All"
        actual = str(result_type)
        assert actual == expected

    def test_to_string_null(self):
        result_type = PipelineResultTypes(value=PipelineResultTypes.NULL)
        expected = "Null"
        actual = str(result_type)
        assert actual == expected


class TestBufferCell(object):

    BUFFER_CELL = '''<Obj RefId="0">
    <Props>
        <C N="character">65</C>
        <Obj N="foregroundColor" RefId="1">
            <TN RefId="0">
                <T>System.ConsoleColor</T>
                <T>System.Enum</T>
                <T>System.ValueType</T>
                <T>System.Object</T>
            </TN>
            <ToString>Cyan</ToString>
            <I32>11</I32>
        </Obj>
        <Obj N="backgroundColor" RefId="2">
            <TNRef RefId="0"/>
            <ToString>Green</ToString>
            <I32>10</I32>
        </Obj>
        <I32 N="bufferCellType">0</I32>
    </Props>
</Obj>'''

    def test_create_buffer_cell(self):
        serializer = Serializer()

        buffer_cell = BufferCell(
            character="A", foreground_color=Color(value=Color.CYAN),
            background_color=Color(value=Color.GREEN),
            cell_type=BufferCellType.COMPLETE
        )

        expected_xml = normalise_xml(self.BUFFER_CELL)
        actual = serializer.serialize(buffer_cell)
        actual_xml = normalise_xml(ET.tostring(actual))

        assert_xml_diff(actual_xml, expected_xml)

    def test_parse_buffer_cell(self):
        serializer = Serializer()
        actual = serializer.deserialize(normalise_xml(self.BUFFER_CELL),
                                        ObjectMeta("Obj", object=BufferCell))

        assert actual.character == "A"
        assert actual.foreground_color.value == Color.CYAN
        assert actual.background_color.value == Color.GREEN
        assert actual.cell_type == BufferCellType.COMPLETE


class TestArray(object):

    SINGLE_ARRAY = '''<Obj RefId="0">
    <MS>
        <Obj N="mae" RefId="1">
            <TN RefId="0">
                <T>System.Object[]</T>
                <T>System.Array</T>
                <T>System.Object</T>
            </TN>
            <LST>
                <I32>1</I32>
                <I32>2</I32>
                <I32>3</I32>
            </LST>
        </Obj>
        <Obj N="mal" RefId="2">
            <TNRef RefId="0"/>
            <LST>
                <I32>3</I32>
            </LST>
        </Obj>
    </MS>
</Obj>'''

    SINGLE_ARRAY2 = '''<Obj RefId="0">
        <MS>
            <Obj N="mae" RefId="1">
                <TN RefId="0">
                    <T>System.Object[]</T>
                    <T>System.Array</T>
                    <T>System.Object</T>
                </TN>
                <LST>
                    <I32>4</I32>
                    <I32>5</I32>
                    <I32>6</I32>
                </LST>
            </Obj>
            <Obj N="mal" RefId="2">
                <TNRef RefId="0"/>
                <LST>
                    <I32>3</I32>
                </LST>
            </Obj>
        </MS>
    </Obj>'''

    TWO_ARRAY = '''<Obj RefId="0">
    <MS>
        <Obj N="mae" RefId="1">
            <TN RefId="0">
                <T>System.Object[]</T>
                <T>System.Array</T>
                <T>System.Object</T>
            </TN>
            <LST>
                <I32>1</I32>
                <I32>2</I32>
                <I32>3</I32>
                <I32>4</I32>
                <I32>5</I32>
                <I32>6</I32>
                <I32>7</I32>
                <I32>8</I32>
                <I32>9</I32>
            </LST>
        </Obj>
        <Obj N="mal" RefId="2">
            <TNRef RefId="0"/>
            <LST>
                <I32>3</I32>
                <I32>3</I32>
            </LST>
        </Obj>
    </MS>
</Obj>'''

    THREE_ARRAY = '''<Obj RefId="0">
    <MS>
        <Obj N="mae" RefId="1">
            <TN RefId="0">
                <T>System.Object[]</T>
                <T>System.Array</T>
                <T>System.Object</T>
            </TN>
            <LST>
                <I32>1</I32>
                <I32>2</I32>
                <I32>3</I32>
                <I32>4</I32>
                <I32>5</I32>
                <I32>6</I32>
                <I32>7</I32>
                <I32>8</I32>
                <I32>9</I32>
                <I32>10</I32>
                <I32>11</I32>
                <I32>12</I32>
                <I32>13</I32>
                <I32>14</I32>
                <I32>15</I32>
                <I32>16</I32>
                <I32>17</I32>
                <I32>18</I32>
                <I32>19</I32>
                <I32>20</I32>
                <I32>21</I32>
                <I32>22</I32>
                <I32>23</I32>
                <I32>24</I32>
            </LST>
        </Obj>
        <Obj N="mal" RefId="2">
            <TNRef RefId="0"/>
            <LST>
                <I32>2</I32>
                <I32>3</I32>
                <I32>4</I32>
            </LST>
        </Obj>
    </MS>
</Obj>'''

    def test_create_array(self):
        serializer = Serializer()

        array = Array(array=[1, 2, 3])

        expected_xml = normalise_xml(self.SINGLE_ARRAY)
        actual = serializer.serialize(array)
        actual_xml = normalise_xml(ET.tostring(actual))

        assert_xml_diff(actual_xml, expected_xml)

        array.array = [4, 5, 6]
        expected_xml = normalise_xml(self.SINGLE_ARRAY2)
        actual = serializer.serialize(array)
        actual_xml = normalise_xml(ET.tostring(actual))

        assert_xml_diff(actual_xml, expected_xml)

    def test_parse_array(self):
        serializer = Serializer()
        actual = serializer.deserialize(self.SINGLE_ARRAY,
                                        ObjectMeta("Obj", object=Array))
        array = actual.array
        assert array == [1, 2, 3]
        assert actual.mae == [1, 2, 3]
        assert actual.mal == [3]

    def test_two_dimensional_create_array(self):
        serializer = Serializer()

        array = Array(array=[[1, 2, 3], [4, 5, 6], [7, 8, 9]])

        expected_xml = normalise_xml(self.TWO_ARRAY)
        actual = serializer.serialize(array)
        actual_xml = normalise_xml(ET.tostring(actual))

        assert_xml_diff(actual_xml, expected_xml)

    def test_parse_two_dimensional_array(self):
        serializer = Serializer()
        actual = serializer.deserialize(self.TWO_ARRAY,
                                        ObjectMeta("Obj", object=Array))
        array = actual.array
        assert array == [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        assert actual.mae == [1, 2, 3, 4, 5, 6, 7, 8, 9]
        assert actual.mal == [3, 3]

    def test_three_dimensional_create_array(self):
        serializer = Serializer()

        array = Array(array=[
            [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
            [[13, 14, 15, 16], [17, 18, 19, 20], [21, 22, 23, 24]]
        ])

        expected_xml = normalise_xml(self.THREE_ARRAY)
        actual = serializer.serialize(array)
        actual_xml = normalise_xml(ET.tostring(actual))

        assert_xml_diff(actual_xml, expected_xml)

    def test_parse_three_dimensional_array(self):
        serializer = Serializer()
        actual = serializer.deserialize(self.THREE_ARRAY,
                                        ObjectMeta("Obj", object=Array))
        array = actual.array
        assert array == [
            [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
            [[13, 14, 15, 16], [17, 18, 19, 20], [21, 22, 23, 24]]
        ]
        assert actual.mae == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                              13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]
        assert actual.mal == [2, 3, 4]
