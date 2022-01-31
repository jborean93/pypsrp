import uuid

from pypsrp.complex_objects import HostMethodIdentifier, ObjectMeta
from pypsrp.messages import (
    ErrorRecordMessage,
    Message,
    MessageType,
    PublicKeyRequest,
    RunspacePoolHostCall,
    RunspacePoolHostResponse,
    UserEvent,
    WarningRecord,
)
from pypsrp.serializer import Serializer


class TestPublicKeyRequest(object):
    def test_create_public_key_request(self):
        pub_key_req = PublicKeyRequest()
        empty_uuid = "00000000-0000-0000-0000-000000000000"
        serializer = Serializer()
        expected = b"<S />"

        msg = Message(0x2, empty_uuid, empty_uuid, pub_key_req, serializer)
        actual = msg.pack()
        assert (
            actual == b"\x02\x00\x00\x00"
            b"\x07\x00\x01\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00" + expected
        )

    def test_parse_public_key_request(self):
        data = (
            b"\x02\x00\x00\x00"
            b"\x07\x00\x01\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S />"
        )
        actual = Message.unpack(data, Serializer())
        assert actual.message_type == MessageType.PUBLIC_KEY_REQUEST
        assert isinstance(actual.data, PublicKeyRequest)


class TestUserEvent(object):
    def test_parse_msg(self):
        xml = """<Obj RefId="0">
            <MS>
                <I32 N="PSEventArgs.EventIdentifier">1</I32>
                <S N="PSEventArgs.SourceIdentifier">ae6245f2-c179-4a9a-a039-47b60fc44500</S>
                <DT N="PSEventArgs.TimeGenerated">2009-06-17T10:57:23.1578277-07:00</DT>
                <Obj N="PSEventArgs.Sender" RefId="1">
                    <TN RefId="0">
                        <T>System.Timers.Timer</T>
                        <T>System.ComponentModel.Component</T>
                        <T>System.MarshalByRefObject</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>System.Timers.Timer</ToString>
                    <Props>
                        <B N="AutoReset">true</B>
                        <B N="Enabled">true</B>
                        <Db N="Interval">5000</Db>
                        <Nil N="Site"/>
                        <Nil N="SynchronizingObject"/>
                        <Nil N="Container"/>
                    </Props>
                </Obj>
                <Obj N="PSEventArgs.SourceArgs" RefId="2">
                    <TN RefId="1">
                        <T>System.Object[]</T>
                        <T>System.Array</T>
                        <T>System.Object</T>
                    </TN>
                    <LST>
                        <Ref RefId="1"/>
                        <Obj RefId="3">
                            <TN RefId="2">
                                <T>System.Timers.ElapsedEventArgs</T>
                                <T>System.EventArgs</T>
                                <T>System.Object</T>
                            </TN>
                            <ToString>System.Timers.ElapsedEventArgs</ToString>
                            <Props>
                                <DT N="SignalTime">2009-06-17T10:57:23.1568275-07:00</DT>
                            </Props>
                        </Obj>
                    </LST>
                </Obj>
                <Nil N="PSEventArgs.MessageData"/>
                <Nil N="PSEventArgs.ComputerName"/>
                <G N="PSEventArgs.RunspaceId">fb9c87e8-1190-40a7-a681-6fc9b9f84a17</G>
            </MS>
        </Obj>"""
        serializer = Serializer()
        meta = ObjectMeta("Obj", object=UserEvent)
        actual = serializer.deserialize(xml, meta)

        assert str(actual.args[0]) == "System.Timers.Timer"
        assert actual.args[0].adapted_properties["Interval"] == 5000.0
        assert str(actual.args[1]) == "System.Timers.ElapsedEventArgs"
        assert actual.args[1].adapted_properties["SignalTime"] == "2009-06-17T10:57:23.1568275-07:00"
        assert actual.computer is None
        assert actual.data is None
        assert actual.event_id == 1
        assert actual.runspace_id == uuid.UUID("fb9c87e8-1190-40a7-a681-6fc9b9f84a17")
        assert str(actual.sender) == "System.Timers.Timer"
        assert actual.sender.adapted_properties["Interval"] == 5000.0
        assert actual.source_id == "ae6245f2-c179-4a9a-a039-47b60fc44500"
        assert actual.time == "2009-06-17T10:57:23.1578277-07:00"


class TestRunspacePoolHostCall(object):
    def test_parse_message(self):
        xml = """<Obj RefId="0">
            <MS>
                <I64 N="ci">1</I64>
                <Obj N="mi" RefId="1">
                    <TN RefId="0">
                        <T>System.Management.Automation.Remoting.RemoteHostMethodId</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>ReadLine</ToString>
                    <I32>11</I32>
                </Obj>
                <Obj N="mp" RefId="2">
                    <TN RefId="1">
                        <T>System.Collections.ArrayList</T>
                        <T>System.Object</T>
                    </TN>
                    <LST/>
                </Obj>
            </MS>
        </Obj>"""
        serializer = Serializer()
        meta = ObjectMeta("Obj", object=RunspacePoolHostCall)
        actual = serializer.deserialize(xml, meta)
        assert actual.ci == 1
        assert str(actual.mi) == "ReadLine"
        assert isinstance(actual.mi, HostMethodIdentifier)
        assert actual.mi.value == 11
        assert actual.mp == []


class TestRunspacePoolHostResponse(object):
    def test_parse_message(self):
        xml = """<Obj RefId="11">
            <MS>
                <S N="mr">Line read from the host</S>
                <I64 N="ci">1</I64>
                <Obj N="mi" RefId="12">
                    <TN RefId="4">
                        <T>System.Management.Automation.Remoting.RemoteHostMethodId</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>ReadLine</ToString>
                    <I32>11</I32>
                </Obj>
            </MS>
        </Obj>"""
        serializer = Serializer()
        meta = ObjectMeta("Obj", object=RunspacePoolHostResponse)
        actual = serializer.deserialize(xml, meta)
        assert actual.ci == 1
        assert actual.me is None
        assert str(actual.mi) == "ReadLine"
        assert isinstance(actual.mi, HostMethodIdentifier)
        assert actual.mi.value == 11
        assert actual.mr == "Line read from the host"


class TestErrorRecord(object):
    def test_parse_error(self):
        xml = """<Obj RefId="0">
            <TN RefId="0">
                <T>System.Management.Automation.ErrorRecord</T>
                <T>System.Object</T>
            </TN>
            <ToString>error stream</ToString>
            <MS>
                <B N="writeErrorStream">true</B>
                <Obj N="Exception" RefId="1">
                    <TN RefId="1">
                        <T>Microsoft.PowerShell.Commands.WriteErrorException</T>
                        <T>System.SystemException</T>
                        <T>System.Exception</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Microsoft.PowerShell.Commands.WriteErrorException: error stream</ToString>
                    <Props>
                        <S N="Message">error stream</S>
                        <Obj N="Data" RefId="2">
                            <TN RefId="2">
                                <T>System.Collections.ListDictionaryInternal</T>
                                <T>System.Object</T>
                            </TN>
                            <DCT/>
                        </Obj>
                        <Nil N="InnerException"/>
                        <Nil N="TargetSite"/>
                        <Nil N="StackTrace"/>
                        <Nil N="HelpLink"/>
                        <Nil N="Source"/>
                        <I32 N="HResult">-2146233087</I32>
                    </Props>
                </Obj>
                <Nil N="TargetObject"/>
                <S N="FullyQualifiedErrorId">Microsoft.PowerShell.Commands.WriteErrorException</S>
                <Obj N="InvocationInfo" RefId="3">
                    <TN RefId="3">
                        <T>System.Management.Automation.InvocationInfo</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>System.Management.Automation.InvocationInfo</ToString>
                    <Props>
                        <S N="MyCommand">Write-Error 'error stream'_x000A_</S>
                        <Obj N="BoundParameters" RefId="4">
                            <TN RefId="4">
                                <T>System.Collections.Generic.Dictionary`2[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                                <T>System.Object</T>
                            </TN>
                            <DCT/>
                        </Obj>
                        <Obj N="UnboundArguments" RefId="5">
                            <TN RefId="5">
                                <T>System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                                <T>System.Object</T>
                            </TN>
                            <LST/>
                        </Obj>
                        <I32 N="ScriptLineNumber">0</I32>
                        <I32 N="OffsetInLine">0</I32>
                        <I64 N="HistoryId">1</I64>
                        <S N="ScriptName"/>
                        <S N="Line"/>
                        <S N="PositionMessage"/>
                        <S N="PSScriptRoot"/>
                        <Nil N="PSCommandPath"/>
                        <S N="InvocationName"/>
                        <I32 N="PipelineLength">0</I32>
                        <I32 N="PipelinePosition">0</I32>
                        <B N="ExpectingInput">false</B>
                        <S N="CommandOrigin">Internal</S>
                        <Nil N="DisplayScriptPosition"/>
                    </Props>
                </Obj>
                <I32 N="ErrorCategory_Category">0</I32>
                <S N="ErrorCategory_Activity">Write-Error</S>
                <S N="ErrorCategory_Reason">WriteErrorException</S>
                <S N="ErrorCategory_TargetName"/>
                <S N="ErrorCategory_TargetType"/>
                <S N="ErrorCategory_Message">NotSpecified: (:) [Write-Error], WriteErrorException</S>
                <B N="SerializeExtendedInfo">true</B>
                <Ref N="InvocationInfo_BoundParameters" RefId="4"/>
                <Obj N="InvocationInfo_CommandOrigin" RefId="6">
                    <TN RefId="6">
                        <T>System.Management.Automation.CommandOrigin</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Internal</ToString>
                    <I32>1</I32>
                </Obj>
                <B N="InvocationInfo_ExpectingInput">false</B>
                <S N="InvocationInfo_InvocationName"/>
                <S N="InvocationInfo_Line"/>
                <I32 N="InvocationInfo_OffsetInLine">0</I32>
                <I64 N="InvocationInfo_HistoryId">1</I64>
                <Obj N="InvocationInfo_PipelineIterationInfo" RefId="7">
                    <TN RefId="7">
                        <T>System.Int32[]</T>
                        <T>System.Array</T>
                        <T>System.Object</T>
                    </TN>
                    <LST/>
                </Obj>
                <I32 N="InvocationInfo_PipelineLength">0</I32>
                <I32 N="InvocationInfo_PipelinePosition">0</I32>
                <S N="InvocationInfo_PSScriptRoot"/>
                <Nil N="InvocationInfo_PSCommandPath"/>
                <S N="InvocationInfo_PositionMessage"/>
                <I32 N="InvocationInfo_ScriptLineNumber">0</I32>
                <S N="InvocationInfo_ScriptName"/>
                <Ref N="InvocationInfo_UnboundArguments" RefId="5"/>
                <B N="SerializeExtent">false</B>
                <Obj N="CommandInfo_CommandType" RefId="8">
                    <TN RefId="8">
                        <T>System.Management.Automation.CommandTypes</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Script</ToString>
                    <I32>64</I32>
                </Obj>
                <S N="CommandInfo_Definition">Write-Error 'error stream'_x000A_</S>
                <S N="CommandInfo_Name"/>
                <Obj N="CommandInfo_Visibility" RefId="9">
                    <TN RefId="9">
                        <T>System.Management.Automation.SessionStateEntryVisibility</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Public</ToString>
                    <I32>0</I32>
                </Obj>
                <Obj N="PipelineIterationInfo" RefId="10">
                    <TN RefId="10">
                        <T>System.Collections.ObjectModel.ReadOnlyCollection`1[[System.Int32, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                        <T>System.Object</T>
                    </TN>
                    <LST>
                        <I32>0</I32>
                        <I32>0</I32>
                    </LST>
                </Obj>
                <S N="ErrorDetails_ScriptStackTrace">at &lt;ScriptBlock&gt;, &lt;No file&gt;: line 5</S>
                <Nil N="PSMessageDetails"/>
            </MS>
        </Obj>"""
        serializer = Serializer()
        meta = ObjectMeta("Obj", object=ErrorRecordMessage)
        actual = serializer.deserialize(xml, meta)

        assert str(actual) == "error stream"
        assert actual.exception.adapted_properties["Message"] == "error stream"
        assert actual.exception.adapted_properties["HResult"] == -2146233087
        assert actual.target_object is None
        assert actual.fq_error == "Microsoft.PowerShell.Commands.WriteErrorException"
        assert actual.invocation
        invoc_props = actual.invocation_info.adapted_properties
        assert invoc_props["MyCommand"] == "Write-Error 'error stream'\n"
        assert invoc_props["BoundParameters"] == {}
        assert invoc_props["UnboundArguments"] == []
        assert invoc_props["ScriptLineNumber"] == 0
        assert invoc_props["OffsetInLine"] == 0
        assert invoc_props["HistoryId"] == 1
        assert invoc_props["CommandOrigin"] == "Internal"
        assert actual.fq_error == "Microsoft.PowerShell.Commands.WriteErrorException"
        assert actual.category == 0
        assert actual.reason == "WriteErrorException"
        assert actual.target_name == ""
        assert actual.target_type == ""
        assert actual.message == "NotSpecified: (:) [Write-Error], WriteErrorException"
        assert actual.details_message is None
        assert actual.action is None
        assert actual.script_stacktrace == "at <ScriptBlock>, <No file>: line 5"
        assert actual.extended_info_present
        assert actual.invocation_name == ""
        assert actual.invocation_bound_parameters == {}
        assert actual.invocation_unbound_arguments == []
        assert str(actual.invocation_command_origin) == "Internal"
        assert actual.invocation_expecting_input is False
        assert actual.invocation_line == ""
        assert actual.invocation_offset_in_line == 0
        assert actual.invocation_position_message == ""
        assert actual.invocation_script_name == ""
        assert actual.invocation_script_line_number == 0
        assert actual.invocation_history_id == 1
        assert actual.invocation_pipeline_length == 0
        assert actual.invocation_pipeline_position == 0
        assert actual.invocation_pipeline_iteration_info == []
        assert str(actual.command_type) == "Script"
        assert actual.command_definition == "Write-Error 'error stream'\n"
        assert actual.command_name == ""
        assert str(actual.command_visibility) == "Public"
        assert actual.pipeline_iteration_info == [0, 0]


class TestWarningRecord(object):
    def test_parse_warning(self):
        xml = """<Obj RefId="0">
            <TN RefId="0">
                <T>System.Management.Automation.WarningRecord</T>
                <T>System.Management.Automation.InformationalRecord</T>
                <T>System.Object</T>
            </TN>
            <ToString>warning stream</ToString>
            <MS>
                <S N="InformationalRecord_Message">warning stream</S>
                <B N="InformationalRecord_SerializeInvocationInfo">true</B>
                <Obj N="InvocationInfo_BoundParameters" RefId="1">
                    <TN RefId="1">
                        <T>System.Management.Automation.PSBoundParametersDictionary</T>
                        <T>System.Collections.Generic.Dictionary`2[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                        <T>System.Object</T>
                    </TN>
                    <DCT/>
                </Obj>
                <Obj N="InvocationInfo_CommandOrigin" RefId="2">
                    <TN RefId="2">
                        <T>System.Management.Automation.CommandOrigin</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Runspace</ToString>
                    <I32>0</I32>
                </Obj>
                <B N="InvocationInfo_ExpectingInput">false</B>
                <S N="InvocationInfo_InvocationName"/>
                <S N="InvocationInfo_Line"/>
                <I32 N="InvocationInfo_OffsetInLine">0</I32>
                <I64 N="InvocationInfo_HistoryId">1</I64>
                <Obj N="InvocationInfo_PipelineIterationInfo" RefId="3">
                    <TN RefId="3">
                        <T>System.Int32[]</T>
                        <T>System.Array</T>
                        <T>System.Object</T>
                    </TN>
                    <LST>
                        <I32>0</I32>
                        <I32>0</I32>
                    </LST>
                </Obj>
                <I32 N="InvocationInfo_PipelineLength">1</I32>
                <I32 N="InvocationInfo_PipelinePosition">1</I32>
                <S N="InvocationInfo_PSScriptRoot"/>
                <Nil N="InvocationInfo_PSCommandPath"/>
                <S N="InvocationInfo_PositionMessage"/>
                <I32 N="InvocationInfo_ScriptLineNumber">0</I32>
                <S N="InvocationInfo_ScriptName"/>
                <Obj N="InvocationInfo_UnboundArguments" RefId="4">
                    <TN RefId="4">
                        <T>System.Collections.Generic.List`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                        <T>System.Object</T>
                    </TN>
                    <LST/>
                </Obj>
                <B N="SerializeExtent">false</B>
                <Obj N="CommandInfo_CommandType" RefId="5">
                    <TN RefId="5">
                        <T>System.Management.Automation.CommandTypes</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Script</ToString>
                    <I32>64</I32>
                </Obj>
                <S N="CommandInfo_Definition">Write-Warning 'warning stream'_x000A_</S>
                <S N="CommandInfo_Name"/>
                <Obj N="CommandInfo_Visibility" RefId="6">
                    <TN RefId="6">
                        <T>System.Management.Automation.SessionStateEntryVisibility</T>
                        <T>System.Enum</T>
                        <T>System.ValueType</T>
                        <T>System.Object</T>
                    </TN>
                    <ToString>Public</ToString>
                    <I32>0</I32>
                </Obj>
                <Obj N="InformationalRecord_PipelineIterationInfo" RefId="7">
                    <TN RefId="7">
                        <T>System.Collections.ObjectModel.ReadOnlyCollection`1[[System.Int32, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                        <T>System.Object</T>
                    </TN>
                    <LST>
                        <I32>0</I32>
                        <I32>0</I32>
                    </LST>
                </Obj>
            </MS>
        </Obj>"""
        serializer = Serializer()
        meta = ObjectMeta("Obj", object=WarningRecord)
        actual = serializer.deserialize(xml, meta)

        assert str(actual) == "warning stream"
        assert actual.invocation
        assert actual.message == "warning stream"
        assert actual.pipeline_iteration_info == [0, 0]
        assert actual.invocation_name == ""
        assert actual.invocation_bound_parameters == {}
        assert actual.invocation_unbound_arguments == []
        assert str(actual.invocation_command_origin) == "Runspace"
        assert actual.invocation_expecting_input is False
        assert actual.invocation_line == ""
        assert actual.invocation_offset_in_line == 0
        assert actual.invocation_position_message == ""
        assert actual.invocation_script_name == ""
        assert actual.invocation_script_line_number == 0
        assert actual.invocation_history_id == 1
        assert actual.invocation_pipeline_length == 1
        assert actual.invocation_pipeline_position == 1
        assert actual.invocation_pipeline_iteration_info == [0, 0]
        assert actual.command_definition == "Write-Warning 'warning stream'\n"
        assert actual.command_name == ""
        assert str(actual.command_type) == "Script"
        assert str(actual.command_visibility) == "Public"
