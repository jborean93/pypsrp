import xml.etree.ElementTree as ET

from pypsrp.powershell import RunspacePool, PowerShell
from pypsrp.serializer import Serializer, SerializerV2
from pypsrp.wsman import WSMan

"""
wsman = WSMan('server2019.domain.local', auth='kerberos', cert_validation=False)

with RunspacePool(wsman) as rp:
    ps = PowerShell(rp)

    ps.add_script('''
$ErrorActionPreference = 'Stop'
$obj = [PSCustomObject]@{
    NoteProperty1 = 'note prop 1'
    NoteProperty2 = 'note prop 2'
}
$obj | Add-Member -MemberType AliasProperty -Name AliasProperty1 -Value NoteProperty1
$obj | Add-Member -MemberType ScriptProperty -Name ScriptProperty1 -Value { $this.NoteProperty1 } 

$obj

[System.IO.FileShare]::None

[System.IO.FileInfo]::new("C:\\temp\\win_package.ps1")

$string = 'string value'
$string | Add-Member -MemberType AliasProperty -Name Size -Value Length -PassThru

[DateTime]::Now

[DateTime]::new(1970, 1, 1, 0, 0, 0, 0, 'UTC')

,@('a', 'b')

,[System.Collections.Generic.List[String]]@('c', 'd')

@{HashKey1 = '1'; HashKey2 = 1}

$dict = [System.Collections.Generic.Dictionary[String, Object]]::new()
$dict['DictKey1'] = '1'
$dict['DictKey2'] = 1
$dict

$queue = [System.Collections.Generic.Queue[Object]]@()
$queue.Enqueue('1')
$queue.Enqueue(1)
,$queue

$stack = [System.Collections.Generic.Stack[Object]]@()
$stack.Push('1')
$stack.Push(1)
,$stack
''')
    ps.invoke()

a = ''
"""

ps_custom_obj = '''<Obj RefId="0">
    <TN RefId="0">
        <T>System.Management.Automation.PSCustomObject</T>
        <T>System.Object</T>
    </TN>
    <MS>
        <S N="NoteProperty1">note prop 1</S>
        <S N="NoteProperty2">note prop 2</S>
        <S N="AliasProperty1">note prop 1</S>
        <S N="ScriptProperty1">note prop 1</S>
    </MS>
</Obj>'''

enum_obj = '''<Obj RefId="0">
    <TN RefId="0">
        <T>System.IO.FileShare</T>
        <T>System.Enum</T>
        <T>System.ValueType</T>
        <T>System.Object</T>
    </TN>
    <ToString>None</ToString>
    <I32>0</I32>
</Obj>'''

fileinfo_obj = r'''<Obj RefId="0">
    <TN RefId="0">
        <T>System.IO.FileInfo</T>
        <T>System.IO.FileSystemInfo</T>
        <T>System.MarshalByRefObject</T>
        <T>System.Object</T>
    </TN>
    <ToString>C:\temp\win_package.ps1</ToString>
    <Props>
        <S N="Name">win_package.ps1</S>
        <I64 N="Length">44248</I64>
        <S N="DirectoryName">C:\temp</S>
        <S N="Directory">C:\temp</S>
        <B N="IsReadOnly">false</B>
        <B N="Exists">true</B>
        <S N="FullName">C:\temp\win_package.ps1</S>
        <S N="Extension">.ps1</S>
        <DT N="CreationTime">2020-01-15T23:16:57.7817215+00:00</DT>
        <DT N="CreationTimeUtc">2020-01-15T23:16:57.7817215Z</DT>
        <DT N="LastAccessTime">2020-01-30T01:35:22.939241+00:00</DT>
        <DT N="LastAccessTimeUtc">2020-01-30T01:35:22.939241Z</DT>
        <DT N="LastWriteTime">2020-01-30T01:35:22.939241+00:00</DT>
        <DT N="LastWriteTimeUtc">2020-01-30T01:35:22.939241Z</DT>
        <S N="Attributes">Archive</S>
    </Props>
    <MS>
        <S N="Mode">-a----</S>
        <S N="VersionInfo">File:             C:\temp\win_package.ps1_x000D__x000A_InternalName:     _x000D__x000A_OriginalFilename: _x000D__x000A_FileVersion:      _x000D__x000A_FileDescription:  _x000D__x000A_Product:          _x000D__x000A_ProductVersion:   _x000D__x000A_Debug:            False_x000D__x000A_Patched:          False_x000D__x000A_PreRelease:       False_x000D__x000A_PrivateBuild:     False_x000D__x000A_SpecialBuild:     False_x000D__x000A_Language:         _x000D__x000A_</S>
        <S N="BaseName">win_package</S>
        <Obj N="Target" RefId="1">
            <TN RefId="1">
                <T>System.Collections.Generic.List`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
                <T>System.Object</T>
            </TN>
            <LST />
        </Obj>
        <Nil N="LinkType" />
    </MS>
</Obj>'''

extended_str_obj ='''<Obj RefId="0">
  <S>string value</S>
  <MS>
    <I32 N="Size">12</I32>
  </MS>
</Obj>'''

array_obj = '''<Obj RefId="0">
  <TN RefId="0">
    <T>System.Object[]</T>
    <T>System.Array</T>
    <T>System.Object</T>
  </TN>
  <LST>
    <S>a</S>
    <I32>1</I32>
  </LST>
</Obj>'''

list_str_obj = '''<Obj RefId="0">
  <TN RefId="0">
    <T>System.Collections.Generic.List`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
    <T>System.Object</T>
  </TN>
  <LST>
    <S>c</S>
    <S>d</S>
  </LST>
</Obj>'''

hashtable_obj = '''<Obj RefId="0">
  <TN RefId="0">
    <T>System.Collections.Hashtable</T>
    <T>System.Object</T>
  </TN>
  <DCT>
    <En>
      <S N="Key">HashKey2</S>
      <I32 N="Value">1</I32>
    </En>
    <En>
      <S N="Key">HashKey1</S>
      <S N="Value">1</S>
    </En>
  </DCT>
</Obj>'''

dict_obj = '''<Obj RefId="0">
  <TN RefId="0">
    <T>System.Collections.Generic.Dictionary`2[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
    <T>System.Object</T>
  </TN>
  <DCT>
    <En>
      <S N="Key">DictKey1</S>
      <S N="Value">1</S>
    </En>
    <En>
      <S N="Key">DictKey2</S>
      <I32 N="Value">1</I32>
    </En>
  </DCT>
</Obj>'''

queue_obj = '''<Obj RefId="0">
  <TN RefId="0">
    <T>System.Collections.Generic.Queue`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
    <T>System.Object</T>
  </TN>
  <QUE>
    <S>1</S>
    <I32>1</I32>
  </QUE>
</Obj>'''

stack_obj = '''<Obj RefId="0">
  <TN RefId="0">
    <T>System.Collections.Generic.Stack`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</T>
    <T>System.Object</T>
  </TN>
  <STK>
    <I32>1</I32>
    <S>1</S>
  </STK>
</Obj>'''

"""
PSObject
https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/MshObject.cs

Can adapt the following items
            if (obj is PSMemberSet) { return PSObject.s_mshMemberSetAdapter; }

            if (obj is PSObject) { return PSObject.s_mshObjectAdapter; }

            if (obj is CimInstance) { return PSObject.s_cimInstanceAdapter; }
#if !UNIX
            if (obj is ManagementClass) { return PSObject.s_managementClassAdapter; }

            if (obj is ManagementBaseObject) { return PSObject.s_managementObjectAdapter; }

            if (obj is DirectoryEntry) { return PSObject.s_directoryEntryAdapter; }
#endif
            if (obj is DataRowView) { return PSObject.s_dataRowViewAdapter; }

            if (obj is DataRow) { return PSObject.s_dataRowAdapter; }

            if (obj is XmlNode) { return PSObject.s_xmlNodeAdapter; }

"""

# MS == ExtendedProperties
# Props == AdaptedProperties


class PSPropertyInfo:

    def __init__(self):
        self.is_instance = False  # Looks like is_instance are adapted properties and False is extended properties
        self.name = None


class PSObjectMeta:

    def __init__(self):
        self.properties = []
        self.type_names = []
        self.to_string = None


class PSObject:

    def __init__(self):
        self.psobject = PSObjectMeta()

    def __str__(self):
        return self.psobject.to_string


class FileInfo(PSObject):

    def __init__(self):
        super(FileInfo, self).__init__()

        self.mode = None
        self.version_info = None
        self.base_name = None

        type_names = ['System.IO.FileInfo', 'System.IO.FileSystemInfo', 'System.MarshalByRefObject', 'System.Object']

    def __str__(self):
        return self.psobject._to_string


s = SerializerV2()

fileinfo = s.deserialize(ET.fromstring(fileinfo_obj))
array = s.deserialize(ET.fromstring(array_obj))
list_str = s.deserialize(ET.fromstring(list_str_obj))


a = ''
