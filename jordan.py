import xml.etree.ElementTree as ET

from pypsrp.powershell import RunspacePool, PowerShell
from pypsrp.serializer import Serializer
from pypsrp.wsman import WSMan

wsman = WSMan('server2019.domain.local', ssl=False, auth='kerberos')

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
''')
    ps.invoke()

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

fileinfo_obj = '''<Obj RefId="0">
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


fileinfo_xml = ET.fromstring(fileinfo_obj)

fileinfo = PSObject()
for element in fileinfo_xml:
    if element.tag =='TN':
        fileinfo.psobject.type_names = [e.text for e in element]
    elif element.tag == 'TNRef':
        fileinfo.psobject.type_names = []  # TODO: lookup reference table
    elif element.tag in ['Props', 'MS']:
        for property in element:
            prop_info = PSPropertyInfo()
            prop_info.name = property.attrib['N']
            prop_info.is_instance = element.tag == 'Props'
            setattr(fileinfo, prop_info.name, property.text)

            fileinfo.psobject.properties.append(prop_info)
    elif element.tag == 'ToString':
        fileinfo.psobject.to_string = element.text
    else:
        # TODO: property sets (used in an enum)
        a = ''



'''
        for obj_property in element:
            if obj_property.tag == "TN":
                for obj_type in obj_property:
                    obj.types.append(obj_type.text)
                self.tn[obj_property.attrib['RefId']] = obj.types
            elif obj_property.tag == "TNRef":
                obj.types = self.tn[obj_property.attrib['RefId']]
            elif obj_property.tag == "Props":
                for adapted_property in obj_property:
                    key = adapted_property.attrib['N']
                    value = self.deserialize(adapted_property, clear=False)
                    obj.adapted_properties[key] = value
            elif obj_property.tag == "MS":
                for extended_property in obj_property:
                    key = extended_property.attrib['N']
                    value = self.deserialize(extended_property, clear=False)
                    obj.extended_properties[key] = value
            elif obj_property.tag == "ToString":
                value = self.deserialize(obj_property, clear=False)
                obj.to_string = value
            else:
                value = self.deserialize(obj_property, clear=False)
                obj.property_sets.append(value)

'''


a = ''
