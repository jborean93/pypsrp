# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import pytest
import six
import xml.etree.ElementTree as ET

import pypsrp.dotnet as dotnet

from pypsrp.serializer import SerializerV2

from pypsrp._utils import (
    to_string,
)


# Contains control characters, non-ascii chars, and chars that are surrogate pairs in UTF-16
COMPLEX_STRING = u'treble clef\n _x0000_ _X0000_ %s café' % b"\xF0\x9D\x84\x9E".decode('utf-8')
COMPLEX_ENCODED_STRING = u'treble clef_x000A_ _x005F_x0000_ _x005F_X0000_ _xD834__xDD1E_ café'


@pytest.mark.parametrize('rehydrate', [True, False])
def test_ps_enum(rehydrate):
    type_name = 'MyEnumRehydrated' if rehydrate else 'MyEnum'

    class EnumTest(dotnet.PSEnumBase, dotnet.PSInt):
        PSObject = dotnet.PSObjectMeta(type_names=['System.%s' % type_name, 'System.Object'], rehydrate=rehydrate)

        none = 0
        Value1 = 1
        Value2 = 2
        Value3 = 3

    assert str(EnumTest.none) == 'None'
    assert str(EnumTest.Value1) == 'Value1'
    assert str(EnumTest.Value2) == 'Value2'
    assert str(EnumTest.Value3) == 'Value3'

    val = EnumTest.Value1
    assert isinstance(val, dotnet.PSObject)
    assert isinstance(val, dotnet.PSEnumBase)
    assert isinstance(val, dotnet.PSInt)
    assert isinstance(val, int)

    element = SerializerV2().serialize(val)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><I32>1</I32>' \
                     '<TN RefId="0"><T>System.%s</T><T>System.Object</T></TN>' \
                     '<ToString>Value1</ToString></Obj>' % type_name

    actual = SerializerV2().deserialize(element)
    assert actual == val
    assert str(actual) == 'Value1'
    assert isinstance(actual, dotnet.PSObject)
    assert isinstance(actual, dotnet.PSInt)
    assert isinstance(actual, int)

    # Without hydration we just get the primitive value back
    if rehydrate:
        assert actual.PSTypeNames == ['System.%s' % type_name, 'System.Object']
        assert isinstance(actual, dotnet.PSEnumBase)
        assert isinstance(actual, EnumTest)

    else:
        assert actual.PSTypeNames == ['Deserialized.System.%s' % type_name, 'Deserialized.System.Object']
        assert not isinstance(actual, dotnet.PSEnumBase)
        assert not isinstance(actual, EnumTest)


@pytest.mark.parametrize('rehydrate', [True, False])
def test_ps_enum_unsigned_type(rehydrate):
    type_name = 'EnumUIntRehydrated' if rehydrate else 'EnumUInt'

    class EnumTest(dotnet.PSEnumBase, dotnet.PSUInt):
        PSObject = dotnet.PSObjectMeta(type_names=['System.%s' % type_name, 'System.Object'], rehydrate=rehydrate)

        none = 0
        Value1 = 1
        Value2 = 2
        Value3 = 3

    assert str(EnumTest.none) == 'None'
    assert str(EnumTest.Value1) == 'Value1'
    assert str(EnumTest.Value2) == 'Value2'
    assert str(EnumTest.Value3) == 'Value3'

    val = EnumTest.Value1
    assert isinstance(val, dotnet.PSObject)
    assert isinstance(val, dotnet.PSEnumBase)
    assert isinstance(val, dotnet.PSUInt)
    assert isinstance(val, int)

    element = SerializerV2().serialize(val)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><U32>1</U32>' \
                     '<TN RefId="0"><T>System.%s</T><T>System.Object</T></TN>' \
                     '<ToString>Value1</ToString></Obj>' % type_name

    actual = SerializerV2().deserialize(element)
    assert actual == val
    assert str(actual) == 'Value1'
    assert isinstance(actual, dotnet.PSObject)
    assert isinstance(actual, dotnet.PSUInt)
    assert isinstance(actual, int)

    # Without hydration we just get the primitive value back
    if rehydrate:
        assert actual.PSTypeNames == ['System.%s' % type_name, 'System.Object']
        assert isinstance(actual, dotnet.PSEnumBase)
        assert isinstance(actual, EnumTest)

    else:
        assert actual.PSTypeNames == ['Deserialized.System.%s' % type_name, 'Deserialized.System.Object']
        assert not isinstance(actual, dotnet.PSEnumBase)
        assert not isinstance(actual, EnumTest)


@pytest.mark.parametrize('rehydrate', [True, False])
def test_ps_enum_extended_properties(rehydrate):
    type_name = 'EnumExtendedRehydrated' if rehydrate else 'EnumExtended'

    class EnumTest(dotnet.PSEnumBase, dotnet.PSInt64):
        PSObject = dotnet.PSObjectMeta(type_names=['System.%s' % type_name, 'System.Object'], rehydrate=rehydrate)

        none = 0
        Value1 = 1
        Value2 = 2
        Value3 = 3

    assert str(EnumTest.none) == 'None'
    assert str(EnumTest.Value1) == 'Value1'
    assert str(EnumTest.Value2) == 'Value2'
    assert str(EnumTest.Value3) == 'Value3'

    val = EnumTest.none
    val.PSObject.extended_properties.append(dotnet.PSPropertyInfo('Test café'))
    val['Test café'] = u'café'
    assert isinstance(val, dotnet.PSObject)
    assert isinstance(val, dotnet.PSEnumBase)
    assert isinstance(val, dotnet.PSInt64)
    assert isinstance(val, dotnet.large_int)

    element = SerializerV2().serialize(val)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><I64>0</I64>' \
                     '<TN RefId="0"><T>System.%s</T><T>System.Object</T></TN>' \
                     '<MS><S N="Test café">café</S></MS>' \
                     '<ToString>None</ToString></Obj>' % type_name

    actual = SerializerV2().deserialize(element)
    assert actual == val
    assert val['Test café'] == u'café'
    assert str(actual) == 'None'
    assert isinstance(actual, dotnet.PSObject)
    assert isinstance(actual, dotnet.PSInt64)
    assert isinstance(actual, dotnet.large_int)

    # Without hydration we just get the primitive value back
    if rehydrate:
        assert actual.PSTypeNames == ['System.%s' % type_name, 'System.Object']
        assert isinstance(actual, dotnet.PSEnumBase)
        assert isinstance(actual, EnumTest)

    else:
        assert actual.PSTypeNames == ['Deserialized.System.%s' % type_name, 'Deserialized.System.Object']
        assert not isinstance(actual, dotnet.PSEnumBase)
        assert not isinstance(actual, EnumTest)


@pytest.mark.parametrize('rehydrate', [True, False])
def test_ps_flags(rehydrate):
    type_name = 'FlagHydrated' if rehydrate else 'Flag'

    class FlagTest(dotnet.PSFlagBase, dotnet.PSInt):
        PSObject = dotnet.PSObjectMeta(type_names=['System.%s' % type_name, 'System.Object'], rehydrate=rehydrate)

        none = 0
        Flag1 = 1
        Flag2 = 2
        Flag3 = 4

    assert str(FlagTest.none) == 'None'
    assert str(FlagTest.Flag1) == 'Flag1'
    assert str(FlagTest.Flag2) == 'Flag2'
    assert str(FlagTest.Flag3) == 'Flag3'
    assert str(FlagTest.Flag1 | FlagTest.Flag3) == 'Flag1, Flag3'

    val = FlagTest.Flag1 | FlagTest.Flag3

    assert isinstance(val, dotnet.PSObject)
    assert isinstance(val, dotnet.PSEnumBase)
    assert isinstance(val, dotnet.PSFlagBase)
    assert isinstance(val, dotnet.PSInt)
    assert isinstance(val, int)

    element = SerializerV2().serialize(val)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><I32>5</I32>' \
                     '<TN RefId="0"><T>System.%s</T><T>System.Object</T></TN>' \
                     '<ToString>Flag1, Flag3</ToString></Obj>' % type_name

    actual = SerializerV2().deserialize(element)
    assert actual == val
    assert str(actual) == 'Flag1, Flag3'
    assert isinstance(actual, dotnet.PSObject)
    assert isinstance(actual, dotnet.PSInt)
    assert isinstance(actual, int)

    # Without hydration we just get the primitive value back
    if rehydrate:
        assert actual.PSTypeNames == ['System.%s' % type_name, 'System.Object']
        assert isinstance(actual, dotnet.PSEnumBase)
        assert isinstance(actual, dotnet.PSFlagBase)
        assert isinstance(actual, FlagTest)

    else:
        assert actual.PSTypeNames == ['Deserialized.System.%s' % type_name, 'Deserialized.System.Object']
        assert not isinstance(actual, dotnet.PSEnumBase)
        assert not isinstance(actual, dotnet.PSFlagBase)
        assert not isinstance(actual, FlagTest)


def test_ps_custom_object_empty():
    obj = dotnet.PSCustomObject()
    assert obj.PSAdapted == {}
    assert obj.PSExtended == {}
    assert obj.PSTypeNames == ['System.Management.Automation.PSCustomObject', 'System.Object']

    obj.PSObject.to_string = 'to string value'
    element = SerializerV2().serialize(obj)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN>' \
                     '<ToString>to string value</ToString>' \
                     '</Obj>'

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSCustomObject)
    assert actual.PSAdapted == {}
    assert actual.PSExtended == {}
    assert actual.PSTypeNames == ['System.Management.Automation.PSCustomObject', 'System.Object']
    assert str(actual) == 'to string value'


def test_ps_custom_object_type_name():
    obj = dotnet.PSCustomObject({'PSTypeName': 'MyType', 'My Property': 'Value'})
    assert obj.PSAdapted == {}
    assert obj.PSExtended == {'My Property': 'Value'}
    assert obj.PSTypeNames == ['MyType', 'System.Management.Automation.PSCustomObject', 'System.Object']

    obj.PSObject.to_string = 'to string value'
    element = SerializerV2().serialize(obj)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>MyType</T><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN>' \
                     '<MS><S N="My Property">Value</S></MS><ToString>to string value</ToString></Obj>'

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSObject)
    assert actual.PSAdapted == {}
    assert actual.PSExtended == {'My Property': 'Value'}
    assert actual.PSTypeNames == ['Deserialized.MyType', 'Deserialized.System.Management.Automation.PSCustomObject', 'Deserialized.System.Object']
    assert str(actual) == 'to string value'


def test_ps_flags_operators():
    class FlagTest(dotnet.PSFlagBase, dotnet.PSInt):
        PSObject = dotnet.PSObjectMeta(type_names=['System.FlagTest', 'System.Object'])

        none = 0
        Flag1 = 1
        Flag2 = 2
        Flag3 = 4
        Flag4 = 8

    val = FlagTest.none
    assert str(val) == 'None'

    val |= FlagTest.Flag1 | FlagTest.Flag2
    assert isinstance(val, FlagTest)
    assert str(val) == 'Flag1, Flag2'
    assert val == 3

    val &= FlagTest.Flag1
    assert isinstance(val, FlagTest)
    assert str(val) == 'Flag1'
    assert val == 1

    val = (FlagTest.Flag1 | FlagTest.Flag2) ^ FlagTest.Flag1
    assert isinstance(val, FlagTest)
    assert str(val) == 'Flag2'
    assert val == 2

    val = val << 2
    assert isinstance(val, FlagTest)
    assert str(val) == 'Flag4'
    assert val == 8

    val = val >> 1
    assert isinstance(val, FlagTest)
    assert str(val) == 'Flag3'
    assert val == 4

    val &= ~val
    assert isinstance(val, FlagTest)
    assert str(val) == 'None'
    assert val == 0


def test_ps_string():
    ps_string = dotnet.PSString(COMPLEX_STRING)
    element = SerializerV2().serialize(ps_string)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<S>%s</S>' % COMPLEX_ENCODED_STRING

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSString)
    assert isinstance(actual, six.text_type)
    assert actual == ps_string
    assert actual.PSObject.type_names == ['System.String', 'System.Object']

    # Check that we can still slice a string
    sliced_actual = actual[:6]
    assert isinstance(sliced_actual, dotnet.PSString)
    assert isinstance(sliced_actual, six.text_type)
    assert sliced_actual == COMPLEX_STRING[:6]


def test_ps_string_with_properties():
    n_special_str = to_string(COMPLEX_STRING)

    ps_string = dotnet.PSString(COMPLEX_STRING)
    ps_string.PSObject.extended_properties.append(dotnet.PSPropertyInfo('TestProperty'))
    ps_string.PSObject.extended_properties.append(dotnet.PSPropertyInfo(n_special_str))
    ps_string.TestProperty = u'property value'
    ps_string[n_special_str] = u'other value'
    element = SerializerV2().serialize(ps_string)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><S>{0}</S><MS>' \
                     '<S N="TestProperty">property value</S>' \
                     '<S N="{0}">other value</S></MS></Obj>'.format(COMPLEX_ENCODED_STRING)

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSString)
    assert isinstance(actual, six.text_type)
    assert actual == ps_string
    assert actual['TestProperty'] == 'property value'
    assert actual.TestProperty == 'property value'
    assert actual[n_special_str] == 'other value'
    assert actual.PSObject.type_names == ['System.String', 'System.Object']

    # Check that we can still slice a string and properties are still preserved
    sliced_actual = actual[:6]
    assert isinstance(sliced_actual, dotnet.PSString)
    assert isinstance(sliced_actual, six.text_type)
    assert sliced_actual == COMPLEX_STRING[:6]
    assert sliced_actual['TestProperty'] == 'property value'
    assert sliced_actual[n_special_str] == 'other value'

    # Check that a new PSString instance does not inherit the same PSObject values
    new_str = dotnet.PSString('other')
    assert new_str.PSObject.adapted_properties == []
    assert new_str.PSObject.extended_properties == []


@pytest.mark.parametrize('input_val', [
    'decimal',
    'text',
])
def test_ps_char(input_val):
    sparkles = b"\x28\x27".decode('utf-16-le')
    if input_val == 'decimal':
        input_val = ord(sparkles)

    else:
        input_val = sparkles

    ps_char = dotnet.PSChar(input_val)
    assert isinstance(ps_char, dotnet.PSChar)
    assert isinstance(ps_char, int)
    assert str(ps_char) == to_string(sparkles)

    element = SerializerV2().serialize(ps_char)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<C>%s</C>' % int(ps_char)

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSChar)
    assert isinstance(actual, int)
    assert actual == ps_char
    assert int(actual) == ord(sparkles)
    assert str(actual) == sparkles
    assert actual.PSTypeNames == ['System.Char', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_val, expected', [
    (0, 0),
    (u'\u0000', 0),
    (1, 1),
    ('1', 49),
    (b"\xc3\xa9", 233),
    (u"é", 233),
    (65535, 65535),
    (u"\uffff", 65535),
])
def test_ps_char_edge_cases(input_val, expected):
    str_expected = to_string(dotnet.unichr(expected))

    actual = dotnet.PSChar(input_val)
    assert isinstance(actual, dotnet.PSChar)
    assert actual == expected
    assert str(actual) == str_expected

    element = SerializerV2().serialize(actual)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<C>%s</C>' % expected

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSChar)
    assert actual == expected
    assert str(actual) == str_expected
    assert actual.PSTypeNames == ['System.Char', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_val', [
    b"\xF0\x9D\x84\x9E".decode('utf-8'),
    "2c",
])
def test_ps_char_invalid_string(input_val):
    with pytest.raises(ValueError, match="A PSChar must be 1 UTF-16 codepoint"):
        dotnet.PSChar(input_val)


@pytest.mark.parametrize('input_val', [-1, 65536])
def test_ps_char_invalid_int(input_val):
    with pytest.raises(ValueError, match='A PSChar must be between 0 and 65535.'):
        dotnet.PSChar(input_val)


def test_ps_char_with_properties():
    ps_char = dotnet.PSChar('c')
    ps_char.PSObject.extended_properties.append(dotnet.PSPropertyInfo('Test Property'))
    ps_char['Test Property'] = 1

    element = SerializerV2().serialize(ps_char)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    assert actual == '<Obj RefId="0"><C>99</C><MS><I32 N="Test Property">1</I32></MS></Obj>'

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSChar)
    assert isinstance(actual, int)
    assert actual == 99
    assert str(actual) == 'c'
    assert actual['Test Property'] == 1
    assert isinstance(actual['Test Property'], dotnet.PSInt)
    assert actual.PSTypeNames == ['System.Char', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_val, expected', [
    (True, True),
    ('value', True),
    (1, True),
    (False, False),
    ('', False),
    (0, False),
])
def test_ps_bool(input_val, expected):
    actual = dotnet.PSBool(input_val)
    assert isinstance(actual, dotnet.PSBool)
    assert isinstance(actual, bool)
    assert actual == expected

    element = SerializerV2().serialize(actual)

    actual = to_string(ET.tostring(element, encoding='utf-8'))
    print(actual)
    assert actual == '<B>%s</B>' % str(expected).lower()

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSBool)
    assert isinstance(actual, bool)
    assert not isinstance(actual, dotnet.PSObject)  # We cannot subclass bool so this won't be a PSObject
    assert actual == expected


def test_ps_bool_deserialize_extended():
    # This just makes sure we don't choke on an extended primitive bool and we still get the raw value back.
    xml_val = '<Obj RefId="0"><B>true</B><MS><I32 N="Test Property">1</I32></MS></Obj>'
    element = ET.fromstring(xml_val)

    actual = SerializerV2().deserialize(element)
    assert isinstance(actual, dotnet.PSBool)
    assert isinstance(actual, bool)
    assert not isinstance(actual, dotnet.PSObject)
    assert actual is True
