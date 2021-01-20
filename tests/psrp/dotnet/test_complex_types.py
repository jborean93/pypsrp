# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import psrp.dotnet.complex_types as complex_types
import pytest
import queue
import re
import xml.etree.ElementTree as ElementTree

from psrp.dotnet.primitive_types import (
    PSChar,
    PSInt,
    PSUInt16,
    PSInt64,
)

from psrp.dotnet.ps_base import (
    PSGenericBase,
    PSNoteProperty,
    PSObject,
)

from psrp.dotnet.serializer import (
    deserialize,
    serialize,
)

# Contains control characters, non-ascii chars, and chars that are surrogate pairs in UTF-16
COMPLEX_STRING = u'treble clef\n _x0000_ _X0000_ %s café' % b"\xF0\x9D\x84\x9E".decode('utf-8')
COMPLEX_ENCODED_STRING = u'treble clef_x000A_ _x005F_x0000_ _x005F_X0000_ _xD834__xDD1E_ café'


def test_ps_custom_object_empty():
    obj = complex_types.PSCustomObject()
    assert obj.PSTypeNames == ['System.Management.Automation.PSCustomObject', 'System.Object']

    obj.PSObject.to_string = 'to string value'
    element = serialize(obj)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN>' \
                     '<ToString>to string value</ToString>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSCustomObject)
    assert actual.PSTypeNames == ['System.Management.Automation.PSCustomObject', 'System.Object']
    assert str(actual) == 'to string value'


def test_ps_custom_object_type_name():
    obj = complex_types.PSCustomObject(**{'PSTypeName': 'MyType', 'My Property': 'Value'})
    assert obj.PSTypeNames == ['MyType', 'System.Management.Automation.PSCustomObject', 'System.Object']

    obj.PSObject.to_string = 'to string value'
    element = serialize(obj)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>MyType</T>' \
                     '<T>System.Management.Automation.PSCustomObject</T>' \
                     '<T>System.Object</T></TN>' \
                     '<MS><S N="My Property">Value</S></MS>' \
                     '<ToString>to string value</ToString>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, PSObject)
    assert actual.PSTypeNames == ['Deserialized.MyType', 'Deserialized.System.Management.Automation.PSCustomObject',
                                  'Deserialized.System.Object']
    assert str(actual) == 'to string value'


def test_ps_stack():
    ps_value = complex_types.PSStack(['abc', 123, PSInt64(1)])
    ps_value.append(True)
    assert isinstance(ps_value, complex_types.PSStack)
    assert isinstance(ps_value, list)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0"><T>System.Collections.Stack</T><T>System.Object</T></TN>' \
                     '<STK><S>abc</S><I32>123</I32><I64>1</I64><B>true</B></STK>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSStack)
    assert isinstance(actual, list)
    assert actual == ['abc', 123, PSInt64(1), True]
    # Verify we can still index the list
    assert actual[0] == 'abc'
    assert actual[1] == 123
    assert actual[2] == PSInt64(1)
    assert actual[3] is True
    assert actual.PSTypeNames == ['System.Collections.Stack', 'System.Object']


def test_ps_stack_with_properties():
    ps_value = complex_types.PSStack([0, 2, PSChar('a')])
    ps_value.PSObject.extended_properties.append(PSNoteProperty('1'))
    ps_value[1] = 1
    ps_value['1'] = complex_types.PSStack(['123', 123])

    # Make sure we can access the stack using an index and the properties with a string.
    assert ps_value[1] == 1
    assert isinstance(ps_value['1'], complex_types.PSStack)
    assert ps_value['1'] == ['123', 123]

    # Check that appending an item doesn't clear our properties
    ps_value.append(2)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>System.Collections.Stack</T><T>System.Object</T></TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="1"><TNRef RefId="0" />' \
                     '<STK><S>123</S><I32>123</I32></STK>' \
                     '</Obj>' \
                     '</MS>' \
                     '<STK><I32>0</I32><I32>1</I32><C>97</C><I32>2</I32></STK>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSStack)
    assert isinstance(actual, list)
    assert actual == [0, 1, PSChar('a'), 2]
    # Verify we can still index the list
    assert actual[0] == 0
    assert actual[1] == 1
    assert actual[2] == PSChar('a')
    assert actual[3] == 2

    # Verify we can access the extended prop using a string index.
    assert isinstance(actual['1'], complex_types.PSStack)
    assert actual['1'] == complex_types.PSStack(['123', 123])

    assert actual.PSTypeNames == ['System.Collections.Stack', 'System.Object']


def test_ps_queue():
    ps_value = complex_types.PSQueue()
    ps_value.put('abc')
    ps_value.put(123)
    ps_value.put(PSInt64(1))
    ps_value.put(complex_types.PSQueue())
    assert isinstance(ps_value, complex_types.PSQueue)
    assert isinstance(ps_value, queue.Queue)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>System.Collections.Queue</T><T>System.Object</T></TN>' \
                     '<QUE>' \
                     '<S>abc</S>' \
                     '<I32>123</I32>' \
                     '<I64>1</I64>' \
                     '<Obj RefId="1"><TNRef RefId="0" /><QUE /></Obj>' \
                     '</QUE>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSQueue)
    assert isinstance(actual, queue.Queue)

    assert actual.get() == 'abc'
    assert actual.get() == 123
    assert actual.get() == PSInt64(1)

    queue_entry = actual.get()
    assert isinstance(queue_entry, complex_types.PSQueue)
    assert isinstance(queue_entry, queue.Queue)
    with pytest.raises(queue.Empty):
        queue_entry.get(block=False)

    with pytest.raises(queue.Empty):
        actual.get(block=False)

    assert actual.PSTypeNames == ['System.Collections.Queue', 'System.Object']


def test_ps_queue_from_queue():
    q = queue.Queue()
    q.put(1)
    q.put('1')
    q.put('a')

    element = serialize(q)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0"><T>System.Collections.Queue</T><T>System.Object</T></TN>' \
                     '<QUE><I32>1</I32><S>1</S><S>a</S></QUE>' \
                     '</Obj>'


def test_ps_queue_with_properties():
    ps_value = complex_types.PSQueue()
    ps_value.put('abc')
    ps_value.put(123)
    ps_value.put(PSInt64(1))
    ps_value.put(complex_types.PSQueue())

    ps_value.PSObject.extended_properties.append(PSNoteProperty('1'))
    ps_value['1'] = complex_types.PSQueue()
    ps_value['1'].put('entry')

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>System.Collections.Queue</T><T>System.Object</T></TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="1"><TNRef RefId="0" /><QUE><S>entry</S></QUE></Obj>' \
                     '</MS>' \
                     '<QUE>' \
                     '<S>abc</S>' \
                     '<I32>123</I32>' \
                     '<I64>1</I64>' \
                     '<Obj RefId="2"><TNRef RefId="0" /><QUE /></Obj>' \
                     '</QUE>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSQueue)
    assert isinstance(actual, queue.Queue)

    assert actual.get() == 'abc'
    assert actual.get() == 123
    assert actual.get() == PSInt64(1)

    queue_entry = actual.get()
    assert isinstance(queue_entry, complex_types.PSQueue)
    assert isinstance(queue_entry, queue.Queue)
    with pytest.raises(queue.Empty):
        queue_entry.get(block=False)

    with pytest.raises(queue.Empty):
        actual.get(block=False)

    prop_queue = actual['1']
    assert isinstance(prop_queue, complex_types.PSQueue)
    assert isinstance(prop_queue, queue.Queue)
    assert prop_queue.get() == 'entry'
    with pytest.raises(queue.Empty):
        prop_queue.get(block=False)

    assert actual.PSTypeNames == ['System.Collections.Queue', 'System.Object']


def test_ps_list():
    ps_value = complex_types.PSList(['abc', 123, PSInt64(1)])
    ps_value.append(True)
    assert isinstance(ps_value, complex_types.PSList)
    assert isinstance(ps_value, list)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0"><T>System.Collections.ArrayList</T><T>System.Object</T></TN>' \
                     '<LST><S>abc</S><I32>123</I32><I64>1</I64><B>true</B></LST>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSList)
    assert isinstance(actual, list)
    assert actual == ['abc', 123, PSInt64(1), True]
    # Verify we can still index the list
    assert actual[0] == 'abc'
    assert actual[1] == 123
    assert actual[2] == PSInt64(1)
    assert actual[3] is True
    assert actual.PSTypeNames == ['System.Collections.ArrayList', 'System.Object']


def test_ps_list_from_list():
    element = serialize([1, '1', 'a'])
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0"><T>System.Collections.ArrayList</T><T>System.Object</T></TN>' \
                     '<LST><I32>1</I32><S>1</S><S>a</S></LST>' \
                     '</Obj>'


def test_ps_list_with_properties():
    ps_value = complex_types.PSList([0, 2, PSChar('a')])
    ps_value.PSObject.extended_properties.append(PSNoteProperty('1'))
    ps_value[1] = 1
    ps_value['1'] = complex_types.PSList(['123', 123])

    # Make sure we can access the stack using an index and the properties with a string.
    assert ps_value[1] == 1
    assert isinstance(ps_value['1'], complex_types.PSList)
    assert ps_value['1'] == ['123', 123]

    # Check that appending an item doesn't clear our properties
    ps_value.append(2)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>System.Collections.ArrayList</T><T>System.Object</T></TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="1"><TNRef RefId="0" />' \
                     '<LST><S>123</S><I32>123</I32></LST>' \
                     '</Obj>' \
                     '</MS>' \
                     '<LST><I32>0</I32><I32>1</I32><C>97</C><I32>2</I32></LST>' \
                     '</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSList)
    assert isinstance(actual, list)
    assert actual == [0, 1, PSChar('a'), 2]
    # Verify we can still index the list
    assert actual[0] == 0
    assert actual[1] == 1
    assert actual[2] == PSChar('a')
    assert actual[3] == 2

    # Verify we can access the extended prop using a string index.
    assert isinstance(actual['1'], complex_types.PSList)
    assert actual['1'] == complex_types.PSList(['123', 123])

    assert actual.PSTypeNames == ['System.Collections.ArrayList', 'System.Object']


def test_ps_generic_list_initialise_fail():
    expected = re.escape('Type PSGenericList cannot be instantiated; use PSGenericList[...]() to define the 1 '
                         'generic type required.')
    with pytest.raises(TypeError, match=expected):
        complex_types.PSGenericList()


def test_ps_generic_list():
    expected_err = re.escape("invalid literal for int() with base 10: 'a'")
    with pytest.raises(ValueError, match=expected_err):
        complex_types.PSGenericList[PSUInt16](['a'])

    original = ['1', 2, PSInt(3), complex_types.ErrorCategory.NotSpecified, None]
    ps_value = complex_types.PSGenericList[PSUInt16](original)

    assert len(ps_value) == 5
    assert isinstance(ps_value[0], PSUInt16)
    assert ps_value[0] == 1
    assert isinstance(ps_value[1], PSUInt16)
    assert ps_value[1] == 2
    assert isinstance(ps_value[2], PSUInt16)
    assert ps_value[2] == 3
    assert isinstance(ps_value[3], PSUInt16)
    assert ps_value[3] == 0
    assert isinstance(ps_value[4], PSUInt16)
    assert ps_value[4] == 0

    with pytest.raises(ValueError, match=expected_err):
        ps_value.append('a')

    ps_value.append('10')
    assert len(ps_value) == 6
    assert isinstance(ps_value[5], PSUInt16)
    assert ps_value[5] == 10

    with pytest.raises(ValueError, match=expected_err):
        ps_value.extend([1, 'a'])

    ps_value.extend([1, '2'])
    assert len(ps_value) == 8
    assert isinstance(ps_value[6], PSUInt16)
    assert ps_value[6] == 1
    assert isinstance(ps_value[7], PSUInt16)
    assert ps_value[7] == 2

    ps_value.insert(0, '12')
    assert len(ps_value) == 9
    assert isinstance(ps_value[0], PSUInt16)
    assert ps_value[0] == 12
    assert ps_value[1] == 1

    ps_value[0] = '20'
    assert len(ps_value) == 9
    assert isinstance(ps_value[0], PSUInt16)
    assert ps_value[0] == 20

    ps_value[2:] = [1, '2']
    assert len(ps_value) == 4
    assert isinstance(ps_value[0], PSUInt16)
    assert ps_value[0] == 20
    assert isinstance(ps_value[1], PSUInt16)
    assert ps_value[1] == 1
    assert isinstance(ps_value[2], PSUInt16)
    assert ps_value[2] == 1
    assert isinstance(ps_value[3], PSUInt16)
    assert ps_value[3] == 2

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Collections.Generic.List`1[[System.UInt16]]</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<LST>' \
                     '<U16>20</U16>' \
                     '<U16>1</U16>' \
                     '<U16>1</U16>' \
                     '<U16>2</U16>' \
                     '</LST>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, complex_types.PSList)
    # We don't support generic base deserialization
    assert not isinstance(ps_value, complex_types.PSGenericList)
    assert not isinstance(ps_value, PSGenericBase)
    assert len(ps_value) == 4
    assert isinstance(ps_value[0], PSUInt16)
    assert ps_value[0] == 20
    assert isinstance(ps_value[1], PSUInt16)
    assert ps_value[1] == 1
    assert isinstance(ps_value[2], PSUInt16)
    assert ps_value[2] == 1
    assert isinstance(ps_value[3], PSUInt16)
    assert ps_value[3] == 2


@pytest.mark.parametrize('input_value, expected', [
    ({}, '<DCT />'),
    ({'a': 'a'}, '<DCT><En><S N="Key">a</S><S N="Value">a</S></En></DCT>'),
    ({'a': 1}, '<DCT><En><S N="Key">a</S><I32 N="Value">1</I32></En></DCT>'),
    ({1: PSChar('a'), PSInt64(10): ['abc', 456]},
     '<DCT><En><I32 N="Key">1</I32><C N="Value">97</C></En>'
     '<En><I64 N="Key">10</I64><Obj RefId="1" N="Value">'
     '<TN RefId="1"><T>System.Collections.ArrayList</T><T>System.Object</T></TN>'
     '<LST><S>abc</S><I32>456</I32></LST></Obj></En></DCT>')
])
def test_ps_dict(input_value, expected):
    ps_value = complex_types.PSDict(input_value)
    assert isinstance(ps_value, complex_types.PSDict)
    assert isinstance(ps_value, dict)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><TN RefId="0"><T>System.Collections.Hashtable</T><T>System.Object</T></TN>' \
                     f'{expected}' \
                     f'</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSDict)
    assert isinstance(actual, dict)
    assert actual == input_value
    assert actual.PSTypeNames == ['System.Collections.Hashtable', 'System.Object']


def test_ps_dict_from_dict():
    element = serialize({'abc': 'def', 1: 2, PSChar('a'): complex_types.PSList([1, 2])})
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Obj RefId="0"><TN RefId="0"><T>System.Collections.Hashtable</T><T>System.Object</T></TN>' \
                     '<DCT>' \
                     '<En>' \
                     '<S N="Key">abc</S>' \
                     '<S N="Value">def</S>' \
                     '</En>' \
                     '<En>' \
                     '<I32 N="Key">1</I32>' \
                     '<I32 N="Value">2</I32>' \
                     '</En>' \
                     '<En>' \
                     '<C N="Key">97</C>' \
                     '<Obj RefId="1" N="Value">' \
                     '<TN RefId="1"><T>System.Collections.ArrayList</T><T>System.Object</T></TN>' \
                     '<LST><I32>1</I32><I32>2</I32></LST>' \
                     '</Obj>' \
                     '</En>' \
                     '</DCT>' \
                     '</Obj>'


def test_ps_dict_with_properties():
    ps_value = complex_types.PSDict({})
    ps_value.PSObject.extended_properties.append(PSNoteProperty('key'))

    complex_prop = PSNoteProperty(COMPLEX_STRING)
    ps_value.PSObject.extended_properties.append(complex_prop)

    other_prop = PSNoteProperty('other', 'prop')
    ps_value.PSObject.extended_properties.append(other_prop)

    # Setting a value will always set it in the dict, even adding a new dict entry if the prop exists
    ps_value['key'] = 'dict'
    ps_value[COMPLEX_STRING] = 'dict'

    # We can still set a property using dot notation like in PowerShell
    ps_value.key = 'prop'

    # Or on the property object itself if we cannot access it like a Python attribute
    complex_prop.set_value('prop', ps_value)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><TN RefId="0"><T>System.Collections.Hashtable</T><T>System.Object</T></TN>' \
                     f'<MS>' \
                     f'<S N="key">prop</S>' \
                     f'<S N="{COMPLEX_ENCODED_STRING}">prop</S>' \
                     f'<S N="other">prop</S>' \
                     f'</MS>' \
                     f'<DCT>' \
                     f'<En><S N="Key">key</S><S N="Value">dict</S></En>' \
                     f'<En><S N="Key">{COMPLEX_ENCODED_STRING}</S><S N="Value">dict</S></En>' \
                     f'</DCT>' \
                     f'</Obj>'

    actual = deserialize(element)
    assert isinstance(actual, complex_types.PSDict)
    assert isinstance(actual, dict)

    # In the case of a prop shadowing a dict, [] will favour the dict, and . will only get props
    assert actual['key'] == 'dict'
    assert actual.key == 'prop'

    # If only the prop exists under that name both [] and . will work
    assert actual['other'] == 'prop'
    assert actual.other == 'prop'

    # Because we cannot use special characters using the dot notation, we can only get shadowed props using the raw
    # PSObject property list
    assert actual.PSObject.extended_properties[1].name == COMPLEX_STRING
    assert actual.PSObject.extended_properties[1].get_value(actual) == 'prop'


def test_psrp_pipeline_result_types():
    value = complex_types.PipelineResultTypes.Output | complex_types.PipelineResultTypes.Error
    assert value == 3
    assert str(value) == 'Output, Error'

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<I32>3</I32>' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.Runspaces.PipelineResultTypes</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>Output, Error</ToString>' \
                     '</Obj>'

    value = deserialize(element)
    assert isinstance(value, complex_types.PipelineResultTypes)
    assert value == complex_types.PipelineResultTypes.Output | complex_types.PipelineResultTypes.Error


def test_console_color():
    value = complex_types.ConsoleColor.DarkRed
    assert value == 4
    assert str(value) == 'DarkRed'

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<I32>4</I32>' \
                     '<TN RefId="0">' \
                     '<T>System.ConsoleColor</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>DarkRed</ToString>' \
                     '</Obj>'

    value = deserialize(element)
    assert isinstance(value, complex_types.ConsoleColor)
    assert value == complex_types.ConsoleColor.DarkRed


def test_coordinates():
    value = complex_types.Coordinates(10, 412)
    assert value.X == 10
    assert value.Y == 412

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.Host.Coordinates</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<Props>' \
                     '<I32 N="X">10</I32>' \
                     '<I32 N="Y">412</I32>' \
                     '</Props>' \
                     '</Obj>'

    value = deserialize(element)
    assert isinstance(value, PSObject)
    assert isinstance(value, complex_types.Coordinates)
    assert value.X == 10
    assert value.Y == 412


def test_size():
    value = complex_types.Size(10, 412)
    assert value.Width == 10
    assert value.Height == 412

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.Host.Size</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<Props>' \
                     '<I32 N="Width">10</I32>' \
                     '<I32 N="Height">412</I32>' \
                     '</Props>' \
                     '</Obj>'

    value = deserialize(element)
    assert isinstance(value, PSObject)
    assert isinstance(value, complex_types.Size)
    assert value.Width == 10
    assert value.Height == 412


def test_ps_thread_options():
    state = complex_types.PSThreadOptions.UseNewThread
    assert str(state) == 'UseNewThread'

    element = serialize(state)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<I32>1</I32>' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.Runspaces.PSThreadOptions</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>UseNewThread</ToString>' \
                     '</Obj>'

    state = deserialize(element)
    assert isinstance(state, complex_types.PSThreadOptions)
    assert state == complex_types.PSThreadOptions.UseNewThread


def test_apartment_state():
    state = complex_types.ApartmentState.STA
    assert str(state) == 'STA'

    element = serialize(state)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<I32>0</I32>' \
                     '<TN RefId="0"><T>System.Threading.ApartmentState</T><T>System.Enum</T>' \
                     '<T>System.ValueType</T><T>System.Object</T></TN>' \
                     '<ToString>STA</ToString>' \
                     '</Obj>'

    state = deserialize(element)
    assert isinstance(state, complex_types.ApartmentState)
    assert state == complex_types.ApartmentState.STA


def test_remote_stream_options():
    options = complex_types.RemoteStreamOptions.AddInvocationInfoToDebugRecord | \
              complex_types.RemoteStreamOptions.AddInvocationInfoToErrorRecord
    assert str(options) == 'AddInvocationInfoToErrorRecord, AddInvocationInfoToDebugRecord'

    element = serialize(options)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<I32>5</I32>' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.RemoteStreamOptions</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>AddInvocationInfoToErrorRecord, AddInvocationInfoToDebugRecord</ToString>' \
                     '</Obj>'

    options = deserialize(element)
    assert isinstance(options, complex_types.RemoteStreamOptions)
    assert options == complex_types.RemoteStreamOptions.AddInvocationInfoToDebugRecord | \
        complex_types.RemoteStreamOptions.AddInvocationInfoToErrorRecord


def test_error_category():
    error = complex_types.ErrorCategory.CloseError
    assert str(error) == 'CloseError'

    element = serialize(error)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<I32>2</I32>' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.ErrorCategory</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>CloseError</ToString>' \
                     '</Obj>'

    error = deserialize(element)
    assert isinstance(error, complex_types.ErrorCategory)
    assert error == complex_types.ErrorCategory.CloseError


def test_error_record_plain():
    value = complex_types.ErrorRecord(
        Exception=complex_types.NETException('Exception'),
        CategoryInfo=complex_types.ErrorCategoryInfo(),
    )

    assert value.Exception.Message == 'Exception'
    assert str(value) == 'Exception'
    assert value.CategoryInfo.Category == complex_types.ErrorCategory.NotSpecified
    assert value.CategoryInfo.Activity is None
    assert value.CategoryInfo.Reason is None
    assert value.CategoryInfo.TargetName is None
    assert value.CategoryInfo.TargetType is None
    assert value.TargetObject is None
    assert value.FullyQualifiedErrorId is None
    assert value.InvocationInfo is None
    assert value.ErrorDetails is None
    assert value.PipelineIterationInfo is None
    assert value.ScriptStackTrace is None

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.ErrorRecord</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="Exception">' \
                     '<TN RefId="1">' \
                     '<T>System.Exception</T>' \
                     '<T>System.Object</T>' \
                     '</TN><Props>' \
                     '<S N="Message">Exception</S>' \
                     '<Nil N="Data" />' \
                     '<Nil N="HelpLink" />' \
                     '<Nil N="HResult" />' \
                     '<Nil N="InnerException" />' \
                     '<Nil N="Source" />' \
                     '<Nil N="StackTrace" />' \
                     '<Nil N="TargetSite" />' \
                     '</Props></Obj>' \
                     '<Nil N="TargetObject" />' \
                     '<Nil N="FullyQualifiedErrorId" />' \
                     '<Nil N="InvocationInfo" />' \
                     '<I32 N="ErrorCategory_Category">0</I32>' \
                     '<Nil N="ErrorCategory_Activity" />' \
                     '<Nil N="ErrorCategory_Reason" />' \
                     '<Nil N="ErrorCategory_TargetName" />' \
                     '<Nil N="ErrorCategory_TargetType" />' \
                     '<S N="ErrorCategory_Message">NotSpecified (:) [], </S>' \
                     '<B N="SerializeExtendedInfo">false</B>' \
                     '</MS>' \
                     '<ToString>Exception</ToString>' \
                     '</Obj>'

    value = deserialize(element)

    assert isinstance(value, complex_types.ErrorRecord)
    assert value.serialize_extended_info is False
    assert value.Exception.Message == 'Exception'
    assert str(value) == 'Exception'
    assert isinstance(value.CategoryInfo, complex_types.ErrorCategoryInfo)
    assert value.CategoryInfo.Category == complex_types.ErrorCategory.NotSpecified
    assert value.CategoryInfo.Activity is None
    assert value.CategoryInfo.Reason is None
    assert value.CategoryInfo.TargetName is None
    assert value.CategoryInfo.TargetType is None
    assert value.TargetObject is None
    assert value.FullyQualifiedErrorId is None
    assert value.InvocationInfo is None
    assert value.ErrorDetails is None
    assert value.PipelineIterationInfo is None
    assert value.ScriptStackTrace is None


def test_error_record_with_error_details():
    value = complex_types.ErrorRecord(
        Exception=complex_types.NETException('Exception'),
        CategoryInfo=complex_types.ErrorCategoryInfo(
            Category=complex_types.ErrorCategory.CloseError,
            Activity='Closing a file',
            Reason='File is locked',
        ),
        TargetObject='C:\\temp\\file.txt',
        FullyQualifiedErrorId='CloseError',
        ErrorDetails=complex_types.ErrorDetails(
            Message='Error Detail Message',
        ),
        ScriptStackTrace='At <1>MyScript.ps1',
    )

    assert value.Exception.Message == 'Exception'
    assert str(value) == 'Error Detail Message'
    assert value.CategoryInfo.Category == complex_types.ErrorCategory.CloseError
    assert value.CategoryInfo.Activity == 'Closing a file'
    assert value.CategoryInfo.Reason == 'File is locked'
    assert value.CategoryInfo.TargetName is None
    assert value.CategoryInfo.TargetType is None
    assert value.TargetObject == 'C:\\temp\\file.txt'
    assert value.FullyQualifiedErrorId == 'CloseError'
    assert value.InvocationInfo is None
    assert value.ErrorDetails.Message == 'Error Detail Message'
    assert value.ErrorDetails.RecommendedAction is None
    assert value.PipelineIterationInfo is None
    assert value.ScriptStackTrace == 'At <1>MyScript.ps1'

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.ErrorRecord</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="Exception">' \
                     '<TN RefId="1">' \
                     '<T>System.Exception</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<Props>' \
                     '<S N="Message">Exception</S>' \
                     '<Nil N="Data" />' \
                     '<Nil N="HelpLink" />' \
                     '<Nil N="HResult" />' \
                     '<Nil N="InnerException" />' \
                     '<Nil N="Source" />' \
                     '<Nil N="StackTrace" />' \
                     '<Nil N="TargetSite" />' \
                     '</Props>' \
                     '</Obj>' \
                     '<S N="TargetObject">C:\\temp\\file.txt</S>' \
                     '<S N="FullyQualifiedErrorId">CloseError</S>' \
                     '<Nil N="InvocationInfo" />' \
                     '<I32 N="ErrorCategory_Category">2</I32>' \
                     '<S N="ErrorCategory_Activity">Closing a file</S>' \
                     '<S N="ErrorCategory_Reason">File is locked</S>' \
                     '<Nil N="ErrorCategory_TargetName" />' \
                     '<Nil N="ErrorCategory_TargetType" />' \
                     '<S N="ErrorCategory_Message">CloseError (:) [Closing a file], File is locked</S>' \
                     '<S N="ErrorDetails_Message">Error Detail Message</S>' \
                     '<Nil N="ErrorDetails_RecommendedAction" />' \
                     '<S N="ErrorDetails_ScriptStackTrace">At &lt;1&gt;MyScript.ps1</S>' \
                     '<B N="SerializeExtendedInfo">false</B>' \
                     '</MS>' \
                     '<ToString>Error Detail Message</ToString>' \
                     '</Obj>'

    value = deserialize(element)

    assert isinstance(value, complex_types.ErrorRecord)
    assert value.serialize_extended_info is False
    assert value.Exception.Message == 'Exception'
    assert str(value) == 'Error Detail Message'
    assert value.CategoryInfo.Category == complex_types.ErrorCategory.CloseError
    assert value.CategoryInfo.Activity == 'Closing a file'
    assert value.CategoryInfo.Reason == 'File is locked'
    assert value.CategoryInfo.TargetName is None
    assert value.CategoryInfo.TargetType is None
    assert value.TargetObject == 'C:\\temp\\file.txt'
    assert value.FullyQualifiedErrorId == 'CloseError'
    assert value.InvocationInfo is None
    assert value.ErrorDetails.Message == 'Error Detail Message'
    assert value.ErrorDetails.RecommendedAction is None
    assert value.PipelineIterationInfo is None
    assert value.ScriptStackTrace == 'At <1>MyScript.ps1'


def test_error_record_with_invocation_info():
    value = complex_types.ErrorRecord(
        Exception=complex_types.NETException('Exception'),
        CategoryInfo=complex_types.ErrorCategoryInfo(),
        InvocationInfo=complex_types.InvocationInfo(
            BoundParameters=complex_types.PSDict(Path='C:\\temp\\file.txt'),
            CommandOrigin=complex_types.CommandOrigin.Runspace,
            ExpectingInput=False,
            HistoryId=10,
            InvocationName='Remove-Item',
            Line=10,
            OffsetInLine=20,
            PipelineLength=30,
            PipelinePosition=40,
            PositionMessage='position message',
            UnboundArguments=[True],
        ),
        PipelineIterationInfo=['1'],
    )

    assert value.Exception.Message == 'Exception'
    assert str(value) == 'Exception'
    assert value.CategoryInfo.Category == complex_types.ErrorCategory.NotSpecified
    assert value.CategoryInfo.Activity is None
    assert value.CategoryInfo.Reason is None
    assert value.CategoryInfo.TargetName is None
    assert value.CategoryInfo.TargetType is None
    assert value.TargetObject is None
    assert value.FullyQualifiedErrorId is None
    assert value.InvocationInfo.BoundParameters == {'Path': 'C:\\temp\\file.txt'}
    assert value.InvocationInfo.CommandOrigin == complex_types.CommandOrigin.Runspace
    assert value.InvocationInfo.DisplayScriptPosition is None
    assert value.InvocationInfo.ExpectingInput is False
    assert value.InvocationInfo.HistoryId == 10
    assert value.InvocationInfo.InvocationName == 'Remove-Item'
    assert value.InvocationInfo.Line == '10'
    assert value.InvocationInfo.MyCommand is None
    assert value.InvocationInfo.OffsetInLine == 20
    assert value.InvocationInfo.PSCommandPath is None
    assert value.InvocationInfo.PSScriptRoot is None
    assert value.InvocationInfo.PipelineLength == 30
    assert value.InvocationInfo.PipelinePosition == 40
    assert value.InvocationInfo.PositionMessage == 'position message'
    assert value.InvocationInfo.ScriptLineNumber is None
    assert value.InvocationInfo.ScriptName is None
    assert value.InvocationInfo.UnboundArguments == [True]
    assert value.ErrorDetails is None
    assert value.PipelineIterationInfo == [1]
    assert value.ScriptStackTrace is None

    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.ErrorRecord</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="Exception">' \
                     '<TN RefId="1"><T>System.Exception</T>' \
                     '<T>System.Object</T>' \
                     '</TN><Props>' \
                     '<S N="Message">Exception</S>' \
                     '<Nil N="Data" />' \
                     '<Nil N="HelpLink" />' \
                     '<Nil N="HResult" />' \
                     '<Nil N="InnerException" />' \
                     '<Nil N="Source" />' \
                     '<Nil N="StackTrace" />' \
                     '<Nil N="TargetSite" />' \
                     '</Props>' \
                     '</Obj>' \
                     '<Nil N="TargetObject" />' \
                     '<Nil N="FullyQualifiedErrorId" />' \
                     '<Obj RefId="2" N="InvocationInfo">' \
                     '<TN RefId="2">' \
                     '<T>System.Management.Automation.InvocationInfo</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<Props>' \
                     '<Obj RefId="3" N="BoundParameters">' \
                     '<TN RefId="3">' \
                     '<T>System.Collections.Hashtable</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<DCT>' \
                     '<En><S N="Key">Path</S><S N="Value">C:\\temp\\file.txt</S></En>' \
                     '</DCT>' \
                     '</Obj>' \
                     '<Obj RefId="4" N="CommandOrigin">' \
                     '<I32>0</I32>' \
                     '<TN RefId="4">' \
                     '<T>System.Management.Automation.CommandOrigin</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>Runspace</ToString>' \
                     '</Obj>' \
                     '<Nil N="DisplayScriptPosition" />' \
                     '<B N="ExpectingInput">false</B>' \
                     '<I64 N="HistoryId">10</I64>' \
                     '<S N="InvocationName">Remove-Item</S>' \
                     '<S N="Line">10</S>' \
                     '<Nil N="MyCommand" />' \
                     '<I32 N="OffsetInLine">20</I32>' \
                     '<I32 N="PipelineLength">30</I32>' \
                     '<I32 N="PipelinePosition">40</I32>' \
                     '<S N="PositionMessage">position message</S>' \
                     '<Nil N="PSCommandPath" />' \
                     '<Nil N="PSScriptRoot" />' \
                     '<Nil N="ScriptLineNumber" />' \
                     '<Nil N="ScriptName" />' \
                     '<Obj RefId="5" N="UnboundArguments">' \
                     '<TN RefId="5">' \
                     '<T>System.Collections.ArrayList</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<LST>' \
                     '<B>true</B>' \
                     '</LST>' \
                     '</Obj>' \
                     '</Props>' \
                     '</Obj>' \
                     '<I32 N="ErrorCategory_Category">0</I32' \
                     '><Nil N="ErrorCategory_Activity" />' \
                     '<Nil N="ErrorCategory_Reason" />' \
                     '<Nil N="ErrorCategory_TargetName" />' \
                     '<Nil N="ErrorCategory_TargetType" />' \
                     '<S N="ErrorCategory_Message">NotSpecified (:) [], </S>' \
                     '<B N="SerializeExtendedInfo">false</B>' \
                     '</MS>' \
                     '<ToString>Exception</ToString>' \
                     '</Obj>'

    value.serialize_extended_info = True
    element = serialize(value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.ErrorRecord</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<MS>' \
                     '<Obj RefId="1" N="Exception">' \
                     '<TN RefId="1"><T>System.Exception</T>' \
                     '<T>System.Object</T>' \
                     '</TN><Props>' \
                     '<S N="Message">Exception</S>' \
                     '<Nil N="Data" />' \
                     '<Nil N="HelpLink" />' \
                     '<Nil N="HResult" />' \
                     '<Nil N="InnerException" />' \
                     '<Nil N="Source" />' \
                     '<Nil N="StackTrace" />' \
                     '<Nil N="TargetSite" />' \
                     '</Props>' \
                     '</Obj>' \
                     '<Nil N="TargetObject" />' \
                     '<Nil N="FullyQualifiedErrorId" />' \
                     '<Obj RefId="2" N="InvocationInfo">' \
                     '<TN RefId="2">' \
                     '<T>System.Management.Automation.InvocationInfo</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<Props>' \
                     '<Obj RefId="3" N="BoundParameters">' \
                     '<TN RefId="3">' \
                     '<T>System.Collections.Hashtable</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<DCT>' \
                     '<En><S N="Key">Path</S><S N="Value">C:\\temp\\file.txt</S></En>' \
                     '</DCT>' \
                     '</Obj>' \
                     '<Obj RefId="4" N="CommandOrigin">' \
                     '<I32>0</I32>' \
                     '<TN RefId="4">' \
                     '<T>System.Management.Automation.CommandOrigin</T>' \
                     '<T>System.Enum</T>' \
                     '<T>System.ValueType</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<ToString>Runspace</ToString>' \
                     '</Obj>' \
                     '<Nil N="DisplayScriptPosition" />' \
                     '<B N="ExpectingInput">false</B>' \
                     '<I64 N="HistoryId">10</I64>' \
                     '<S N="InvocationName">Remove-Item</S>' \
                     '<S N="Line">10</S>' \
                     '<Nil N="MyCommand" />' \
                     '<I32 N="OffsetInLine">20</I32>' \
                     '<I32 N="PipelineLength">30</I32>' \
                     '<I32 N="PipelinePosition">40</I32>' \
                     '<S N="PositionMessage">position message</S>' \
                     '<Nil N="PSCommandPath" />' \
                     '<Nil N="PSScriptRoot" />' \
                     '<Nil N="ScriptLineNumber" />' \
                     '<Nil N="ScriptName" />' \
                     '<Obj RefId="5" N="UnboundArguments">' \
                     '<TN RefId="5">' \
                     '<T>System.Collections.ArrayList</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<LST>' \
                     '<B>true</B>' \
                     '</LST>' \
                     '</Obj>' \
                     '</Props>' \
                     '</Obj>' \
                     '<I32 N="ErrorCategory_Category">0</I32' \
                     '><Nil N="ErrorCategory_Activity" />' \
                     '<Nil N="ErrorCategory_Reason" />' \
                     '<Nil N="ErrorCategory_TargetName" />' \
                     '<Nil N="ErrorCategory_TargetType" />' \
                     '<S N="ErrorCategory_Message">NotSpecified (:) [], </S>' \
                     '<B N="SerializeExtendedInfo">true</B>' \
                     '<Ref RefId="3" N="InvocationInfo_BoundParameters" />' \
                     '<Ref RefId="4" N="InvocationInfo_CommandOrigin" />' \
                     '<B N="InvocationInfo_ExpectingInput">false</B>' \
                     '<S N="InvocationInfo_InvocationName">Remove-Item</S>' \
                     '<S N="InvocationInfo_Line">10</S>' \
                     '<I32 N="InvocationInfo_OffsetInLine">20</I32>' \
                     '<I64 N="InvocationInfo_HistoryId">10</I64>' \
                     '<Obj RefId="6" N="InvocationInfo_PipelineIterationInfo">' \
                     '<TNRef RefId="5" /><LST />' \
                     '</Obj>' \
                     '<I32 N="InvocationInfo_PipelineLength">30</I32>' \
                     '<I32 N="InvocationInfo_PipelinePosition">40</I32>' \
                     '<Nil N="InvocationInfo_PSScriptRoot" />' \
                     '<Nil N="InvocationInfo_PSCommandPath" />' \
                     '<S N="InvocationInfo_PositionMessage">position message</S>' \
                     '<Nil N="InvocationInfo_ScriptLineNumber" />' \
                     '<Nil N="InvocationInfo_ScriptName" />' \
                     '<Ref RefId="5" N="InvocationInfo_UnboundArguments" />' \
                     '<B N="SerializeExtent">false</B>' \
                     '<Obj RefId="7" N="PipelineIterationInfo">' \
                     '<TN RefId="6">' \
                     '<T>System.Collections.Generic.List`1[[System.Int32]]</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<LST><I32>1</I32></LST>' \
                     '</Obj>' \
                     '</MS>' \
                     '<ToString>Exception</ToString>' \
                     '</Obj>'

    value = deserialize(element)

    assert isinstance(value, complex_types.ErrorRecord)
    assert str(value) == 'Exception'
    assert value.serialize_extended_info is True
    assert value.Exception.Message == 'Exception'

    # The exception contains the original invocation info and so doesn't have the re-computed values.
    assert isinstance(value.Exception.SerializedRemoteInvocationInfo, complex_types.InvocationInfo)
    assert value.Exception.SerializedRemoteInvocationInfo.PositionMessage == 'position message'
    assert value.CategoryInfo.Category == complex_types.ErrorCategory.NotSpecified
    assert value.CategoryInfo.Activity is None
    assert value.CategoryInfo.Reason is None
    assert value.CategoryInfo.TargetName is None
    assert value.CategoryInfo.TargetType is None
    assert value.TargetObject is None
    assert value.FullyQualifiedErrorId is None
    assert value.InvocationInfo.BoundParameters == {'Path': 'C:\\temp\\file.txt'}
    assert value.InvocationInfo.CommandOrigin == complex_types.CommandOrigin.Runspace
    assert value.InvocationInfo.DisplayScriptPosition is None
    assert value.InvocationInfo.ExpectingInput is False
    assert value.InvocationInfo.HistoryId == 10
    assert value.InvocationInfo.InvocationName == 'Remove-Item'
    assert value.InvocationInfo.Line == '10'
    assert value.InvocationInfo.MyCommand is None
    assert value.InvocationInfo.OffsetInLine == 20
    assert value.InvocationInfo.PSCommandPath is None
    assert value.InvocationInfo.PSScriptRoot is None
    assert value.InvocationInfo.PipelineLength == 30
    assert value.InvocationInfo.PipelinePosition == 40
    assert value.InvocationInfo.PositionMessage is None  # Haven't fully implemented these fields.
    assert value.InvocationInfo.ScriptLineNumber is None
    assert value.InvocationInfo.ScriptName is None
    assert value.InvocationInfo.UnboundArguments == [True]
    assert value.ErrorDetails is None
    assert value.PipelineIterationInfo == [1]
    assert value.ScriptStackTrace is None


def test_ps_primitive_dictionary():
    prim_dict = complex_types.PSPrimitiveDictionary({
        'key': 'value',
        'int key': 1,
        'casted': PSChar('a'),
    })

    assert prim_dict['key'] == 'value'
    assert prim_dict['int key'] == 1
    assert prim_dict['casted'] == 97
    assert isinstance(prim_dict['casted'], PSChar)

    element = serialize(prim_dict)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.PSPrimitiveDictionary</T>' \
                     '<T>System.Collections.Hashtable</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<DCT>' \
                     '<En><S N="Key">key</S><S N="Value">value</S></En>' \
                     '<En><S N="Key">int key</S><I32 N="Value">1</I32></En>' \
                     '<En><S N="Key">casted</S><C N="Value">97</C></En>' \
                     '</DCT>' \
                     '</Obj>'

    prim_dict = deserialize(element)
    assert isinstance(prim_dict, complex_types.PSPrimitiveDictionary)
    assert isinstance(prim_dict, dict)
    assert prim_dict['key'] == 'value'
    assert prim_dict['int key'] == 1
    assert prim_dict['casted'] == 97
    assert isinstance(prim_dict['casted'], PSChar)
