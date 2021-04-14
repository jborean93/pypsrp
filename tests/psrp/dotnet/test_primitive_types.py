# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime
import decimal
import psrp.dotnet.primitive_types as primitive_types
import pytest
import re
import uuid
import xml.etree.ElementTree as ElementTree

from psrp.dotnet.crypto import (
    CryptoProvider,
)

from psrp.dotnet.ps_base import (
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


class FakeCryptoProvider(CryptoProvider):

    def decrypt(self, value):
        return value

    def encrypt(self, value):
        return value


@pytest.mark.parametrize('ps_type, tag, type_names', [
    (primitive_types.PSString, 'S', ['System.String', 'System.Object']),
    (primitive_types.PSUri, 'URI', ['System.Uri', 'System.Object']),
    (primitive_types.PSXml, 'XD', ['System.Xml.XmlDocument', 'System.Xml.XmlNode', 'System.Object']),
    (primitive_types.PSScriptBlock, 'SBK', ['System.Management.Automation.ScriptBlock', 'System.Object']),
])
def test_ps_string_types(ps_type, tag, type_names):
    ps_value = ps_type(COMPLEX_STRING)
    element = serialize(ps_value)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == f'<{tag}>{COMPLEX_ENCODED_STRING}</{tag}>'

    actual = deserialize(element)
    assert isinstance(actual, ps_type)
    assert isinstance(actual, str)
    assert actual == ps_value
    assert actual.PSObject.type_names == type_names

    # Check that we can still slice a string
    sliced_actual = actual[:6]
    assert isinstance(sliced_actual, ps_type)
    assert isinstance(sliced_actual, str)
    assert sliced_actual == COMPLEX_STRING[:6]


def test_ps_string_from_string():
    element = serialize(COMPLEX_STRING)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == f'<S>{COMPLEX_ENCODED_STRING}</S>'


@pytest.mark.parametrize('ps_type, tag, type_names', [
    (primitive_types.PSString, 'S', ['System.String', 'System.Object']),
    (primitive_types.PSUri, 'URI', ['System.Uri', 'System.Object']),
    (primitive_types.PSXml, 'XD', ['System.Xml.XmlDocument', 'System.Xml.XmlNode', 'System.Object']),
    (primitive_types.PSScriptBlock, 'SBK', ['System.Management.Automation.ScriptBlock', 'System.Object']),
])
def test_ps_string_with_properties(ps_type, tag, type_names):
    ps_value = ps_type(COMPLEX_STRING)
    ps_value.PSObject.extended_properties.append(PSNoteProperty('TestProperty'))
    ps_value.PSObject.extended_properties.append(PSNoteProperty(COMPLEX_STRING))
    ps_value.TestProperty = ps_type('property value')
    ps_value[COMPLEX_STRING] = ps_type('other value')
    element = serialize(ps_value)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == f'<Obj RefId="0"><{tag}>{COMPLEX_ENCODED_STRING}</{tag}>' \
                     f'<MS><{tag} N="TestProperty">property value</{tag}>' \
                     f'<{tag} N="{COMPLEX_ENCODED_STRING}">other value</{tag}>' \
                     f'</MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, ps_type)
    assert isinstance(actual, str)
    assert actual == ps_value

    assert actual['TestProperty'] == ps_type('property value')
    assert actual.TestProperty == ps_type('property value')
    assert isinstance(actual['TestProperty'], ps_type)

    assert actual[COMPLEX_STRING] == ps_type('other value')
    assert isinstance(actual[COMPLEX_STRING], ps_type)
    assert actual.PSObject.type_names == type_names

    # Check that we can still slice a string and the type is preserved
    sliced_actual = actual[:6]
    assert isinstance(sliced_actual, ps_type)
    assert isinstance(sliced_actual, str)
    assert sliced_actual == COMPLEX_STRING[:6]
    assert sliced_actual.PSObject.extended_properties == []

    # Check that a new instance does not inherit the same PSObject values
    new_str = ps_type('other')
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

    ps_char = primitive_types.PSChar(input_val)
    assert isinstance(ps_char, primitive_types.PSChar)
    assert isinstance(ps_char, int)
    assert str(ps_char) == sparkles

    element = serialize(ps_char)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<C>%s</C>' % int(ps_char)

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSChar)
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
    str_expected = str(chr(expected))

    actual = primitive_types.PSChar(input_val)
    assert isinstance(actual, primitive_types.PSChar)
    assert actual == expected
    assert str(actual) == str_expected

    element = serialize(actual)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<C>%s</C>' % expected

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSChar)
    assert actual == expected
    assert str(actual) == str_expected
    assert actual.PSTypeNames == ['System.Char', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_val', [
    b"\xF0\x9D\x84\x9E".decode('utf-8'),
    "2c",
])
def test_ps_char_invalid_string(input_val):
    with pytest.raises(ValueError, match="A PSChar must be 1 UTF-16 codepoint"):
        primitive_types.PSChar(input_val)


@pytest.mark.parametrize('input_val', [-1, 65536])
def test_ps_char_invalid_int(input_val):
    with pytest.raises(ValueError, match='A PSChar must be between 0 and 65535.'):
        primitive_types.PSChar(input_val)


def test_ps_char_with_properties():
    ps_char = primitive_types.PSChar('c')
    ps_char.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_char['Test Property'] = 1

    element = serialize(ps_char)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0"><C>99</C><MS><I32 N="Test Property">1</I32></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSChar)
    assert isinstance(actual, int)
    assert actual == 99
    assert str(actual) == 'c'
    assert actual['Test Property'] == 1
    assert isinstance(actual['Test Property'], primitive_types.PSInt)
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
    actual = primitive_types.PSBool(input_val)
    assert isinstance(actual, primitive_types.PSBool)
    assert isinstance(actual, bool)
    assert actual == expected

    element = serialize(actual)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<B>%s</B>' % str(expected).lower()

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSBool)
    assert isinstance(actual, bool)
    assert not isinstance(actual, PSObject)  # We cannot subclass bool so this won't be a PSObject
    assert actual == expected


def test_ps_bool_from_bool():
    element = serialize(True)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<B>true</B>'


def test_ps_bool_deserialize_extended():
    # This just makes sure we don't choke on an extended primitive bool and we still get the raw value back.
    xml_val = '<Obj RefId="0"><B>true</B><MS><I32 N="Test Property">1</I32></MS></Obj>'
    element = ElementTree.fromstring(xml_val)

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSBool)
    assert isinstance(actual, bool)
    assert not isinstance(actual, PSObject)
    assert actual is True


@pytest.mark.parametrize('input_val, expected, expected_str, expected_repr', [
    (datetime.datetime(1970, 1, 1, 0, 0, 0),
     '<DT>1970-01-01T00:00:00Z</DT>', '1970-01-01 00:00:00+00:00',
     'PSDateTime(1970, 1, 1, 0, 0, tzinfo=datetime.timezone.utc, nanosecond=0)'),
    (datetime.datetime(1970, 1, 1, 0, 0, 0, microsecond=999999),
     '<DT>1970-01-01T00:00:00.999999Z</DT>', '1970-01-01 00:00:00.999999+00:00',
     'PSDateTime(1970, 1, 1, 0, 0, 0, 999999, tzinfo=datetime.timezone.utc, nanosecond=0)'),
    (datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone(offset=datetime.timedelta(hours=10))),
     '<DT>1970-01-01T00:00:00+10:00</DT>', '1970-01-01 00:00:00+10:00',
     'PSDateTime(1970, 1, 1, 0, 0, tzinfo=datetime.timezone(datetime.timedelta(seconds=36000)), nanosecond=0)'),
    (datetime.datetime(1970, 1, 1, 0, 0, 0, microsecond=999999,
                       tzinfo=datetime.timezone(offset=datetime.timedelta(hours=10))),
     '<DT>1970-01-01T00:00:00.999999+10:00</DT>', '1970-01-01 00:00:00.999999+10:00',
     'PSDateTime(1970, 1, 1, 0, 0, 0, 999999, tzinfo=datetime.timezone(datetime.timedelta(seconds=36000)), '
     'nanosecond=0)'),
    (datetime.datetime(1600, 12, 12, 23, 59, 59),
     '<DT>1600-12-12T23:59:59Z</DT>', '1600-12-12 23:59:59+00:00',
     'PSDateTime(1600, 12, 12, 23, 59, 59, tzinfo=datetime.timezone.utc, nanosecond=0)'),
])
def test_ps_datetime(input_val, expected, expected_str, expected_repr):
    ps_datetime = primitive_types.PSDateTime(input_val)
    assert isinstance(ps_datetime, primitive_types.PSDateTime)
    assert isinstance(ps_datetime, datetime.datetime)

    element = serialize(ps_datetime)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == expected

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSDateTime)
    assert isinstance(actual, datetime.datetime)
    assert actual.year == input_val.year
    assert actual.month == input_val.month
    assert actual.day == input_val.day
    assert actual.hour == input_val.hour
    assert actual.minute == input_val.minute
    assert actual.second == input_val.second
    assert actual.microsecond == input_val.microsecond
    assert str(actual) == expected_str
    assert repr(actual) == expected_repr
    assert actual.PSTypeNames == ['System.DateTime', 'System.ValueType', 'System.Object']


def test_ps_datetime_from_datetime():
    element = serialize(datetime.datetime(1970, 1, 1, 0, 0, 0, microsecond=999999))
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()

    assert actual == '<DT>1970-01-01T00:00:00.999999Z</DT>'


@pytest.mark.parametrize('nanosecond, fraction', [(7, 0), (70, 0), (700, 7)])
def test_ps_datetime_nanosecond(nanosecond, fraction):
    ps_datetime = primitive_types.PSDateTime(1970, 6, 11, 4, 8, 23, microsecond=123456, nanosecond=nanosecond)
    assert isinstance(ps_datetime, primitive_types.PSDateTime)
    assert isinstance(ps_datetime, datetime.datetime)

    element = serialize(ps_datetime)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<DT>1970-06-11T04:08:23.123456%sZ</DT>' % fraction

    assert str(ps_datetime) == f'1970-06-11 04:08:23.123456{nanosecond:03d}'


def test_ps_datetime_nanosecond_timezone():
    tz = datetime.timezone(offset=datetime.timedelta(hours=-10, minutes=-35))
    ps_datetime = primitive_types.PSDateTime(1970, 6, 11, 4, 8, 23, microsecond=123456, nanosecond=454, tzinfo=tz)
    assert isinstance(ps_datetime, primitive_types.PSDateTime)
    assert isinstance(ps_datetime, datetime.datetime)

    element = serialize(ps_datetime)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<DT>1970-06-11T04:08:23.1234564-10:35</DT>'

    assert str(ps_datetime) == '1970-06-11 04:08:23.123456454-10:35'


def test_ps_datetime_with_properties():
    ps_datetime = primitive_types.PSDateTime(2000, 2, 29, 15, 43, 10, microsecond=10)
    ps_datetime.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_datetime['Test Property'] = 1

    element = serialize(ps_datetime)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0"><DT>2000-02-29T15:43:10.000010Z</DT>' \
                     '<MS><I32 N="Test Property">1</I32></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSDateTime)
    assert isinstance(actual, datetime.datetime)
    assert actual.year == ps_datetime.year
    assert actual.month == ps_datetime.month
    assert actual.day == ps_datetime.day
    assert actual.hour == ps_datetime.hour
    assert actual.minute == ps_datetime.minute
    assert actual.second == ps_datetime.second
    assert actual.microsecond == ps_datetime.microsecond
    assert str(actual) == '2000-02-29 15:43:10.000010+00:00'
    assert actual['Test Property'] == 1
    assert isinstance(actual['Test Property'], primitive_types.PSInt)
    assert actual.PSTypeNames == ['System.DateTime', 'System.ValueType', 'System.Object']


def test_ps_datetime_add_duration():
    datetime_obj = primitive_types.PSDateTime(2000, 2, 29, 15, 43, 10, microsecond=10, nanosecond=733)
    duration = primitive_types.PSDuration(days=400, hours=10, minutes=20, seconds=55, microseconds=100,
                                           nanoseconds=400)

    actual = datetime_obj + duration

    assert isinstance(actual, primitive_types.PSDateTime)
    assert isinstance(actual, datetime.datetime)
    assert actual.year == 2001
    assert actual.month == 4
    assert actual.day == 5
    assert actual.hour == 2
    assert actual.minute == 4
    assert actual.second == 5
    assert actual.microsecond == 111
    assert actual.nanosecond == 133

    element = serialize(actual)
    actual_str = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual_str == '<DT>2001-04-05T02:04:05.0001111Z</DT>'


def test_ps_datetime_sub_duration():
    datetime_obj = primitive_types.PSDateTime(2000, 2, 29, 15, 43, 10, microsecond=10, nanosecond=733)
    duration = primitive_types.PSDuration(days=400, hours=10, minutes=20, seconds=55, microseconds=100,
                                           nanoseconds=400)

    actual = datetime_obj - duration

    assert isinstance(actual, primitive_types.PSDateTime)
    assert isinstance(actual, datetime.datetime)
    assert actual.year == 1999
    assert actual.month == 1
    assert actual.day == 25
    assert actual.hour == 5
    assert actual.minute == 22
    assert actual.second == 14
    assert actual.microsecond == 999910
    assert actual.nanosecond == 333

    element = serialize(actual)
    actual_str = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual_str == '<DT>1999-01-25T05:22:14.9999103Z</DT>'


def test_ps_datetime_sub_datetime():
    datetime_obj = primitive_types.PSDateTime(2000, 2, 29, 15, 43, 10, microsecond=10, nanosecond=731)
    sub_datetime = primitive_types.PSDateTime(1970, 1, 1, nanosecond=732)

    actual = datetime_obj - sub_datetime

    assert isinstance(actual, primitive_types.PSDuration)
    assert isinstance(actual, datetime.timedelta)
    assert actual.days == 11016
    assert actual.seconds == 56590
    assert actual.microseconds == 9
    assert actual.nanoseconds == 999


@pytest.mark.parametrize('input_val, expected, expected_str, expected_repr', [
    (datetime.timedelta(0), '<TS>PT0S</TS>', '0:00:00', 'PSDuration(0)'),
    (datetime.timedelta(hours=24), '<TS>P1D</TS>', '1 day, 0:00:00', 'PSDuration(days=1)'),
    (datetime.timedelta(hours=1, minutes=5), '<TS>PT1H5M</TS>', '1:05:00', 'PSDuration(seconds=3900)'),
    (datetime.timedelta(seconds=6005), '<TS>PT1H40M5S</TS>', '1:40:05', 'PSDuration(seconds=6005)'),
    (datetime.timedelta(seconds=-6005), '<TS>-PT1H40M5S</TS>', '-1 day, 22:19:55',
     'PSDuration(days=-1, seconds=80395)'),
    (datetime.timedelta(microseconds=99), '<TS>PT0.000099S</TS>', '0:00:00.000099',
     'PSDuration(microseconds=99)'),
    (datetime.timedelta(microseconds=922337203685477580), '<TS>P10675199DT2H48M5.47758S</TS>',
     '10675199 days, 2:48:05.477580', 'PSDuration(days=10675199, seconds=10085, microseconds=477580)'),
])
def test_ps_duration(input_val, expected, expected_str, expected_repr):
    ps_duration = primitive_types.PSDuration(input_val)
    assert isinstance(ps_duration, primitive_types.PSDuration)
    assert isinstance(ps_duration, datetime.timedelta)

    element = serialize(ps_duration)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == expected

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSDuration)
    assert isinstance(actual, datetime.timedelta)
    assert actual.days == input_val.days
    assert actual.microseconds == input_val.microseconds
    assert actual.seconds == input_val.seconds
    assert str(actual) == expected_str
    assert repr(actual) == expected_repr
    assert actual.PSTypeNames == ['System.TimeSpan', 'System.ValueType', 'System.Object']


def test_ps_duration_from_timedelta():
    element = serialize(datetime.timedelta(microseconds=922337203685477580))

    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<TS>P10675199DT2H48M5.47758S</TS>'


@pytest.mark.parametrize('nanosecond', [8, 80, 800])
def test_ps_duration_with_nanoseconds(nanosecond):
    base_nanoseconds = 922337203685477580000
    fraction = ''
    if nanosecond > 100:
        fraction = f'0{nanosecond // 100}'

    ps_duration = primitive_types.PSDuration(nanoseconds=(base_nanoseconds + nanosecond))
    assert isinstance(ps_duration, primitive_types.PSDuration)
    assert isinstance(ps_duration, datetime.timedelta)

    element = serialize(ps_duration)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<TS>P10675199DT2H48M5.47758{fraction}S</TS>'

    assert repr(ps_duration) == f'PSDuration(days=10675199, seconds=10085, microseconds=477580, ' \
                                f'nanoseconds={nanosecond})'
    assert str(ps_duration) == f'10675199 days, 2:48:05.477580{nanosecond:03d}'


def test_ps_duration_with_properties():
    ps_duration = primitive_types.PSDuration(days=10, hours=25, minutes=70, seconds=129, microseconds=1000,
                                              nanoseconds=1100)
    ps_duration.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_duration['Test Property'] = 1

    element = serialize(ps_duration)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0"><TS>P11DT2H12M9.0010011S</TS><MS><I32 N="Test Property">1</I32></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSDuration)
    assert isinstance(actual, datetime.timedelta)
    assert actual.days == ps_duration.days
    assert actual.microseconds == ps_duration.microseconds
    assert actual.seconds == ps_duration.seconds
    assert actual.microseconds == ps_duration.microseconds
    assert actual.nanoseconds == ps_duration.nanoseconds
    assert str(actual) == '11 days, 2:12:09.001001100'
    assert actual['Test Property'] == 1
    assert isinstance(actual['Test Property'], primitive_types.PSInt)
    assert actual.PSTypeNames == ['System.TimeSpan', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('other, expected', [
    (primitive_types.PSDuration(days=30, hours=23, minutes=50, seconds=45, microseconds=19, nanoseconds=521),
     primitive_types.PSDuration(days=41, hours=10, minutes=4, seconds=44, microseconds=2013, nanoseconds=175)),
    (primitive_types.PSDuration(days=-30, hours=23, minutes=-50, seconds=45, microseconds=-19, nanoseconds=521),
     primitive_types.PSDuration(days=-19, hours=8, minutes=24, seconds=44, microseconds=1975, nanoseconds=175)),
    (datetime.timedelta(days=30, hours=23, minutes=50, seconds=45, microseconds=19),
     primitive_types.PSDuration(days=41, hours=10, minutes=4, seconds=44, microseconds=2012, nanoseconds=654)),
    (datetime.timedelta(days=-30, hours=23, minutes=-50, seconds=45, microseconds=-19),
     primitive_types.PSDuration(days=-19, hours=8, minutes=24, seconds=44, microseconds=1974, nanoseconds=654)),
])
def test_ps_duration_add(other, expected):
    duration = primitive_types.PSDuration(days=10, hours=10, minutes=13, seconds=59, microseconds=1993,
                                           nanoseconds=654)

    actual = duration + other
    assert actual == expected


def test_ps_duration_add_invalid_type():
    duration = primitive_types.PSDuration(1)

    with pytest.raises(TypeError):
        duration += 1


@pytest.mark.parametrize('other, expected', [
    (primitive_types.PSDuration(days=30, hours=23, minutes=50, seconds=45, microseconds=19, nanoseconds=521),
     primitive_types.PSDuration(days=-21, hours=10, minutes=23, seconds=14, microseconds=1974, nanoseconds=133)),
    (primitive_types.PSDuration(days=-30, hours=23, minutes=-50, seconds=45, microseconds=-19, nanoseconds=521),
     primitive_types.PSDuration(days=39, hours=12, minutes=3, seconds=14, microseconds=2012, nanoseconds=133)),
    (datetime.timedelta(days=30, hours=23, minutes=50, seconds=45, microseconds=19),
     primitive_types.PSDuration(days=-21, hours=10, minutes=23, seconds=14, microseconds=1974, nanoseconds=654)),
    (datetime.timedelta(days=-30, hours=23, minutes=-50, seconds=45, microseconds=-19),
     primitive_types.PSDuration(days=39, hours=12, minutes=3, seconds=14, microseconds=2012, nanoseconds=654)),
])
def test_ps_duration_sub(other, expected):
    duration = primitive_types.PSDuration(days=10, hours=10, minutes=13, seconds=59, microseconds=1993,
                                           nanoseconds=654)

    actual = duration - other
    assert actual == expected


def test_ps_duration_sub_invalid_type():
    duration = primitive_types.PSDuration(1)

    with pytest.raises(TypeError):
        duration -= 1


@pytest.mark.parametrize('other, expected', [
    (datetime.timedelta(days=30, hours=23, minutes=50, seconds=45, microseconds=19),
     primitive_types.PSDuration(days=20, hours=13, minutes=36, seconds=45, microseconds=998025, nanoseconds=346)),
    (datetime.timedelta(days=-30, hours=23, minutes=-50, seconds=45, microseconds=-19),
     primitive_types.PSDuration(days=-40, hours=11, minutes=56, seconds=45, microseconds=997987, nanoseconds=346)),
])
def test_ps_duration_rsub(other, expected):
    duration = primitive_types.PSDuration(days=10, hours=10, minutes=13, seconds=59, microseconds=1993,
                                           nanoseconds=654)

    actual = other - duration
    assert actual == expected


def test_ps_duration_negative():
    original = primitive_types.PSDuration(days=30, hours=10, nanoseconds=500)

    pos = +original
    assert isinstance(pos, primitive_types.PSDuration)
    assert original == +original

    sub = -original
    assert isinstance(sub, primitive_types.PSDuration)
    assert sub.days == -31
    assert sub.seconds == 50399
    assert sub.microseconds == 999999
    assert sub.nanoseconds == 500

    pos = -sub
    assert pos == original


def test_duration_equality():
    duration_lowest = primitive_types.PSDuration(nanoseconds=1)
    duration_lower = primitive_types.PSDuration(nanoseconds=2)
    duration_lower2 = primitive_types.PSDuration(nanoseconds=2)
    duration_higher = primitive_types.PSDuration(nanoseconds=3)
    duration_higher2 = primitive_types.PSDuration(nanoseconds=3)
    duration_highest = primitive_types.PSDuration(nanoseconds=4)

    assert duration_lower == duration_lower2
    assert duration_lowest != duration_lower
    assert duration_lowest < duration_lower
    assert duration_lowest <= duration_lower
    assert not duration_lower < duration_lower2
    assert duration_lower <= duration_lower2
    assert duration_lower < duration_higher
    assert duration_highest > duration_higher
    assert duration_highest >= duration_higher
    assert duration_higher >= duration_higher
    assert not duration_higher > duration_higher2
    assert duration_higher >= duration_higher2


def test_duration_timedelta_equality():
    duration_low = primitive_types.PSDuration(days=1)
    duration_low_ns = primitive_types.PSDuration(days=1, nanoseconds=1)
    timedelta_low = datetime.timedelta(days=1)

    duration_high = primitive_types.PSDuration(days=2, nanoseconds=1)
    timedelta_high = datetime.timedelta(days=2)

    assert duration_low == timedelta_low
    assert timedelta_low == duration_low
    assert not duration_low_ns == timedelta_low
    assert not timedelta_low == duration_low_ns

    assert duration_low < timedelta_high
    assert duration_low_ns < timedelta_high
    assert duration_low <= timedelta_high
    assert duration_low_ns <= timedelta_high

    assert timedelta_high > duration_low_ns
    assert timedelta_high >= duration_low_ns

    assert duration_high > timedelta_low
    assert duration_high >= timedelta_low


@pytest.mark.parametrize('ps_type, tag, type_name', [
    (primitive_types.PSByte, 'By', 'Byte'),
    (primitive_types.PSSByte, 'SB', 'SByte'),
    (primitive_types.PSUInt16, 'U16', 'UInt16'),
    (primitive_types.PSInt16, 'I16', 'Int16'),
    (primitive_types.PSUInt, 'U32', 'UInt32'),
    (primitive_types.PSInt, 'I32', 'Int32'),
    (primitive_types.PSUInt64, 'U64', 'UInt64'),
    (primitive_types.PSInt64, 'I64', 'Int64'),
])
def test_numeric(ps_type, tag, type_name):
    for value in [ps_type.MinValue, 0, 1, ps_type.MaxValue]:
        ps_value = ps_type(value)
        assert isinstance(ps_value, ps_type)
        assert isinstance(ps_value, int)

        element = serialize(ps_value)
        actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
        assert actual == f'<{tag}>{value}</{tag}>'

        actual = deserialize(element)
        assert isinstance(actual, ps_type)
        assert isinstance(actual, int)
        assert actual == value
        assert actual.PSTypeNames == [f'System.{type_name}', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_value, tag', [
    (10, 'I32'),
    (256, 'I32'),
    (2147483647, 'I32'),
    (2147483648, 'I64'),
])
def test_ps_int_from_int(input_value, tag):
    element = serialize(input_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<{tag}>{input_value}</{tag}>'


@pytest.mark.parametrize('input_args', [
    ('11111111', 2),
    ('377', 8),
    ('FF', 16),
])
def test_ps_int_with_base(input_args):
    ps_value = primitive_types.PSInt(*input_args)
    assert isinstance(ps_value, primitive_types.PSInt)
    assert isinstance(ps_value, int)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<I32>255</I32>'


@pytest.mark.parametrize('ps_type, tag, type_name', [
    (primitive_types.PSByte, 'By', 'Byte'),
    (primitive_types.PSSByte, 'SB', 'SByte'),
    (primitive_types.PSUInt16, 'U16', 'UInt16'),
    (primitive_types.PSInt16, 'I16', 'Int16'),
    (primitive_types.PSUInt, 'U32', 'UInt32'),
    (primitive_types.PSInt, 'I32', 'Int32'),
    (primitive_types.PSUInt64, 'U64', 'UInt64'),
    (primitive_types.PSInt64, 'I64', 'Int64'),
])
def test_numeric_with_properties(ps_type, tag, type_name):
    ps_value = ps_type(None)
    assert isinstance(ps_value, ps_type)
    assert ps_value == 0

    ps_value = ps_type(10)
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = 1

    element = serialize(ps_value)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == f'<Obj RefId="0"><{tag}>10</{tag}><MS><I32 N="Test Property">1</I32></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, ps_type)
    assert isinstance(actual, int)
    assert actual == 10
    assert actual['Test Property'] == 1
    assert isinstance(actual['Test Property'], primitive_types.PSInt)
    assert actual.PSTypeNames == [f'System.{type_name}', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('ps_type, value', [
    (primitive_types.PSByte, -1),
    (primitive_types.PSByte, 256),
    (primitive_types.PSSByte, -129),
    (primitive_types.PSSByte, 128),
    (primitive_types.PSUInt16, -1),
    (primitive_types.PSUInt16, 65536),
    (primitive_types.PSInt16, -32769),
    (primitive_types.PSInt16, 32768),
    (primitive_types.PSUInt, -1),
    (primitive_types.PSUInt, 4294967296),
    (primitive_types.PSInt, -2147483649),
    (primitive_types.PSInt, 2147483648),
    (primitive_types.PSUInt64, -1),
    (primitive_types.PSUInt64, 18446744073709551616),
    (primitive_types.PSInt64, -9223372036854775809),
    (primitive_types.PSInt64, 9223372036854775808),

])
def test_numeric_invalid_value(ps_type, value):
    expected = re.escape(f"Cannot create {ps_type.__qualname__} with value '{value}': Value must be between "
                         f"{ps_type.MinValue} and {ps_type.MaxValue}.")
    with pytest.raises(ValueError, match=expected):
        ps_type(value)


@pytest.mark.parametrize('ps_type', [
    primitive_types.PSByte,
    primitive_types.PSSByte,
    primitive_types.PSUInt16,
    primitive_types.PSInt16,
    primitive_types.PSUInt,
    primitive_types.PSInt,
    primitive_types.PSUInt64,
    primitive_types.PSInt64,
])
def test_numeric_operators(ps_type):
    actual = ps_type(2) + 4
    assert isinstance(actual, ps_type)
    assert actual == 6

    actual = ps_type(3) & 2
    assert isinstance(actual, ps_type)
    assert actual == 2

    quotient, remainder = divmod(ps_type(11), 10)
    assert isinstance(quotient, ps_type)
    assert quotient == 1
    assert isinstance(remainder, int)
    assert remainder == 1

    actual = ps_type(13) // 2
    assert isinstance(actual, ps_type)
    assert actual == 6

    actual = ps_type(1) << 2
    assert isinstance(actual, ps_type)
    assert actual == 4

    actual = ps_type(3) % 2
    assert isinstance(actual, ps_type)
    assert actual == 1

    actual = ps_type(3) * 2
    assert isinstance(actual, ps_type)
    assert actual == 6

    actual = ps_type(1) | 2
    assert isinstance(actual, ps_type)
    assert actual == 3

    actual = ps_type(2) ** 2
    assert isinstance(actual, ps_type)
    assert actual == 4

    actual = ps_type(4) >> 2
    assert isinstance(actual, ps_type)
    assert actual == 1

    actual = ps_type(4) - 2
    assert isinstance(actual, ps_type)
    assert actual == 2

    actual = ps_type(19) ^ 21
    assert isinstance(actual, ps_type)
    assert actual == 6

    actual = ps_type(1)
    actual += 1
    assert isinstance(actual, ps_type)
    assert actual == 2

    actual -= 1
    assert isinstance(actual, ps_type)
    assert actual == 1

    actual *= 2
    assert isinstance(actual, ps_type)
    assert actual == 2


@pytest.mark.parametrize('ps_type', [
    primitive_types.PSSByte,
    primitive_types.PSInt16,
    primitive_types.PSInt,
    primitive_types.PSInt64,
])
def test_numeric_negative_operators(ps_type):
    actual = abs(ps_type(-1))
    assert isinstance(actual, ps_type)
    assert actual == 1

    actual = ~ps_type(-1)
    assert isinstance(actual, ps_type)
    assert actual == 0

    actual = ~ps_type(1)
    assert isinstance(actual, ps_type)
    assert actual == -2

    actual = -ps_type(-1)
    assert isinstance(actual, ps_type)
    assert actual == 1

    actual = -ps_type(1)
    assert isinstance(actual, ps_type)
    assert actual == -1

    actual = +ps_type(-1)
    assert isinstance(actual, ps_type)
    assert actual == -1

    actual = +ps_type(1)
    assert isinstance(actual, ps_type)
    assert actual == 1


@pytest.mark.parametrize('ps_type, input_val, expected, type_name', [
    (primitive_types.PSSingle, 1, '<Sg>1.0</Sg>', 'Single'),
    (primitive_types.PSSingle, 1.0, '<Sg>1.0</Sg>', 'Single'),
    (primitive_types.PSSingle, 1.1, '<Sg>1.1</Sg>', 'Single'),
    (primitive_types.PSSingle, 3.402823e+38, '<Sg>3.402823E+38</Sg>', 'Single'),
    (primitive_types.PSSingle, -3.402823e+38, '<Sg>-3.402823E+38</Sg>', 'Single'),
    (primitive_types.PSDouble, 1, '<Db>1.0</Db>', 'Double'),
    (primitive_types.PSDouble, 1.0, '<Db>1.0</Db>', 'Double'),
    (primitive_types.PSDouble, 1.1, '<Db>1.1</Db>', 'Double'),
    (primitive_types.PSDouble, 1.7976931348623157e+308, '<Db>1.7976931348623157E+308</Db>', 'Double'),
    (primitive_types.PSDouble, 1.79769313486232e+308, '<Db>INF</Db>', 'Double'),
    (primitive_types.PSDouble, -1.79769313486232e+307, '<Db>-1.79769313486232E+307</Db>', 'Double'),
    (primitive_types.PSDouble, -1.79769313486232e+308, '<Db>-INF</Db>', 'Double'),
])
def test_ps_single_and_double(ps_type, input_val, expected, type_name):
    ps_value = ps_type(input_val)
    assert isinstance(ps_value, ps_type)
    assert isinstance(ps_value, float)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == expected

    actual = deserialize(element)
    assert isinstance(actual, ps_type)
    assert isinstance(actual, float)
    assert actual == float(input_val)
    assert actual.PSTypeNames == [f'System.{type_name}', 'System.ValueType', 'System.Object']


def test_ps_single_from_float():
    element = serialize(1.1)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Sg>1.1</Sg>'


@pytest.mark.parametrize('ps_type, tag, type_name', [
    (primitive_types.PSSingle, 'Sg', 'Single'),
    (primitive_types.PSDouble, 'Db', 'Double'),
])
def test_ps_single_and_double_with_properties(ps_type, tag, type_name):
    ps_value = ps_type(1.1)
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = 1.1

    element = serialize(ps_value)

    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == f'<Obj RefId="0"><{tag}>1.1</{tag}><MS><Sg N="Test Property">1.1</Sg></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, ps_type)
    assert isinstance(actual, float)
    assert actual == 1.1
    assert actual['Test Property'] == 1.1
    assert isinstance(actual['Test Property'], primitive_types.PSSingle)
    assert actual.PSTypeNames == [f'System.{type_name}', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_value, expected', [
    (0, '<D>0</D>'),
    (-1, '<D>-1</D>'),
    (1, '<D>1</D>'),
    (1.0, '<D>1</D>'),
    ('1.1', '<D>1.1</D>'),
    ('1.10', '<D>1.10</D>'),
])
def test_ps_decimal(input_value, expected):
    ps_value = primitive_types.PSDecimal(input_value)
    assert isinstance(ps_value, primitive_types.PSDecimal)
    assert isinstance(ps_value, decimal.Decimal)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == expected

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSDecimal)
    assert isinstance(actual, decimal.Decimal)
    assert actual == decimal.Decimal(input_value)
    assert actual.PSTypeNames == ['System.Decimal', 'System.ValueType', 'System.Object']


def test_ps_decimal_with_properties():
    ps_value = primitive_types.PSDecimal('1.302000')
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = decimal.Decimal(0)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><D>1.302000</D><MS><D N="Test Property">0</D></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSDecimal)
    assert isinstance(actual, decimal.Decimal)
    assert actual == decimal.Decimal('1.302000')
    assert actual['Test Property'] == decimal.Decimal(0)
    assert isinstance(actual['Test Property'], primitive_types.PSDecimal)
    assert actual.PSTypeNames == ['System.Decimal', 'System.ValueType', 'System.Object']


@pytest.mark.parametrize('input_value, expected', [
    (b'\x00\x01\x02\x03', '<BA>AAECAw==</BA>'),
    (b'', '<BA />'),
])
def test_ps_byte_array(input_value, expected):
    ps_value = primitive_types.PSByteArray(input_value)
    assert isinstance(ps_value, primitive_types.PSByteArray)
    assert isinstance(ps_value, bytes)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == expected

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSByteArray)
    assert isinstance(actual, bytes)
    assert actual == input_value
    assert actual.PSTypeNames == ['System.Byte[]', 'System.Array', 'System.Object']


def test_ps_byte_array_with_properties():
    value = 'café'.encode('utf-8')

    ps_value = primitive_types.PSByteArray(value)
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = value

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><BA>Y2Fmw6k=</BA><MS><BA N="Test Property">Y2Fmw6k=</BA></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSByteArray)
    assert isinstance(actual, bytes)
    assert actual == value
    assert actual['Test Property'] == value
    assert isinstance(actual['Test Property'], primitive_types.PSByteArray)
    assert actual.PSTypeNames == ['System.Byte[]', 'System.Array', 'System.Object']

    # Check that we can still slice bytes and the type is preserved
    sliced_actual = actual[:2]
    assert isinstance(sliced_actual, primitive_types.PSByteArray)
    assert isinstance(sliced_actual, bytes)
    assert sliced_actual == value[:2]
    assert sliced_actual.PSObject.extended_properties == []

    # Check that a new PSString instance does not inherit the same PSObject values
    new_str = primitive_types.PSByteArray(b'other')
    assert new_str.PSObject.adapted_properties == []
    assert new_str.PSObject.extended_properties == []


@pytest.mark.parametrize('input_value, expected', [
    ('00000000-0000-0000-0000-000000000000', '<G>00000000-0000-0000-0000-000000000000</G>'),
    ('f5853fa8-a3d8-438c-bf94-723d3fef8934', '<G>f5853fa8-a3d8-438c-bf94-723d3fef8934</G>'),
])
def test_ps_guid(input_value, expected):
    ps_value = primitive_types.PSGuid(input_value)
    assert isinstance(ps_value, primitive_types.PSGuid)
    assert isinstance(ps_value, uuid.UUID)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == expected

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSGuid)
    assert isinstance(actual, uuid.UUID)
    assert actual == primitive_types.PSGuid(input_value)
    assert actual.PSTypeNames == ['System.Guid', 'System.ValueType', 'System.Object']


def test_ps_guid_with_properties():
    ps_value = primitive_types.PSGuid(int=1)
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = uuid.UUID(int=2)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><G>00000000-0000-0000-0000-000000000001</G>' \
                     f'<MS><G N="Test Property">00000000-0000-0000-0000-000000000002</G></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSGuid)
    assert isinstance(actual, uuid.UUID)
    assert actual == uuid.UUID(int=1)
    assert actual['Test Property'] == uuid.UUID(int=2)
    assert isinstance(actual['Test Property'], primitive_types.PSGuid)
    assert actual.PSTypeNames == ['System.Guid', 'System.ValueType', 'System.Object']

    # uuid.UUID uses __slots__ so setting PSObject on the actual instance is a bit tricker. This makes sure we've done
    # it correctly.
    ps_value = primitive_types.PSGuid(int=0)
    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<G>00000000-0000-0000-0000-000000000000</G>'


@pytest.mark.parametrize('input_val', [primitive_types.PSNull, None])
def test_ps_null(input_val):
    element = serialize(input_val)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == '<Nil />'

    actual = deserialize(element)
    assert actual is None
    assert actual is primitive_types.PSNull


@pytest.mark.parametrize('input_value', [
    '0',
    '01.1',
    '1.2.3.4.5',
    '1.2.3a',
    '1.2.3.a',
    '1.01',
    '1.0.',
    '1.0.0.',
    '1.0.0.0.',
])
def test_ps_version_invalid_strings(input_value):
    expected = re.escape(f"Invalid PSVersion string '{input_value}': must be 2 to 4 groups of numbers that are "
                         f"separated by '.'")

    with pytest.raises(ValueError, match=expected):
        primitive_types.PSVersion(input_value)


def test_ps_version_no_major_and_minor():
    expected = 'The major and minor versions must be specified'

    with pytest.raises(ValueError, match=expected):
        primitive_types.PSVersion(major=1)

    with pytest.raises(ValueError, match=expected):
        primitive_types.PSVersion(minor=1)


def test_ps_version_build_not_set():
    with pytest.raises(ValueError, match='The build version must be set when revision is set'):
        primitive_types.PSVersion(major=1, minor=0, revision=0)


@pytest.mark.parametrize('input_value, major, minor, build, revision', [
    ('1.0', 1, 0, None, None),
    ('1.1', 1, 1, None, None),
    ('1.2.3', 1, 2, 3, None),
    ('1.2.3.4', 1, 2, 3, 4),
    ('0.0', 0, 0, None, None),
    ('0.1', 0, 1, None, None),
    ('0.0.1', 0, 0, 1, None),
    ('1.0.1', 1, 0, 1, None),
    ('10.10234.2030.102', 10, 10234, 2030, 102),
])
def test_ps_version(input_value, major, minor, build, revision):
    ps_value = primitive_types.PSVersion(input_value)
    assert isinstance(ps_value, primitive_types.PSVersion)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Version>{input_value}</Version>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSVersion)
    assert actual == ps_value
    assert actual.major == major
    assert actual.minor == minor
    assert actual.build == build
    assert actual.revision == revision
    assert actual.PSTypeNames == ['System.Version', 'System.Object']


def test_ps_version_with_properties():
    ps_value = primitive_types.PSVersion('1.1')
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = primitive_types.PSVersion('0.0')

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><Version>1.1</Version>' \
                     f'<MS><Version N="Test Property">0.0</Version></MS></Obj>'

    actual = deserialize(element)
    assert isinstance(actual, primitive_types.PSVersion)
    assert actual == ps_value
    assert actual.major == 1
    assert actual.minor == 1
    assert actual.build is None
    assert actual.revision is None
    assert actual['Test Property'] == '0.0'
    assert isinstance(actual['Test Property'], primitive_types.PSVersion)
    assert actual.PSTypeNames == ['System.Version', 'System.Object']


@pytest.mark.parametrize('input_value, expected_repr', [
    ('1.0', 'major=1, minor=0'),
    ('0.0.1', 'major=0, minor=0, build=1'),
    ('1.0.1', 'major=1, minor=0, build=1'),
    ('1.0.1.0', 'major=1, minor=0, build=1, revision=0'),
    ('1.0.1.99', 'major=1, minor=0, build=1, revision=99'),
])
def test_ps_version_str(input_value, expected_repr):
    actual = primitive_types.PSVersion(input_value)
    assert str(actual) == input_value
    assert repr(actual) == f'psrp.dotnet.primitive_types.PSVersion({expected_repr})'


@pytest.mark.parametrize('version, other, expected', [
    (primitive_types.PSVersion('1.0'), primitive_types.PSVersion('1.0'), True),
    (primitive_types.PSVersion('1.0'), '1.0', True),
    (primitive_types.PSVersion('1.1'), primitive_types.PSVersion('1.0'), False),
    (primitive_types.PSVersion('1.1'), '1.0', False),
    (primitive_types.PSVersion('1.0.0'), primitive_types.PSVersion('1.0'), False),
])
def test_ps_version_equals(version, other, expected):
    assert (version == other) == expected


@pytest.mark.parametrize('version, other, expected', [
    ('2.2', '2.3', False),
    ('2.3', '2.3', False),
    ('2.4', '2.3', True),
    ('3.0', '2.3', True),
    ('1.0', '2.3', False),
    ('2.3.0', '2.3', True),
    ('2.3.1', '2.3', True),
    ('2.3', '2.3.0', False),
    ('2.3', '2.3.1', False),
    ('99.102.0.19', '99.102.1.0', False),
    ('99.102.0.19', '99.102.0.0', True),
    ('99.102.0.19', '99.102.0.19', False),
])
def test_ps_version_greater_than(version, other, expected):
    assert (primitive_types.PSVersion(version) > other) == expected


@pytest.mark.parametrize('version, other, expected', [
    ('2.2', '2.3', False),
    ('2.3', '2.3', True),
    ('2.4', '2.3', True),
    ('3.0', '2.3', True),
    ('1.0', '2.3', False),
    ('2.3.0', '2.3', True),
    ('2.3.1', '2.3', True),
    ('2.3', '2.3.0', False),
    ('2.3', '2.3.1', False),
    ('99.102.0.19', '99.102.1.0', False),
    ('99.102.0.19', '99.102.0.0', True),
    ('99.102.0.19', '99.102.0.19', True),
])
def test_ps_version_greater_or_equal(version, other, expected):
    assert (primitive_types.PSVersion(version) >= other) == expected


@pytest.mark.parametrize('version, other, expected', [
    ('2.2', '2.3', True),
    ('2.3', '2.3', False),
    ('2.4', '2.3', False),
    ('3.0', '2.3', False),
    ('1.0', '2.3', True),
    ('2.3.0', '2.3', False),
    ('2.3.1', '2.3', False),
    ('2.3', '2.3.0', True),
    ('2.3', '2.3.1', True),
    ('99.102.0.19', '99.102.1.0', True),
    ('99.102.0.19', '99.102.0.0', False),
    ('99.102.0.19', '99.102.0.19', False),
])
def test_ps_version_less_than(version, other, expected):
    assert (primitive_types.PSVersion(version) < other) == expected


@pytest.mark.parametrize('version, other, expected', [
    ('2.2', '2.3', True),
    ('2.3', '2.3', True),
    ('2.4', '2.3', False),
    ('3.0', '2.3', False),
    ('1.0', '2.3', True),
    ('2.3.0', '2.3', False),
    ('2.3.1', '2.3', False),
    ('2.3', '2.3.0', True),
    ('2.3', '2.3.1', True),
    ('99.102.0.19', '99.102.1.0', True),
    ('99.102.0.19', '99.102.0.0', False),
    ('99.102.0.19', '99.102.0.19', True),
])
def test_ps_version_less_or_equal(version, other, expected):
    assert (primitive_types.PSVersion(version) <= other) == expected
    

def test_ps_version_compare_invalid():
    expected = re.escape("'>=' not supported between instances of 'PSVersion' and 'int")
    with pytest.raises(TypeError, match=expected):
        primitive_types.PSVersion('1.0') >= 1


def test_ps_secure_string():
    fake_cipher = FakeCryptoProvider()
    ps_value = primitive_types.PSSecureString(COMPLEX_STRING)

    element = serialize(ps_value, cipher=fake_cipher)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == \
           '<SS>dAByAGUAYgBsAGUAIABjAGwAZQBmAAoAIABfAHgAMAAwADAAMABfACAAXwBYADAAMAAwADAAXwAgADTYHt0gAGMAYQBmAOkA</SS>'

    actual = deserialize(element, cipher=fake_cipher)
    assert isinstance(actual, primitive_types.PSSecureString)
    assert isinstance(actual, str)
    assert actual == COMPLEX_STRING
    assert actual.PSTypeNames == ['System.Security.SecureString', 'System.Object']


def test_ps_secure_string_with_properties():
    fake_cipher = FakeCryptoProvider()
    ps_value = primitive_types.PSSecureString('abc')
    ps_value.PSObject.extended_properties.append(PSNoteProperty('Test Property'))
    ps_value['Test Property'] = primitive_types.PSSecureString('abc')

    element = serialize(ps_value, cipher=fake_cipher)
    actual = ElementTree.tostring(element, encoding='utf-8', method='xml').decode()
    assert actual == f'<Obj RefId="0"><SS>YQBiAGMA</SS><MS><SS N="Test Property">YQBiAGMA</SS></MS></Obj>'

    actual = deserialize(element, cipher=fake_cipher)
    assert isinstance(actual, primitive_types.PSSecureString)
    assert isinstance(actual, str)
    assert actual == 'abc'
    assert actual['Test Property'] == 'abc'
    assert isinstance(actual['Test Property'], primitive_types.PSSecureString)
    assert actual.PSTypeNames == ['System.Security.SecureString', 'System.Object']

    # Check that we can still slice a string and the type is preserved
    sliced_actual = actual[:2]
    assert isinstance(sliced_actual, primitive_types.PSSecureString)
    assert isinstance(sliced_actual, str)
    assert sliced_actual == 'ab'
    assert sliced_actual.PSObject.extended_properties == []
