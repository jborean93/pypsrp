# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime
import decimal
import pytest
import re
import queue
import uuid

import psrp.dotnet.serializer as serializer
import xml.etree.ElementTree as ElementTree

from psrp.dotnet.complex_types import (
    PSQueue,
)

from psrp.dotnet.primitive_types import (
    PSBool,
    PSByte,
    PSByteArray,
    PSChar,
    PSDateTime,
    PSDecimal,
    PSDouble,
    PSDuration,
    PSGuid,
    PSInt,
    PSInt16,
    PSInt64,
    PSSingle,
    PSSByte,
    PSScriptBlock,
    PSSecureString,
    PSString,
    PSUInt,
    PSUInt16,
    PSUInt64,
    PSUri,
    PSVersion,
    PSXml,
)

from psrp.exceptions import (
    MissingCipherError,
)


# A lot of the serializer tests are done in the tests for each object, these are just for extra edge cases we want to
# validate

COMPLEX_STRING = u'treble clef\n _x0000_ _X0000_ %s café' % b"\xF0\x9D\x84\x9E".decode('utf-8')
COMPLEX_ENCODED_STRING = u'treble clef_x000A_ _x005F_x0000_ _x005F_X0000_ _xD834__xDD1E_ café'


@pytest.mark.parametrize('input_value, expected', [
    (PSBool(True), '<B>true</B>'),
    (PSBool(False), '<B>false</B>'),
    (True, '<B>true</B>'),
    (False, '<B>false</B>'),
    (PSByte(1), '<By>1</By>'),
    (PSByteArray(b'\x00\x01\x02\x03'), '<BA>AAECAw==</BA>'),
    (b'\x00\x01\x02\x03', '<BA>AAECAw==</BA>'),
    (PSChar('a'), '<C>97</C>'),
    (PSDateTime(1970, 1, 1), '<DT>1970-01-01T00:00:00Z</DT>'),
    (datetime.datetime(1970, 1, 1), '<DT>1970-01-01T00:00:00Z</DT>'),
    (PSDecimal(1), '<D>1</D>'),
    (decimal.Decimal(1), '<D>1</D>'),
    (PSDouble(1.0), '<Db>1.0</Db>'),
    (PSDuration(1), '<TS>P1D</TS>'),
    (datetime.timedelta(1), '<TS>P1D</TS>'),
    (PSGuid(int=0), '<G>00000000-0000-0000-0000-000000000000</G>'),
    (uuid.UUID(int=0), '<G>00000000-0000-0000-0000-000000000000</G>'),
    (PSInt(1), '<I32>1</I32>'),
    (1, '<I32>1</I32>'),
    (PSInt16(1), '<I16>1</I16>'),
    (PSInt64(1), '<I64>1</I64>'),
    (PSSingle(1.0), '<Sg>1.0</Sg>'),
    (float(1.0), '<Sg>1.0</Sg>'),
    (PSSByte(1), '<SB>1</SB>'),
    (PSScriptBlock(COMPLEX_STRING), f'<SBK>{COMPLEX_ENCODED_STRING}</SBK>'),
    (PSString(COMPLEX_STRING), f'<S>{COMPLEX_ENCODED_STRING}</S>'),
    (COMPLEX_STRING, f'<S>{COMPLEX_ENCODED_STRING}</S>'),
    (PSUInt(1), '<U32>1</U32>'),
    (PSUInt16(1), '<U16>1</U16>'),
    (PSUInt64(1), '<U64>1</U64>'),
    (PSUri(COMPLEX_STRING), f'<URI>{COMPLEX_ENCODED_STRING}</URI>'),
    (PSVersion('1.2.3.4'), '<Version>1.2.3.4</Version>'),
    (PSXml(COMPLEX_STRING), f'<XD>{COMPLEX_ENCODED_STRING}</XD>'),
])
def test_serialize_primitive_object(input_value, expected):
    element = serializer.serialize(input_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == expected


@pytest.mark.parametrize('input_value, expected', [
    ('<B>true</B>', PSBool(True)),
    ('<B>false</B>', PSBool(False)),
    ('<By>1</By>', PSByte(1)),
    ('<BA>AAECAw==</BA>', PSByteArray(b'\x00\x01\x02\x03')),
    ('<C>97</C>', PSChar('a')),
    ('<DT>2008-04-11T10:42:32.2731993-07:00</DT>',
     PSDateTime(2008, 4, 11, 10, 42, 32, 273199, tzinfo=datetime.timezone(-datetime.timedelta(seconds=25200)),
                nanosecond=300)),
    ('<D>1</D>', PSDecimal(1)),
    ('<Db>1.0</Db>', PSDouble(1.0)),
    ('<TS>PT9.0269026S</TS> ', PSDuration(seconds=9, microseconds=26902, nanoseconds=600)),
    ('<G>00000000-0000-0000-0000-000000000000</G>', PSGuid(int=0)),
    ('<I32>1</I32>', PSInt(1)),
    ('<I16>1</I16>', PSInt16(1)),
    ('<I64>1</I64>', PSInt64(1)),
    ('<Sg>1.0</Sg>', PSSingle(1.0)),
    ('<SB>1</SB>', PSSByte(1)),
    (f'<SBK>{COMPLEX_ENCODED_STRING}</SBK>', PSScriptBlock(COMPLEX_STRING)),
    (f'<S>{COMPLEX_ENCODED_STRING}</S>', PSString(COMPLEX_STRING)),
    ('<U32>1</U32>', PSUInt(1)),
    ('<U16>1</U16>', PSUInt16(1)),
    ('<U64>1</U64>', PSUInt64(1)),
    (f'<URI>{COMPLEX_ENCODED_STRING}</URI>', PSUri(COMPLEX_STRING)),
    ('<Version>1.2.3.4</Version>', PSVersion('1.2.3.4')),
    (f'<XD>{COMPLEX_ENCODED_STRING}</XD>', PSXml(COMPLEX_STRING)),
])
def test_deserialize_primitive_object(input_value, expected):
    element = ElementTree.fromstring(input_value)
    actual = serializer.deserialize(element)
    assert isinstance(actual, type(expected))
    assert actual == expected


def test_deserialize_invalid_duration():
    expected = re.escape("Duration input 'invalid' is not valid, cannot deserialize")
    with pytest.raises(ValueError, match=expected):
        serializer.deserialize(ElementTree.fromstring('<TS>invalid</TS>'))


def test_serialize_python_class():
    class MyClass:
        
        def __init__(self):
            self.attribute = 'abc'
            self.__private = 'wont appear'
            
        @property
        def property(self):
            return 'def'
        
        def __str__(self):
            return 'MyClass'
        
        def function(self):
            return 'wont appear'
        
    element = serializer.serialize(MyClass())
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<TN RefId="0">' \
                     '<T>System.Management.Automation.PSCustomObject</T>' \
                     '<T>System.Object</T>' \
                     '</TN>' \
                     '<MS>' \
                     '<S N="attribute">abc</S>' \
                     '<S N="property">def</S>' \
                     '</MS>' \
                     '</Obj>'


def test_deserialize_unknown_tag():
    expected = re.escape('Unknown element found: bad')
    with pytest.raises(ValueError, match=expected):
        serializer.deserialize(ElementTree.fromstring('<bad>test</bad>'))


def test_deserialize_special_queue():
    clixml = '<Obj RefId="0">' \
             '<TN RefId="0">' \
             '<T>System.Collections.Generic.Queue`1[[System.Object]]</T>' \
             '<T>System.Object</T>' \
             '</TN>' \
             '<QUE>' \
             '<I32>1</I32>' \
             '<I32>2</I32>' \
             '</QUE>' \
             '</Obj>'
    
    actual = serializer.deserialize(ElementTree.fromstring(clixml))
    assert actual.PSTypeNames == [
        'Deserialized.System.Collections.Generic.Queue`1[[System.Object]]',
        'Deserialized.System.Object',
    ]
    assert isinstance(actual, PSQueue)
    assert actual.get() == 1
    assert actual.get() == 2
    with pytest.raises(queue.Empty):
        actual.get(block=False)


def test_serialize_secure_string_without_cipher():
    with pytest.raises(MissingCipherError):
        serializer.serialize(PSSecureString('test'))

    with pytest.raises(MissingCipherError):
        serializer.deserialize(ElementTree.fromstring('<SS></SS>'))
