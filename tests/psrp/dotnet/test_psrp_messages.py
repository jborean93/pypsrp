# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime
import psrp.dotnet.psrp_messages as psrp_messages
import xml.etree.ElementTree as ElementTree

from psrp.dotnet.primitive_types import (
    PSBool,
    PSDateTime,
    PSGuid,
    PSInt,
    PSInt64,
    PSString,
    PSVersion,
)

from psrp.dotnet.ps_base import (
    PSObject,
)

from psrp.dotnet.serializer import (
    deserialize,
    serialize,
)


def test_session_capability():
    ps_value = psrp_messages.SessionCapability('1.2', '1.2.3', PSVersion('4.5.6.7'))
    assert ps_value.PSVersion == PSVersion('1.2')
    assert ps_value.protocolversion == PSVersion('1.2.3')
    assert ps_value.SerializationVersion == PSVersion('4.5.6.7')
    assert ps_value.TimeZone is None

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<Version N="PSVersion">1.2</Version>' \
                     '<Version N="protocolversion">1.2.3</Version>' \
                     '<Version N="SerializationVersion">4.5.6.7</Version>' \
                     '</MS>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.SessionCapability)
    assert ps_value.PSVersion == PSVersion('1.2')
    assert ps_value.protocolversion == PSVersion('1.2.3')
    assert ps_value.SerializationVersion == PSVersion('4.5.6.7')

    # Because we couldn't rehydrate the object there is no TimeZone property.
    assert len(ps_value.PSObject.extended_properties) == 3


def test_session_capability_with_timezone():
    ps_value = psrp_messages.SessionCapability('1.2', '1.2.3', TimeZone=b'\x00\x01\x02\x03',
                                               SerializationVersion='4.5')
    assert ps_value.PSVersion == PSVersion('1.2')
    assert ps_value.protocolversion == PSVersion('1.2.3')
    assert ps_value.SerializationVersion == PSVersion('4.5')
    assert ps_value.TimeZone == b'\x00\x01\x02\x03'

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<Version N="PSVersion">1.2</Version>' \
                     '<Version N="protocolversion">1.2.3</Version>' \
                     '<Version N="SerializationVersion">4.5</Version>' \
                     '<BA N="TimeZone">AAECAw==</BA>' \
                     '</MS>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.SessionCapability)
    assert ps_value.PSVersion == PSVersion('1.2')
    assert ps_value.protocolversion == PSVersion('1.2.3')
    assert ps_value.SerializationVersion == PSVersion('4.5')
    assert ps_value.TimeZone == b'\x00\x01\x02\x03'
    assert len(ps_value.PSObject.extended_properties) == 4


def test_public_key():
    ps_value = psrp_messages.PublicKey('test')
    assert isinstance(ps_value, psrp_messages.PublicKey)
    assert ps_value.PublicKey == 'test'
    assert isinstance(ps_value.PublicKey, PSString)
    
    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0"><MS><S N="PublicKey">test</S></MS></Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.PublicKey)
    assert isinstance(ps_value.PublicKey, PSString)
    assert ps_value.PublicKey == 'test'


def test_encrypted_session_key():
    ps_value = psrp_messages.EncryptedSessionKey('test')
    assert isinstance(ps_value, psrp_messages.EncryptedSessionKey)
    assert ps_value.EncryptedSessionKey == 'test'
    assert isinstance(ps_value.EncryptedSessionKey, PSString)

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0"><MS><S N="EncryptedSessionKey">test</S></MS></Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.EncryptedSessionKey)
    assert isinstance(ps_value.EncryptedSessionKey, PSString)
    assert ps_value.EncryptedSessionKey == 'test'


def test_public_key_request():
    ps_value = psrp_messages.PublicKeyRequest()
    assert isinstance(ps_value, psrp_messages.PublicKeyRequest)
    assert ps_value == ''

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<S />'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSString)
    assert not isinstance(ps_value, psrp_messages.EncryptedSessionKey)
    assert ps_value == ''


def test_set_max_runspaces():
    ps_value = psrp_messages.SetMaxRunspaces(10, -20)
    assert isinstance(ps_value, psrp_messages.SetMaxRunspaces)
    assert ps_value.MaxRunspaces == 10
    assert ps_value.ci == -20

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<I32 N="MaxRunspaces">10</I32>' \
                     '<I64 N="ci">-20</I64>' \
                     '</MS>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.SetMaxRunspaces)
    assert isinstance(ps_value.MaxRunspaces, PSInt)
    assert ps_value.MaxRunspaces == 10
    assert isinstance(ps_value.ci, PSInt64)
    assert ps_value.ci == -20


def test_set_min_runspaces():
    ps_value = psrp_messages.SetMinRunspaces(10, -20)
    assert isinstance(ps_value, psrp_messages.SetMinRunspaces)
    assert ps_value.MinRunspaces == 10
    assert ps_value.ci == -20

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<I32 N="MinRunspaces">10</I32>' \
                     '<I64 N="ci">-20</I64>' \
                     '</MS>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.SetMinRunspaces)
    assert isinstance(ps_value.MinRunspaces, PSInt)
    assert ps_value.MinRunspaces == 10
    assert isinstance(ps_value.ci, PSInt64)
    assert ps_value.ci == -20


def tet_runspace_availability_bool():
    ps_value = psrp_messages.RunspaceAvailability(True, 50)
    assert isinstance(ps_value, psrp_messages.RunspaceAvailability)
    assert ps_value.SetMinMaxRunspacesResponse is True
    assert ps_value.ci == 50
    
    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<B N="SetMinMaxRunspacesResponse">true</B>' \
                     '<I64 N="ci">50</I64>' \
                     '</MS>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.RunspaceAvailability)
    assert isinstance(ps_value.SetMinMaxRunspacesResponse, PSBool)
    assert ps_value.SetMinMaxRunspacesResponse is True
    assert isinstance(ps_value.ci, PSInt64)
    assert ps_value.ci == 50


def tet_runspace_availability_long():
    ps_value = psrp_messages.RunspaceAvailability(PSInt64(10), 50)
    assert isinstance(ps_value, psrp_messages.RunspaceAvailability)
    assert ps_value.SetMinMaxRunspacesResponse == 10
    assert ps_value.ci == 50

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<I64 N="SetMinMaxRunspacesResponse">10</I64>' \
                     '<I64 N="ci">50</I64>' \
                     '</MS>' \
                     '</Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.RunspaceAvailability)
    assert isinstance(ps_value.SetMinMaxRunspacesResponse, PSInt64)
    assert ps_value.SetMinMaxRunspacesResponse == 10
    assert isinstance(ps_value.ci, PSInt64)
    assert ps_value.ci == 50


def test_runspace_pool_state():
    ps_value = psrp_messages.RunspacePoolState(1)
    assert ps_value.RunspaceState == 1
    assert isinstance(ps_value.RunspaceState, PSInt)
    assert ps_value.ExceptionAsErrorRecord is None

    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0"><MS><I32 N="RunspaceState">1</I32></MS></Obj>'

    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.RunspacePoolState)
    assert ps_value.RunspaceState == 1
    assert isinstance(ps_value.RunspaceState, PSInt)
    assert len(ps_value.PSObject.extended_properties) == 1


def test_user_event():
    ps_value = psrp_messages.UserEvent(
        EventIdentifier=1,
        SourceIdentifier='source id',
        TimeGenerated=PSDateTime(1970, 1, 1),
        Sender='sender',
        SourceArgs='source args',
        MessageData='message data',
        ComputerName='computer name',
        RunspaceId=PSGuid('85ba13fb-6804-47f0-861a-8fe0ceb04acd'),
    )
    assert ps_value['PSEventArgs.EventIdentifier'] == 1
    assert ps_value['PSEventArgs.SourceIdentifier'] == 'source id'
    assert ps_value['PSEventArgs.TimeGenerated'] == PSDateTime(1970, 1, 1)
    assert ps_value['PSEventArgs.Sender'] == 'sender'
    assert ps_value['PSEventArgs.SourceArgs'] == 'source args'
    assert ps_value['PSEventArgs.MessageData'] == 'message data'
    assert ps_value['PSEventArgs.ComputerName'] == 'computer name'
    assert ps_value['PSEventArgs.RunspaceId'] == PSGuid('85ba13fb-6804-47f0-861a-8fe0ceb04acd')
    
    element = serialize(ps_value)
    actual = ElementTree.tostring(element, encoding='utf-8').decode()
    assert actual == '<Obj RefId="0">' \
                     '<MS>' \
                     '<I32 N="PSEventArgs.EventIdentifier">1</I32>' \
                     '<S N="PSEventArgs.SourceIdentifier">source id</S>' \
                     '<DT N="PSEventArgs.TimeGenerated">1970-01-01T00:00:00Z</DT>' \
                     '<S N="PSEventArgs.Sender">sender</S>' \
                     '<S N="PSEventArgs.SourceArgs">source args</S>' \
                     '<S N="PSEventArgs.MessageData">message data</S>' \
                     '<S N="PSEventArgs.ComputerName">computer name</S>' \
                     '<G N="PSEventArgs.RunspaceId">85ba13fb-6804-47f0-861a-8fe0ceb04acd</G>' \
                     '</MS>' \
                     '</Obj>'
    
    ps_value = deserialize(element)
    assert isinstance(ps_value, PSObject)
    assert not isinstance(ps_value, psrp_messages.UserEvent)
    assert ps_value['PSEventArgs.EventIdentifier'] == 1
    assert ps_value['PSEventArgs.SourceIdentifier'] == 'source id'
    assert ps_value['PSEventArgs.TimeGenerated'] == PSDateTime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    assert ps_value['PSEventArgs.Sender'] == 'sender'
    assert ps_value['PSEventArgs.SourceArgs'] == 'source args'
    assert ps_value['PSEventArgs.MessageData'] == 'message data'
    assert ps_value['PSEventArgs.ComputerName'] == 'computer name'
    assert ps_value['PSEventArgs.RunspaceId'] == PSGuid('85ba13fb-6804-47f0-861a-8fe0ceb04acd')


def test_runspace_pool_state_with_error_record():
    # TODO: Test this.
    a = ''
