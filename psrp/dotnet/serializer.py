# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import binascii
import datetime
import decimal
import logging
import queue
import re
import typing
import uuid
import xml.etree.ElementTree as ElementTree

from .ps_base import (
    add_note_property,
    PSDictBase,
    PSEnumBase,
    PSListBase,
    PSObject,
    PSQueueBase,
    PSStackBase,
    TypeRegistry,
)

from .complex_types import (
    PSCustomObject,
    PSDict,
    PSList,
    PSQueue,
    PSStack,
)

from .primitive_types import (
    PSByte,
    PSByteArray,
    PSChar,
    PSDateTime,
    PSDecimal,
    PSDouble,
    PSDuration,
    PSGuid,
    PSInt16,
    PSInt,
    PSInt64,
    PSSByte,
    PSScriptBlock,
    PSSecureString,
    PSSingle,
    PSString,
    PSUInt16,
    PSUInt,
    PSUInt64,
    PSUri,
    PSVersion,
    PSXml,
    _timedelta_total_nanoseconds,
)

from psrp.protocol.crypto import (
    CryptoProvider,
)

from ..exceptions import (
    MissingCipherError,
)


log = logging.getLogger(__name__)


# Finds _x in a case insensitive way which we need to escape first as '_x' is the escape code.
_STRING_SERIAL_ESCAPE_ESCAPE = re.compile('(?i)_(x)')

# Finds C0, C1, and surrogate pairs in a unicode string for us to encode according to the PSRP rules.
_STRING_SERIAL_ESCAPE = re.compile('[\u0000-\u001F\u007F-\u009F\U00010000-\U0010FFFF]')

# To support surrogate UTF-16 pairs we need to use a UTF-16 regex so we can replace the UTF-16 string representation
# with the actual UTF-16 byte value and then decode that.
_STRING_DESERIAL_FIND = re.compile(b'\\x00_\\x00x([\\0\\w]{8})\\x00_')

# Python datetime only supports up to microsecond precision but .NET can go to 100 nanoseconds. To support this level
# of precision we need to extract the fractional seconds part of a datetime ourselves and compute the value.
_DATETIME_FRACTION_PATTERN = re.compile(r'\.(\d+)(.*)')

# Need to extract the Day, Hour, Minute, Second fields from a XML Duration format. Slightly modified from the below.
# Has named capturing groups, no years or months are allowed and the seconds can only be up to 7 decimal places.
# https://stackoverflow.com/questions/52644699/validate-a-xsduration-using-a-regular-expression-in-javascript
_DURATION_PATTERN = re.compile(r'''
^(?P<negative>-?)                         # Can start with - to denote a negative duration.
P(?=.)                                    # Must start with P and contain one of the following matches.
    ((?P<days>\d+)D)?                     # Number of days.
    (T(?=.)                               # Hours/Minutes/Seconds are located after T, must contain 1 of them.
        ((?P<hours>\d+)H)?                # Number of hours.
        ((?P<minutes>\d+)M)?              # Number of minutes.
        ((?P<seconds>\d*                  # Number of seconds, can be a decimal number up to 7 decimal places.
        (\.(?P<fraction>\d{1,7}))?)S)?    # Optional fractional seconds as a 2nd capturing group.
    )?                                    # T is optional, the pos lookahead ensures either T or days is present.
$''', re.VERBOSE)


def deserialize(
        value: ElementTree.Element,
        cipher: typing.Optional[CryptoProvider] = None,
) -> typing.Optional[typing.Union[bool, PSObject]]:
    """Deserialize CLIXML to a Python object.

    Deserializes a CLIXML XML Element from .NET to a Python object.

    Args:
        value: The CLIXML XML Element to deserialize to a Python object.
        cipher: The cipher to use when dealing with SecureStrings.

    Returns:
        (ElementTree.Element): The CLIXML as an XML Element object.
    """
    return _Serializer(cipher).deserialize(value)


def serialize(
        value: typing.Optional[any],
        cipher: typing.Optional[CryptoProvider] = None,
) -> ElementTree.Element:
    """Serialize the Python object to CLIXML.

    Serializes a Python object to a CLIXML element for use in .NET.

    Args:
        value: The value to serialize.
        cipher: The cipher to use when dealing with SecureStrings.

    Returns:
        (ElementTree.Element): The CLIXML as an XML Element object.
    """
    return _Serializer(cipher).serialize(value)


def _deserialize_datetime(
        value: str,
) -> PSDateTime:
    """Deserializes a CLIXML DateTime string.

    DateTime values from PowerShell are in the format 'YYYY-MM-DDTHH:MM-SS[.100's of nanoseconds]Z'. Unfortunately
    Python's datetime type only supports up to a microsecond precision so we need to extract the fractional seconds
    and then parse as a string while calculating the nanoseconds ourselves.

    Args:
        value: The CLIXML datetime string value to deserialize.

    Returns:
        (PSDateTime): A PSDateTime of the .NET DateTime object.
    """
    datetime_str = value[:19]
    fraction_tz_section = value[19:]
    nanoseconds = 0

    fraction_match = _DATETIME_FRACTION_PATTERN.match(fraction_tz_section)
    if fraction_match:
        # We have fractional seconds, need to rewrite as microseconds and keep the nanoseconds ourselves.
        fractional_seconds = fraction_match.group(1)
        if len(fractional_seconds) > 6:
            # .NET should only be showing 100's of nanoseconds but just to be safe we will calculate that based
            # on the length of the fractional seconds found.
            nanoseconds = int(fractional_seconds[-1:]) * (10 ** (3 + 6 - len(fractional_seconds)))
            fractional_seconds = fractional_seconds[:-1]

        timezone_section = fraction_match.group(2)

        datetime_str += f'.{fractional_seconds}{timezone_section}'
    else:
        # No fractional seconds, just use strptime on the original value.
        datetime_str = value

    try:
        dt = PSDateTime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S.%f%z')
    except ValueError:
        # Try without fractional seconds
        dt = PSDateTime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S%z')
    dt.nanosecond = nanoseconds

    return dt


def _deserialize_duration(
        value: str,
) -> PSDuration:
    """Deserializes a CLIXML Duration.

    Deserializes a CLIXML Duration into a PSDuration/timedelta object.

    Args:
        value: The CLIXML string value to deserialize.

    Returns:
        (PSDuration): The timedelta object.
    """
    duration_match = _DURATION_PATTERN.match(value)
    if not duration_match:
        raise ValueError(f"Duration input '{value}' is not valid, cannot deserialize")
    matches = duration_match.groupdict()

    is_negative = bool(matches['negative'])
    days = int(matches['days'] or 0)
    hours = int(matches['hours'] or 0)
    minutes = int(matches['minutes'] or 0)

    seconds = int(float(matches['seconds'] or 0))
    seconds += minutes * 60
    seconds += hours * 3600
    seconds += days * 86400
    nanoseconds = int((matches['fraction'] or '').ljust(7, '0')) * 100

    total = (seconds * 1000000000) + nanoseconds
    if is_negative:
        total *= -1

    return PSDuration(nanoseconds=total)


def _deserialize_secure_string(
        value: str,
        cipher: CryptoProvider,
) -> PSSecureString:
    """Deserializes a CLIXML SecureString.

    Deserializes a CLIXML SecureString to a plaintext string.

    Args:
        value: The CLIXML SecureString value to deserialize.
        cipher: The CryptoProvider that can decrypt the SecureString.

    Returns:
        (PSSecureString): The plaintext string that was deserialized.
    """
    if cipher is None:
        raise MissingCipherError()

    b_enc = base64.b64decode(value)
    b_dec = cipher.decrypt(b_enc)

    return PSSecureString(b_dec.decode('utf-16-le'))


def _deserialize_string(
        value: str,
) -> str:
    """Deserializes a CLIXML string value.

    String values in CLIXML have escaped values for control chars and characters that are represented as surrogate
    pairs in UTF-16. This converts the raw CLIXML string value into a Python string.

    Args:
        value: The CLIXML string element to deserialize.

    Returns:
        (str): The Python str value that represents the actual string represented by the CLIXML.
    """
    def rplcr(matchobj):
        # The matched object is the UTF-16 byte representation of the UTF-8 hex string value. We need to decode the
        # byte str to unicode and then unhexlify that hex string to get the actual bytes of the _x****_ value, e.g.
        # group(0) == b'\x00_\x00x\x000\x000\x000\x00A\x00_'
        # group(1) == b'\x000\x000\x000\x00A'
        # unicode (from utf-16-be) == '000A'
        # returns b'\x00\x0A'
        match_hex = matchobj.group(1)
        hex_string = match_hex.decode('utf-16-be')
        return binascii.unhexlify(hex_string)

    # Need to ensure we start with a unicode representation of the string so that we can get the actual UTF-16 bytes
    # value from that string.
    b_value = value.encode('utf-16-be')
    b_escaped = re.sub(_STRING_DESERIAL_FIND, rplcr, b_value)

    return b_escaped.decode('utf-16-be')


def _serialize_datetime(
        value: typing.Union[PSDateTime, datetime.datetime],
) -> str:
    """Serializes a datetime to a .NET DateTime CLIXML value.

    .NET supports DateTime to a 100 nanosecond precision so we need to manually massage the data from Python to suit
    that precision if it is set.

    Args:
        value: The PSDateTime or datetime.datetime object to serialize as a .NET DateTime CLIXML string.

    Returns:
        (str): The .NET DateTime CLIXML string value.
    """
    fraction_seconds = ""
    nanoseconds = getattr(value, 'nanosecond', None)
    if value.microsecond or nanoseconds:
        fraction_seconds = value.strftime('.%f')

        if nanoseconds:
            fraction_seconds += str(nanoseconds // 100)

    timezone = 'Z'
    if value.tzinfo:
        # Python's timezone strftime format doesn't quite match up with the .NET one.
        utc_offset = value.strftime('%z')
        timezone = f'{utc_offset[:3]}:{utc_offset[3:]}'

    dt_str = value.strftime(f'%Y-%m-%dT%H:%M:%S{fraction_seconds}{timezone}')

    return dt_str


def _serialize_duration(
        value: typing.Union[PSDuration, datetime.timedelta],
) -> str:
    """Serialzies a duration to a .NET TimeSpan CLIXML value.

    .NET TimeSpans supports a precision to 100 nanoseconds so we need to manually massage the timedelta object from
    Python to suit that precision if it is available.

    Args:
        value: The PSDuration or datetime.timedelta object to serialize as a .NET TimeSpan CLIXML string.

    Returns:
        (str): The .NET TimeSpan CLIXML string value.
    """
    # We can only go to 100s of nanoseconds in .NET.
    total_ticks = _timedelta_total_nanoseconds(value) // 100

    negative_str = ''
    if total_ticks < 0:
        negative_str = '-'
        total_ticks *= -1

    days, total_ticks = divmod(total_ticks, 864000000000)

    days_str = f'{days}D' if days else ''
    time_str = ''
    if total_ticks or days == 0:
        hours, total_ticks = divmod(total_ticks, 36000000000)
        minutes, total_ticks = divmod(total_ticks, 600000000)
        seconds = total_ticks / 10000000

        days_str = f'{days}D' if days else ''
        hours_str = f'{hours}H' if hours else ''
        minutes_str = f'{minutes}M' if minutes else ''
        seconds_str = f'{seconds:.7f}' if (seconds or (not hours_str and not minutes_str)) else ''
        if seconds_str:
            seconds_str = seconds_str.rstrip('.0').zfill(1) + 'S'

        time_str = f'T{hours_str}{minutes_str}{seconds_str}'

    return f'{negative_str}P{days_str}{time_str}'


def _serialize_secure_string(
        value: PSSecureString,
        cipher: CryptoProvider,
) -> str:
    """Serializes a string as a .NET SecureString CLIXML value.

    Args:
        value: The string to serialize as a SecureString.
        cipher: The CryptoProvider that encrypts the string.

    Returns:
        (str): The CLIXML SecureString value.
    """
    if cipher is None:
        raise MissingCipherError()

    # Convert the string to a UTF-16 byte string as that is what is expected in Windows.
    b_value = value.encode('utf-16-le')
    b_enc = cipher.encrypt(b_value)

    return base64.b64encode(b_enc).decode()


def _serialize_string(
        value: typing.Union[PSString, str],
) -> str:
    """Serializes a string like value to a .NET String CLIXML value.

    There are certain rules when it comes to escaping certain codepoints and chars that are surrogate pairs when
    UTF-16 encoded. This method escapes the string value and turns it into a valid CLIXML string value.

    Args:
        value: The string value to serialize to CLIXML.

    Returns:
        (str): The string value as a valid CLIXML escaped string.
    """
    def rplcr(matchobj):
        surrogate_char = matchobj.group(0)
        byte_char = surrogate_char.encode('utf-16-be')
        hex_char = binascii.hexlify(byte_char).decode().upper()
        hex_split = [hex_char[i:i + 4] for i in range(0, len(hex_char), 4)]

        return ''.join([f'_x{i}_' for i in hex_split])

    # Before running the translation we need to make sure _ before x is encoded, normally _ isn't encoded except
    # when preceding x. The MS-PSRP docs don't state this but the _x0000_ matcher is case insensitive so we need to
    # make sure we escape _X as well as _x.
    value = re.sub(_STRING_SERIAL_ESCAPE_ESCAPE, '_x005F_\\1', value)
    value = re.sub(_STRING_SERIAL_ESCAPE, rplcr, value)

    return value


class _Serializer:
    """The Python object serializer.

    This is used to encapsulate the (de)serialization of Python objects to and from CLIXML. An instance of this class
    should only be used once as it contains a reference map to objects that are serialized in that message. Use the
    `func:serialize` and `func:deserialize` functions instead of calling this directly.

    Args:
        cipher: The CryptoProvider that is used when serializing/deserializing SecureStrings.
    """

    def __init__(
            self,
            cipher: typing.Optional[CryptoProvider] = None,
    ):
        self._cipher = cipher

        # Used for serialization to store the id() of each object against a unique identifier.
        self._obj_ref_list: typing.List[int] = []
        self._tn_ref_list: typing.List[str] = []

        # Used for deserialization
        self._obj_ref_map: typing.Dict[str, any] = {}
        self._tn_ref_map: typing.Dict[str, typing.List[str]] = {}

    def serialize(
            self,
            value: any,
    ) -> ElementTree.Element:
        """ Serialize a Python object to a XML element based on the CLIXML value. """
        element = None
        if value is None:
            element = ElementTree.Element('Nil')

        elif isinstance(value, bool):
            element = ElementTree.Element('B')
            element.text = str(value).lower()

        elif isinstance(value, (PSByteArray, bytes)):
            element = ElementTree.Element(PSByteArray.PSObject.tag)
            element.text = base64.b64encode(value).decode()

        elif isinstance(value, (PSDateTime, datetime.datetime)):
            element = ElementTree.Element(PSDateTime.PSObject.tag)
            element.text = _serialize_datetime(value)

        elif isinstance(value, (PSDuration, datetime.timedelta)):
            element = ElementTree.Element(PSDuration.PSObject.tag)
            element.text = _serialize_duration(value)

        # Integer types
        elif isinstance(value, (
            int,
            float,
            decimal.Decimal,
            PSChar,
            PSSByte,
            PSInt16,
            PSInt,
            PSInt64,
            PSByte,
            PSUInt16,
            PSUInt,
            PSUInt64,
            PSSingle,
            PSDouble,
            PSDecimal,
        )):
            # Need to test each integral integer type in case we are dealing with an enum. This is needed so we get the
            # correct tag for the XML element
            enum_types = [PSByte, PSByte, PSInt16, PSUInt16, PSInt, PSUInt, PSInt64, PSUInt64]
            for enum_type in enum_types:
                if isinstance(value, enum_type):
                    ps_type = enum_type
                    break

            else:
                if isinstance(value, PSObject):
                    ps_type = type(value)
                elif isinstance(value, int):
                    ps_type = PSInt64 if value > PSInt.MaxValue else PSInt
                elif isinstance(value, float):
                    ps_type = PSSingle
                else:
                    ps_type = PSDecimal

            # Need to make sure int like types are represented by the int value.
            xml_value = value
            if not isinstance(xml_value, (decimal.Decimal, float)):
                xml_value = int(xml_value)

            element = ElementTree.Element(ps_type.PSObject.tag)
            element.text = str(xml_value).upper()  # upper() needed for the Double and Single types.

        # Naive strings
        elif isinstance(value, (
            uuid.UUID,
            PSGuid,
            PSVersion,
        )):
            if isinstance(value, PSObject):
                ps_type = type(value)
            else:
                ps_type = PSGuid

            element = ElementTree.Element(ps_type.PSObject.tag)
            element.text = str(value)

        # SecureString that needs encrypting
        elif isinstance(value, PSSecureString):
            element = ElementTree.Element(PSSecureString.PSObject.tag)
            element.text = _serialize_secure_string(value, self._cipher)

        # String types that need escaping
        elif isinstance(value, (
            str,
            PSString,  # URI, XML, ScriptBlocks inherit PSString so they are included here.
        )):
            if isinstance(value, PSObject):
                ps_type = type(value)
            else:
                ps_type = PSString

            element = ElementTree.Element(ps_type.PSObject.tag)
            element.text = _serialize_string(value)

        # These types of objects need to be placed inside a '<Obj></Obj>' entry.
        is_complex = element is None
        is_enum = isinstance(value, PSEnumBase)
        is_extended_primitive = not is_complex and isinstance(value, PSObject) and \
            bool(value.PSObject.adapted_properties or value.PSObject.extended_properties)

        if not (is_complex or is_extended_primitive or is_enum):
            return element

        obj_id = id(value)
        if obj_id in self._obj_ref_list:
            ref_id = self._obj_ref_list.index(obj_id)
            return ElementTree.Element('Ref', RefId=str(ref_id))

        self._obj_ref_list.append(obj_id)
        ref_id = self._obj_ref_list.index(obj_id)

        if not is_complex:
            sub_element = element
            element = ElementTree.Element('Obj', RefId=str(ref_id))
            element.append(sub_element)

        else:
            element = ElementTree.Element('Obj', RefId=str(ref_id))

        ps_object = getattr(value, 'PSObject', None)
        if ps_object is None:
            # Handle edge cases for known Python container types, otherwise default to a PSCustomObject.
            if isinstance(value, list):
                ps_object = PSList.PSObject

            elif isinstance(value, queue.Queue):
                ps_object = PSQueue.PSObject

            elif isinstance(value, dict):
                ps_object = PSDict.PSObject

            else:
                ps_object = PSCustomObject.PSObject

        # Do not add the type names for extended primitive object unless it's an enum
        if ps_object.type_names and (is_enum or not is_extended_primitive):
            type_names = ps_object.type_names
            main_type = type_names[0]
            is_ref = main_type in self._tn_ref_list

            if is_ref:
                ref_id = self._tn_ref_list.index(main_type)
                ElementTree.SubElement(element, 'TNRef', RefId=str(ref_id))

            else:
                self._tn_ref_list.append(main_type)
                ref_id = self._tn_ref_list.index(main_type)

                tn = ElementTree.SubElement(element, 'TN', RefId=str(ref_id))
                for type_name in type_names:
                    ElementTree.SubElement(tn, 'T').text = type_name

        no_props = True
        for xml_name, prop_type in [('Props', 'adapted'), ('MS', 'extended')]:
            properties = getattr(ps_object, f'{prop_type}_properties')
            if not properties:
                continue

            no_props = False
            prop_elements = ElementTree.SubElement(element, xml_name)
            for prop in properties:
                prop_value = prop.get_value(value)

                # If it's an optional property and the value is not set, omit it from the CLIXML.
                if prop_value is None and prop.optional:
                    continue

                prop_element = self.serialize(prop_value)
                prop_element.attrib['N'] = _serialize_string(prop.name)
                prop_elements.append(prop_element)

        if isinstance(value, (PSStackBase, PSListBase, list)):
            element_tag = PSStackBase.PSObject.tag if isinstance(value, PSStackBase) else PSListBase.PSObject.tag
            container_element = ElementTree.SubElement(element, element_tag)

            for entry in value:
                container_element.append(self.serialize(entry))

        elif isinstance(value, (PSQueueBase, queue.Queue)):
            que_element = ElementTree.SubElement(element, PSQueueBase.PSObject.tag)

            while True:
                try:
                    que_entry = self.serialize(value.get(block=False))
                except queue.Empty:
                    break
                else:
                    que_element.append(que_entry)

        elif isinstance(value, (PSDictBase, dict)):
            dct_element = ElementTree.SubElement(element, PSDictBase.PSObject.tag)

            for dct_key, dct_value in value.items():
                en_element = ElementTree.SubElement(dct_element, 'En')

                s_dct_key = self.serialize(dct_key)
                s_dct_key.attrib['N'] = 'Key'
                en_element.append(s_dct_key)

                s_dct_value = self.serialize(dct_value)
                s_dct_value.attrib['N'] = 'Value'
                en_element.append(s_dct_value)

        else:
            to_string = None if is_extended_primitive and not is_enum else ps_object.to_string
            if to_string:
                ElementTree.SubElement(element, 'ToString').text = to_string
            
            if is_complex and no_props and not isinstance(value, PSObject):
                # If this was a complex object but no properties were defined we consider this a normal Python
                # class instance to serialize. We use the instance attributes and properties to create the CLIXML.
                prop_element = None
                private_prefix = f'_{type(value).__name__}__'  # Double underscores appear as _{class name}__{name}
                for prop in dir(value):
                    prop_value = getattr(value, prop)

                    if prop == 'PSObject' or \
                            prop.startswith('__') or \
                            prop.startswith(private_prefix) or \
                            callable(prop_value):
                        continue

                    elif not prop_element:
                        prop_element = ElementTree.SubElement(element, 'MS')

                    sub_element = self.serialize(prop_value)
                    sub_element.attrib['N'] = _serialize_string(prop)
                    prop_element.append(sub_element)

        return element

    def deserialize(
            self,
            element: ElementTree.Element,
    ) -> any:
        """ Deserializes a XML element of the CLIXML value to a Python type. """
        # These types are pure primitive types and we don't need to do anything special when de-serializing
        element_tag = element.tag

        if element.tag == 'Ref':
            return self._obj_ref_map[element.attrib['RefId']]

        if element_tag == 'Nil':
            return None

        elif element_tag == 'B':
            # Technically can be an extended primitive but due to limitations in Python we cannot subclass bool.
            return element.text.lower() == 'true'

        elif element_tag == 'ToString':
            return _deserialize_string(element.text)

        elif element_tag == PSSecureString.PSObject.tag:
            return _deserialize_secure_string(element.text, self._cipher)

        elif element_tag == PSByteArray.PSObject.tag:
            return PSByteArray(base64.b64decode(element.text))

        elif element_tag == PSChar.PSObject.tag:
            return PSChar(int(element.text))

        elif element_tag == PSDateTime.PSObject.tag:
            return _deserialize_datetime(element.text)

        elif element_tag == PSDuration.PSObject.tag:
            return _deserialize_duration(element.text)

        # Rely on the type to parse the value
        type_map = {cls.PSObject.tag: cls for cls in [
            PSByte,
            PSDecimal,
            PSDouble,
            PSGuid,
            PSInt16,
            PSInt,
            PSInt64,
            PSSByte,
            PSSingle,
            PSUInt16,
            PSUInt,
            PSUInt64,
            PSVersion,
        ]}
        if element_tag in type_map:
            return type_map[element_tag](element.text)

        # String types
        type_map = {cls.PSObject.tag: cls for cls in [
            PSScriptBlock,
            PSString,
            PSUri,
            PSXml,
        ]}
        if element_tag in type_map:
            # Empty strings are `<S />` which means element.text is None.
            return type_map[element_tag](_deserialize_string(element.text or ''))

        # By now we should have an Obj, if not something has gone wrong.
        if element_tag != 'Obj':
            raise ValueError(f'Unknown element found: {element.tag}')

        type_names = [e.text for e in element.findall('TN/T')]
        if type_names:
            tn_ref_id = element.find('TN').attrib['RefId']
            self._tn_ref_map[tn_ref_id] = type_names

        else:
            tn_ref = element.find('TNRef')
            if tn_ref is not None:
                tn_ref_id = tn_ref.attrib['RefId']
                type_names = self._tn_ref_map[tn_ref_id]

        # Build the starting value based on the registered types. This could either be a rehydrated class that has been
        # registered with the TypeRegistry or just a blank PSObject.
        value = TypeRegistry().rehydrate(type_names)
        original_type_names = value.PSTypeNames

        props = {
            'adapted_properties': None,
            'extended_properties': None,
        }
        for obj_entry in element:
            if obj_entry.tag == 'Props':
                props['adapted_properties'] = obj_entry

            elif obj_entry.tag == 'MS':
                props['extended_properties'] = obj_entry

            elif obj_entry.tag == 'ToString':
                value.PSObject.to_string = self.deserialize(obj_entry)

            elif obj_entry.tag == PSDictBase.PSObject.tag:
                raw_values = dict([(self.deserialize(dict_entry.find('*/[@N="Key"]')),
                                    self.deserialize(dict_entry.find('*/[@N="Value"]')))
                                   for dict_entry in obj_entry])

                dict_type = type(value) if isinstance(value, PSDictBase) else PSDict
                value = dict_type(raw_values)

            elif obj_entry.tag == PSStackBase.PSObject.tag:
                raw_values = [self.deserialize(stack_entry) for stack_entry in obj_entry]
                stack_type = type(value) if isinstance(value, PSStackBase) else PSStack
                value = stack_type(raw_values)

            elif obj_entry.tag == PSQueueBase.PSObject.tag:
                if not isinstance(value, PSQueueBase):
                    value = PSQueue()

                for queue_entry in obj_entry:
                    value.put(self.deserialize(queue_entry))

            elif obj_entry.tag in [PSListBase.PSObject.tag, 'IE']:  # IE isn't used by us but the docs refer to it.
                raw_values = [self.deserialize(list_entry) for list_entry in obj_entry]
                list_type = type(value) if isinstance(value, PSListBase) else PSList
                value = list_type(raw_values)

            elif obj_entry.tag not in ['TN', 'TNRef']:
                # Extended primitive types and enums store the value as a sub element of the Obj.
                new_value = self.deserialize(obj_entry)

                if isinstance(value, PSEnumBase):
                    value = type(value)(new_value)

                else:
                    # If the TypeRegister returned any types, set them on the new object name.
                    if value.PSTypeNames:
                        new_value.PSObject.type_names = value.PSTypeNames

                    value = new_value

        if isinstance(value, PSObject):
            # Ensure the object's type names are what was in the CLIXML
            if original_type_names:
                value.PSObject.type_names = original_type_names

            for prop_group_name, prop_xml in props.items():
                if prop_xml is None:
                    continue

                # add_note_property only sets to extended properties. We just use the actual prop list as the scratch
                # object's extended properties. Anything modified/added will reflect in our actual object property.
                scratch_obj = PSCustomObject()
                scratch_obj.PSObject.extended_properties = getattr(value.PSObject, prop_group_name)
                for obj_property in prop_xml:
                    prop_name = _deserialize_string(obj_property.attrib['N'])
                    prop_value = self.deserialize(obj_property)
                    add_note_property(scratch_obj, prop_name, prop_value, force=True)
                    
        ref_id = element.attrib.get('RefId', None)
        if ref_id is not None:
            self._obj_ref_map[ref_id] = value

        return value
