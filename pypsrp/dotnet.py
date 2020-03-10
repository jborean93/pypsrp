# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

# These are all the base .NET classes as defined by Python. They should be used directly to help with serializing a
# Python value as a specific .NET object or used as a base class to define slight variations of specific types, like a
# Generic.List[String]. See the 'examples' folder for more info on how to use these types.

__metaclass__ = type

import sys

from datetime import (
    datetime,
)

from decimal import (
    Decimal,
)

from six import (
    binary_type,
    text_type,
)

from uuid import (
    UUID,
)

try:
    from queue import Queue
except ImportError:  # pragma: no cover
    from Queue import Queue


class NoToString(object):
    """ Used to set to a PSObjectMeta to_string attribute to tell the serializer not to set a <ToString> element."""
    def __new__(cls, *args, **kwargs):
        return cls


class PSPropertyInfo:

    def __init__(self, name, clixml_name=None, optional=False, ps_type=None):
        """
        Define the metadata of the property of a class and how it is serialized and deserialized to CLIXML. Each
        property should be set to the adapted or extended propertiest list on a PSObjectMeta.

        :param name: The Python attribute name to get/set the value when (de)serializing.
        :param clixml_name: The value to set as the XML element attribute 'N' when (de)serializing. This is the actual
            .NET/PS attribute name.
        :param optional: Will skip adding the property if does not exist on the object that is being deserialized
            rather than a <Nil></Nil> element.
        :param ps_type: Explicitly set the PowerShell type to serialize the property value as. This overrides the
            actual Python type when being serialized. It is also used to encapsulate the XML value when the object is
            being deserialized.
        """
        self.name = name
        self.clixml_name = clixml_name or name
        self.optional = optional
        self.ps_type = ps_type


class PSObjectMeta:

    def __init__(self):
        """
        Explicit metadata to set on a PSObject that defines how the object is to be serialized and contains the raw
        .NET object information.
        """
        self.adapted_properties = []  # A list of adapted properties of the raw object.
        self.extended_properties = []  # A list of extended properties of the raw object.
        self.to_string = None  # The raw <ToString> XML element from deserialization.
        self.type_names = []  # A list of type names for the deserialized object.


class PSListObjectMeta(PSObjectMeta):

    def __init__(self):
        super(PSListObjectMeta, self).__init__()
        self.value_type = PSObject


class PSDictObjectMeta(PSListObjectMeta):

    def __init__(self):
        super(PSDictObjectMeta, self).__init__()
        self.key_type = PSObject


class PSEnumObjectMeta(PSObjectMeta):

    def __init__(self):
        """
        Extension of PSObjectMeta that adds the enum_type to define the underlying type of an Enum value.
        """
        super(PSEnumObjectMeta, self).__init__()
        self.enum_type = PSInt


class PSObject:

    def __init__(self, *args, **kwargs):
        """
        Base object of all .NET objects to be serialized or have been deserialized. These objects contains the
        psobject attribute which defines all the extra metadata of how a Python class is to be serialized and it's .NET
        type. Any custom types defined by an end user should inherit this class otherwise a generic PSCustomObject is
        serialized based on the class' attributes and properties.
        """
        super(PSObject, self).__init__(*args, **kwargs)
        self.psobject = PSObjectMeta()

    def __str__(self):
        if self.psobject.to_string is not None:
            return self.psobject.to_string
        else:
            return super(PSObject, self).__str__()


class PSString(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.1 - String
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/052b8c32-735b-49c0-8c24-bb32a5c871ce

    XML Element: <S>
    """
    def __init__(self, *args, **kwargs):
        super(PSString, self).__init__()


class PSChar(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.2 - Character
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ff6f9767-a0a5-4cca-b091-4f15afc6e6d8

    XML Element: <C>
    """
    def __init__(self, *args, **kwargs):
        super(PSChar, self).__init__()


PSBool = bool
"""
[MS-PSRP] - 2.2.5.1.3 - Boolean
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/8b4b1067-4b58-46d5-b1c9-b881b6e7a0aa

XML Element: <B>
Cannot subclass due to a limitation on Python. This unfortunately means we can't represent an extended primitive
object of this type in Python as well.
"""


class PSDateTime(PSObject, datetime):
    """
    [MS-PSRP] 2.2.5.1.4 - Date/Time
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/a3b75b8d-ad7e-4649-bb82-cfa70f54fb8c

    XML Element: <DT>
    """
    def __init__(self, *args, **kwargs):
        super(PSDateTime, self).__init__()
        self.nanosecond = 0


class PSDuration(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.4 - Duration
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/434cd15d-8fb3-462c-a004-bcd0d3a60201

    XML Element: <TS>
    """
    def __init__(self, *args, **kwargs):
        super(PSDuration, self).__init__()


class PSByte(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.6 - Unsigned Byte
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/6e25153d-77b6-4e21-b5fa-6f986895171a

    XML Element: <By>
    """
    def __init__(self, *args, **kwargs):
        super(PSByte, self).__init__()


class PSSByte(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.7 - Signed Byte
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/8046c418-1531-4c43-9b9d-fb9bceace0db

    XML Element: <SB>
    """
    def __init__(self, *args, **kwargs):
        super(PSSByte, self).__init__()


class PSUInt16(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.8 - Unsigned Short
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/33751ca7-90d0-4b5e-a04f-2d8798cfb419

    XML Element: <U16>
    """
    def __init__(self, *args, **kwargs):
        super(PSUInt16, self).__init__()


class PSInt16(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.9 - Signed Short
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e0ed596d-0aea-40bb-a254-285b71188214

    XML Element: <I16>
    """
    def __init__(self, *args, **kwargs):
        super(PSInt16, self).__init__()


class PSUInt(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.10 - Unsigned Int
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/7b904471-3519-4a6a-900b-8053ad975c08

    XML Element: <U32>
    """
    def __init__(self, *args, **kwargs):
        super(PSUInt, self).__init__()


class PSInt(PSObject, int):
    """
    [MS-PSRP] 2.2.5.1.11 - Signed Int
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/9eef96ba-1876-427b-9450-75a1b28f5668

    XML Element: <I32>
    """
    def __init__(self, *args, **kwargs):
        super(PSInt, self).__init__()


if sys.version_info[0] > 2:
    class PSUInt64(PSObject, int):
        """
        [MS-PSRP] 2.2.5.1.12 - Unsigned Long
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d92cd5d2-59c6-4a61-b517-9fc48823cb4d

        XML Element: <U64>
        """

        def __init__(self, *args, **kwargs):
            super(PSUInt64, self).__init__()

    class PSInt64(PSObject, int):
        """
        [MS-PSRP] 2.2.5.1.13 - Signed Long
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/de124e86-3f8c-426a-ab75-47fdb4597c62

        XML Element: <I64>
        """

        def __init__(self, *args, **kwargs):
            super(PSInt64, self).__init__()
else:
    class PSUInt64(PSObject, long):
        def __init__(self, *args, **kwargs):
            super(PSUInt64, self).__init__()


    class PSInt64(PSObject, long):
        def __init__(self, *args, **kwargs):
            super(PSInt64, self).__init__()


class PSSingle(PSObject, float):
    """
    [MS-PSRP] 2.2.5.1.14 - Float
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d8a5a9ab-5f52-4175-96a3-c29afb7b82b8

    XML Element: <Sg>
    """
    def __init__(self, *args, **kwargs):
        super(PSSingle, self).__init__()


class PSDouble(PSObject, float):
    """
    [MS-PSRP] 2.2.5.1.15 - Double
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/02fa08c5-139c-4e98-a13e-45784b4eabde

    XML Element: <Db>
    """
    def __init__(self, *args, **kwargs):
        super(PSDouble, self).__init__()


class PSDecimal(PSObject, Decimal):
    """
    [MS-PSRP] 2.2.5.1.16 - Decimal
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/0f760f90-fa46-49bd-8868-001e2c29eb50

    XML Element: <D>
    """
    def __init__(self, *args, **kwargs):
        super(PSDecimal, self).__init__()


class PSByteArray(PSObject, binary_type):
    """
    [MS-PSRP] 2.2.5.1.17 - Array of Bytes
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/489ed886-34d2-4306-a2f5-73843c219b14

    XML Element: BA
    """
    def __init__(self, *args, **kwargs):
        super(PSByteArray, self).__init__()


class PSGuid(PSObject, UUID):
    """
    [MS-PSRP] 2.2.5.1.18 - GUID
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c30c37fa-692d-49c7-bb86-b3179a97e106

    XML Element: <G>
    """
    def __setattr__(self, name, value):
        # UUID raises TypeError on __setattr__ and there are cases where we need to override the psobject attribute.
        if name == 'psobject':
            self.__dict__['psobject'] = value
            return

        super(PSGuid, self).__setattr__(name, value)


class PSUri(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.19 - URI
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4ac73ac2-5cf7-4669-b4de-c8ba19a13186

    XML Element: <URI>
    """
    def __init__(self, *args, **kwargs):
        super(PSUri, self).__init__()


PSNull = None
"""
[MS-PSRP] 2.2.5.1.20 - Null Value
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/402f2a78-5771-45ae-bf33-59f6e57767ca

XML Element: <Nil>
"""


class PSVersion(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.21 - Version
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/390db910-e035-4f97-80fd-181a008ff6f8

    XML Element: <Version>
    """
    def __init__(self, *args, **kwargs):
        super(PSVersion, self).__init__()


class PSXml(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.22 - XML Document
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/df5908ab-bb4d-45e4-8adc-7258e5a9f537

    XML Element: <XD>
    """
    def __init__(self, *args, **kwargs):
        super(PSXml, self).__init__()


class PSScriptBlock(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.23 - ScriptBlock
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/306af1be-6be5-4074-acc9-e29bd32f3206

    XML Element: <SBK>
    """
    def __init__(self, *args, **kwargs):
        super(PSScriptBlock, self).__init__()


class PSSecureString(PSObject, text_type):
    """
    [MS-PSRP] 2.2.5.1.24 - Secure String
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/69b9dc01-a843-4f91-89f8-0205f021a7dd

    XML Element: <SS>

    Note: A SecureString is not actually encrypted in memory on the Python host but just a way to mark a string to
    encrypt as a SecureString across the wire.
    """
    def __init__(self, *args, **kwargs):
        super(PSSecureString, self).__init__()


class PSStack(PSObject, list):
    """
    [MS-PSRP] 2.2.5.2.6.1 - Stack
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e9cf648e-38fe-42ba-9ca3-d89a9e0a856a

    XML Element: <STK>
    """
    pass


class PSQueue(PSObject, Queue):
    """
    [MS-PSRP] 2.2.5.2.6.2 - Queue
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ade9f023-ac30-4b7e-be17-900c02a6f837

    XML Element: <QUE>
    """
    pass


class PSList(PSObject, list):
    """
    [MS-PSRP] 2.2.5.2.6.3 - List
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/f4bdb166-cefc-4d49-848c-7d08680ae0a7

    XML Element: <LST> or <IE>
    """
    pass


class PSDict(PSObject, dict):
    """
    [MS-PSRP] 2.2.5.2.6.4 - Dictionaries
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c4e000a2-21d8-46c0-a71b-0051365d8273

    XML Element: <DCT>
    """
    pass


class PSEnumBase(PSObject, int):
    """
    [MS-PSRP] 2.2.5.2.7 0 Contents of Enums
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/893ecc12-6d87-49a8-b5fe-55ab6854c973

    This should not be initialized by itself, it must be implemented by another class with the __init__ signature
    of:

    def __init__(self, value):
        super(PSEnumClass, self).__init__(value, 'System.EnumType')
    """

    ENUM_MAP = {'None': 0}
    IS_FLAGS = False

    def __init__(self, value, type_name=None, base_type=PSInt):
        super(PSEnumBase, self).__init__()
        type_names = ['System.Enum', 'System.ValueType', 'System.Object']
        if type_name:
            type_names.insert(0, type_name)

        self.psobject = PSEnumObjectMeta()
        self.psobject.type_names = type_names
        self.psobject.enum_type = base_type

    def __new__(cls, value):
        enum_value = value

        if isinstance(value, text_type):
            if cls.IS_FLAGS:
                enum_value = 0

                for label in value.split(','):
                    label = label.strip()

                    if label not in cls.ENUM_MAP:
                        raise ValueError("Invalid enum flag '%s', valid flags: %s"
                                         % (label, ", ".join(cls.ENUM_MAP.keys())))

                    enum_value |= cls.ENUM_MAP[label]
            else:
                if value not in cls.ENUM_MAP:
                    raise ValueError("Invalid enum string '%s', valid strings: %s"
                                     % (value, ", ".join(cls.ENUM_MAP.keys())))
                enum_value = cls.ENUM_MAP[value]

        return super(PSEnumBase, cls).__new__(cls, enum_value)

    def __str__(self):
        enum_value = int(self)
        enum_map = dict([(v, k) for k, v in self.ENUM_MAP.items()])

        if not self.IS_FLAGS:
            return enum_map.get(enum_value, str(enum_value))

        if enum_value in enum_map:
            return enum_map[enum_value]

        flags_set = []
        for v in sorted([v for v in enum_map.keys() if v != 0], reverse=True):
            if enum_value & v == v:
                flags_set.append(enum_map[v])
                enum_value &= ~v

        if enum_value != 0:
            flags_set.append(str(enum_value))

        return ", ".join(flags_set or [str(int(self))])
