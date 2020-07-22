# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import datetime
import decimal
import six
import struct
import uuid

from pypsrp._utils import (
    to_bytes,
    to_string,
    to_unicode,
)

try:
    from typing import (
        Dict,
        List,
        Optional,
        Tuple,
    )
except ImportError:  # pragma: no cover
    # Python2 does not have typing
    Dict = None
    List = None
    Optional = None
    Tuple = None

try:
    from queue import Queue
except ImportError:  # pragma: no cover
    from Queue import Queue

if six.PY2:
    large_int = long
    unichr = unichr
else:
    large_int = int
    unichr = chr


class _Singleton(type):
    __instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls.__instances:
            cls.__instances[cls] = super(_Singleton, cls).__call__(*args, **kwargs)

        return cls.__instances[cls]


@six.add_metaclass(_Singleton)
class TypeRegistry:
    """Registry of all the Python classes that implement PSObject.

    This singleton is used to store all the classes that implement PSObject and the .NET type it implements. This is
    used for deserialization to provide a dynamic list of Python classes that can be dehydrated.
    """

    def __init__(self):  # type: () -> None
        self.registry = {}

    def register(self, type_name, cls):  # type: (str, type) -> None
        """ Register a type that can be used for rehydration. """
        if type_name not in self.registry:
            self.registry[type_name] = cls

    def rehydrate(self, type_names):  # type: (List[str]) -> PSObject
        """ Rehydrate a blank instance based on the type names. """
        # If the type is registered, return that actual type.
        type_name = type_names[0] if type_names else None
        if type_name and type_name in self.registry:
            # Try and create the object, ignore errors and fallback to PSObject if we cannot init it.
            try:
                return self.registry[type_name]()
            except TypeError:
                pass

        # The type is not registered, return a PSObject with the type names set to 'Deserialized.<TN>'.
        obj = PSObject()
        obj.PSObject = PSObjectMeta(["Deserialized.%s" % tn for tn in type_names])
        return obj


class _PSMetaType(type):
    """PowerShell object meta type.

    This is a meta type that is assigned to PSObject and any class that inherits PSObject will be initialised through
    this type. It enforces the presence of the PSObject class attribute that describes how to (de)serialize the Python
    class to a .NET type through CLIXML. It is also used to automatically register any rehydratable objects in the
    TypeRegister so they are easily rehydrated by the serializer.
    """
    __registry = TypeRegistry()

    def __init__(cls, name, bases, attributes):
        super(_PSMetaType, cls).__init__(name, bases, attributes)
        obj_type = '%s.%s' % (cls.__module__, cls.__name__)

        # Except for some special base objects, all classes of this type must have a valid PSObject class attribute.
        # We check the type name as a string because those classes are defined yet.
        if cls.__module__ == _PSMetaType.__module__ and cls.__name__ in ['PSObject', 'PSEnumBase', 'PSFlagBase']:
            return

        ps_object = cls.PSObject
        if not hasattr(ps_object, 'type_names') or len(ps_object.type_names) < 1:
            raise ValueError('%s''s PSObject class attribute must have at least 1 type_name defined' % obj_type)

        if ps_object.rehydrate:
            cls.__registry.register(ps_object.type_names[0], cls)

        if issubclass(cls, PSEnumBase):
            # Convert the class attributes representing the enum values to an instance of that class.
            for k, v in attributes.items():
                if k.startswith('__') or k == 'PSObject':
                    continue

                enum_val = cls(v)
                setattr(cls, k, enum_val)

                # Make sure the class' PSObject has the enum map. Special edge case for none -> None as None is a
                # reserved keyword in Python but the string should still show the capitalised version.
                if k == 'none':
                    k = 'None'
                cls.PSObject.enum_map.append((v, k))


class PSObjectMeta:

    def __init__(self, type_names, adapted_properties=None, extended_properties=None, rehydrate=True, tag='Obj'):
        # type: (List[str], Optional[List[PSPropertyInfo]], Optional[List[PSPropertyInfo]], bool, str) -> None
        """The PowerShell object metadata.

        This describes the metadata around how to (de)serialize the Python class to a .NET type through CLIXML. The
        value should be assigned to the PSObject class attribute of any class that inherits from PSObject.

        Using `rehydrate=True` can only be done on types that do not have any mandatory args on the `__init__()`
        function. When the object is deserialized the deserialized object will be an actual instance of the registered
        Python type rather than a generic PSObject.

        Setting `tag` should only be set by the builtin types to pypsrp.

        Args:
            type_names: List of .NET type names that the type implements, this should contains at least 1 type.
            adapted_properties: List of adapted properties, these are native to the .NET type.
            extended_properties: List of extended properties, these are added to the .NET type by PowerShell.
            rehydrate: Whether the type is able to be rehydrated or not.
            tag: The CLIXML element tag, this is designed for internal use.

        Attributes:
            type_names (List[str]): See args.
            adapted_properties (List[str]): See args.
            extended_properties (List[str]): See args.
            rehydrate (bool): See args.
            tag (str): See args.
            to_string (Optional[six.text_type]): Set to the `<ToString>` element if the object was deserialized.
            enum_map (List[Tuple[int, str]]): A list of enum values and their label when the type is a PSEnumBase.
        """
        self.type_names = type_names
        self.adapted_properties = adapted_properties or []
        self.extended_properties = extended_properties or []
        self.rehydrate = rehydrate
        self.tag = tag
        self.to_string = None
        self.enum_map = []  # type: List[Tuple[int, str]]
        self._xml = None  # type: Optional[six.text_type]

    def new_instance_copy(self):  # type: () -> PSObjectMeta
        """ Creates a copy of the existing meta to use for a new class instance. """
        props = {
            'adapted_properties': [],
            'extended_properties': [],
        }
        for prop_name, prop_value in props.items():
            for prop in getattr(self, prop_name):
                prop_value.append(PSPropertyInfo(prop.name, prop.optional, prop.ps_type))

        return PSObjectMeta(
            type_names=list(self.type_names),
            rehydrate=self.rehydrate,
            tag=self.tag,
            **props
        )


class PSPropertyInfo:

    def __init__(self, name, optional=False, ps_type=None):
        # type: (str, bool, Optional[type]) -> None
        """Property metadata for an object's property.

        The metadata for an object's property that describes how that property is serialized/deserialized.

        Args:
            name: The name of the property, this must match the Python/PS property name.
            optional: Whether the property is optional or not.
            ps_type: The actual primitive type to use when serializing the property.

        Attributes:
            name (str): See args.
            optional (bool): See args.
            ps_type (type): See args.
            value (any): The value of the property.
        """
        self.name = to_string(name)
        self.optional = optional
        self.ps_type = ps_type
        self.value = None


@six.add_metaclass(_PSMetaType)
class PSObject:
    """The base PSObject type.

    This is the base PSObject type that all PS object classes should inherit. It controls all the behaviour around
    getting and setting attributes that are based on PowerShell properties in a way that is similar to PowerShell
    itself.

    This object should not be created by anybody as it is just used to set up the scaffolding around how Python
    deals with PowerShell types.
    """

    PSObject = None  # Must be set by inheriting types

    def __new__(cls, *args, **kwargs):
        # Ensure every new object has an instance copy of the class PSObject.
        if not issubclass(cls, PSEnumBase) and cls.PSObject and cls.PSObject.tag == 'Obj':
            instance = super(PSObject, cls).__new__(cls)

        else:
            # Any primitive object is known to subclass multiple types, we preserve the args and kwargs so they are
            # passing down to the Python type it subclasses.
            instance = super(PSObject, cls).__new__(cls, *args, **kwargs)

        if cls.PSObject:
            instance.PSObject = instance.PSObject.new_instance_copy()

        return instance

    @property
    def PSBase(self):
        """ The raw .NET object without the extended type system properties. This is not yet implemented. """
        return

    @property
    def PSAdapted(self):  # type: () -> Dict[str, any]
        """ A dict of all the adapted properties. """
        return dict((p.name, p.value) for p in self.PSObject.adapted_properties)

    @property
    def PSExtended(self):  # type: () -> Dict[str, any]
        """ A dict of all the extended properties."""
        return dict((p.name, p.value) for p in self.PSObject.extended_properties)

    @property
    def PSTypeNames(self):  # type: () -> List[str]
        """ Shortcut to PSObject.type_names, one of PowerShells reserved properties. """
        return self.PSObject.type_names

    def __getattr__(self, item):
        # The PS properties aren't actually an attribute on the object but self.__dict__ will still report they are.
        # We just try and get the attribute from __dict__ and raise an AttributeError if that key was not found.
        try:
            return self.__dict__[item]
        except KeyError:
            pass

        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, item))

    def __setattr__(self, key, value):
        # Get the raw untainted __dict__ value which does not include our object's PS properties that self.__dict__
        # will return. We use this to see whether we need to set the PSObject property or the Python object attribute.
        d = super(PSObject, self).__getattribute__('__dict__')

        # This must be done first before the key in properties check.
        if key == 'PSObject':
            return super(PSObject, self).__setattr__(key, value)

        if key not in d:
            ps_object = self.PSObject

            # Extended props take priority, once we find a match we stopped checking.
            for prop_type in ['extended', 'adapted']:
                properties = getattr(ps_object, '%s_properties' % prop_type)
                for prop in properties:
                    if prop.name == key:
                        prop.value = value
                        return

        # If the key already exists in the __dict__ or it's a new attribute that's not a registered property, just
        # set the key/value to the object itself.
        super(PSObject, self).__setattr__(key, value)

    def __getattribute__(self, item):
        val = super(PSObject, self).__getattribute__(item)

        # In all cases we want to return the normal attribute Python would return except if __dict__ was called. In
        # this case we make a copy and add the adapted and extended PS properties so that debuggers and calls like
        # vars() and dir() will report them as attributes.
        if item == '__dict__':
            val = val.copy()  # Make sure we don't actually mutate the pure __dict__.
            ps_object = self.PSObject

            # Extended props take priority over adapted props, by checking that last we ensure the prop will have that
            # value if there are duplicates.
            for prop_type in ['adapted', 'extended']:
                properties = getattr(ps_object, '%s_properties' % prop_type)
                for prop in properties:
                    val[prop.name] = prop.value

        return val

    def __getitem__(self, item):
        """Allow getting properties using the index syntax.

        By overriding __getitem__ you can access properties on an object using the index syntax, i.e.
        obj['PropertyName']. This matches the PowerShell behaviour where properties can be retrieved either by dot
        notation or by index notation.

        It also makes it easier to get properties with a name that aren't valid attribute names in Python. By allowing
        a string field someone can do `obj['1 Invalid Attribute$']`. An alternative option is through getattr() as
        that accepts a string. This works because PSObject also override :func:`__getattr__` and :func:`__setattr__`
        and it edits the `__dict__` directly.

        This is complicated by the Dict/List/Stack/Queue types as we need this to preserve the actual lookup values.
        In those cases the __getitem__ lookup will favour the base object items before falling back to looking at the
        attributes.
        """
        return getattr(self, item)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __str__(self):
        if self.PSObject.to_string is not None:
            return to_string(self.PSObject.to_string)

        else:
            return super(PSObject, self).__str__()


class PSEnumBase(PSObject):
    """The base enum PSObject type.

    This is the base enum PSObject type that all enum complex objects should inherit from. While we cannot use the
    `enum` module as a PSObject has a different metaclass we can try and replicate some of the functionality here. Any
    objects that inherit `PSEnumBase` should also inherit one of the integer PS types like `PSInt` and any other class
    attributes (apart from PSObject) are treated as enum value. An example enum would look like:

        class MyEnum(PSEnumBase, PSInt):
            PSObject = PSObjectMeta(
                type_names=['System.MyEnum', 'System.Enum', 'System.ValueType', 'System.Object'],
                rehydrate=True,
            )

            Label = 1
            Other = 2

    A user of that enum would then access it like `MyEnum.Label` or `MyEnum.Other`. This class is designed for enums
    that allow only 1 value, if you require a flag like enum, use `PSFlagBase` as the base type.
    """

    def __str__(self):
        # The enum map is stored in the instance's class PSObject not the instance's PSObject.
        enum_map = dict((k, v) for k, v in self.__class__.PSObject.enum_map)

        return enum_map.get(self, 'Unknown')


class PSFlagBase(PSEnumBase):
    """The base flags enum PSObject type.

    This is like `PSEnumBase` but supports having multiple values set like `[FlagsAttribute]` in .NET. Using any
    bitwise operations will preserve the type so `MyFlags.Flag1 | MyFlags.Flag2` will still be an instance of
    `MyFlags`.

    Like `PSEnumBase`, an implementing type needs to inherit both `PSFlagBase` as well as one of the integer PS types
    like `PSInt`. An example flag enum would look like:

        class MyFlags(PSFlagBase, PSInt):
            PSObject = PSObjectMeta(
                type_names=['System.MyFlags', 'System.Enum', 'System.ValueType', 'System.Object'],
                rehydrate=True,
            )

            Flag1 = 1
            Flag2 = 2
            Flag3 = 4
    """

    def __str__(self):
        # The enum map is stored in the instance's class PSObject not the instance's PSObject.
        enum_map = dict((k, v) for k, v in self.__class__.PSObject.enum_map)

        val = int(self)

        # Special edge case where the value is 0
        if val == 0 and 0 in enum_map:
            return enum_map[0]

        elif 0 in enum_map:
            del enum_map[0]

        flag_list = []
        for enum_val, enum_name in enum_map.items():
            if val & enum_val == enum_val:
                flag_list.append(enum_name)
                val &= ~enum_val

            if val == 0:
                break

        return ', '.join(flag_list)

    def __and__(self, other):
        return self.__class__(super(PSFlagBase, self).__and__(other))

    def __or__(self, other):
        return self.__class__(super(PSFlagBase, self).__or__(other))

    def __xor__(self, other):
        return self.__class__(super(PSFlagBase, self).__xor__(other))

    def __lshift__(self, other):
        return self.__class__(super(PSFlagBase, self).__lshift__(other))

    def __rshift__(self, other):
        return self.__class__(super(PSFlagBase, self).__rshift__(other))

    def __invert__(self):
        return self.__class__(super(PSFlagBase, self).__invert__())


class PSCustomObject(PSObject):

    PSObject = PSObjectMeta(type_names=['System.Management.Automation.PSCustomObject', 'System.Object'])

    def __init__(self, properties=None):
        if not properties:
            return

        for prop_name, prop_value in properties.items():
            # Special use case with [PSCustomObject]@{PSTypeName = 'TypeName'} in PowerShell where the value is
            # added to the top of the objects type names.
            if prop_name == 'PSTypeName':
                self.PSObject.type_names.insert(0, prop_value)

            else:
                self.PSObject.extended_properties.append(PSPropertyInfo(prop_name))
                self[prop_name] = prop_value


class PSString(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.1 - String

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/052b8c32-735b-49c0-8c24-bb32a5c871ce
    """
    PSObject = PSObjectMeta(['System.String', 'System.Object'], tag='S')

    def __init__(self, *args, **kwargs):
        super(PSString, self).__init__()

    def __getslice__(self, start, stop):
        return self.__getitem__(slice(start, stop))

    def __getitem__(self, item):
        if isinstance(item, six.string_types):
            return super(PSString, self).__getitem__(item)

        else:
            # String indexing, need to preserve the PSObject.
            val = PSString(six.text_type.__getitem__(self, item))
            val.PSObject = self.PSObject
            return val


class PSChar(PSObject, int):
    """[MS-PSRP] 2.2.5.1.2 - Character

    A char in .NET represents a UTF-16 codepoint from `\u0000` to `\uFFFF`. The codepoint may not represent a valid
    unicode character, say it's 1 half of a surrogate pair, but it's still a valid Char. A PSChar can be initialized
    just like an `int()` as long as the value is from `0` to `65535` inclusive. A PSChar can also be initialized from
    a single string character like `PSChar('a')`, any byte strings will be encoded as UTF-8 when getting the character.
    If a decimal value is used as a string then the PSChar instance will be the value of that codepoint of the
    character and not the decimal value itself.

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ff6f9767-a0a5-4cca-b091-4f15afc6e6d8
    """
    PSObject = PSObjectMeta(['System.Char', 'System.ValueType', 'System.Object'], tag='C')

    def __init__(self, *args, **kwargs):
        super(PSChar, self).__init__()

    def __new__(cls, *args, **kwargs):
        raw_args = list(args)

        if isinstance(raw_args[0], (six.text_type, bytes)):
            # Ensure we are dealing with a UTF-8 string before converting to UTF-16
            b_value = to_bytes(to_unicode(raw_args[0]), encoding='utf-16-le')
            if len(b_value) > 2:
                raise ValueError('A PSChar must be 1 UTF-16 codepoint.')

            raw_args[0] = struct.unpack("<H", b_value)[0]

        char = super(PSChar, cls).__new__(cls, *raw_args, **kwargs)
        if char < 0 or char > 65535:
            raise ValueError("A PSChar must be between 0 and 65535.")

        return char

    def __str__(self):
        # While backed by an int value, the str representation should be the char it represents.
        return to_string(unichr(self))


PSBool = bool
"""[MS-PSRP] - 2.2.5.1.3 - Boolean

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/8b4b1067-4b58-46d5-b1c9-b881b6e7a0aa
XML Element: <B>

Cannot subclass due to a limitation on Python. This unfortunately means we can't represent an extended primitive
object of this type in Python as well.
"""


class PSDateTime(PSObject, datetime.datetime):
    """[MS-PSRP] 2.2.5.1.4 - Date/Time

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/a3b75b8d-ad7e-4649-bb82-cfa70f54fb8c
    """
    PSObject = PSObjectMeta(['System.DateTime', 'System.ValueType', 'System.Object'], tag='DT')

    def __init__(self, *args, **kwargs):
        super(PSDateTime, self).__init__()
        self.nanosecond = 0


class PSDuration(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.4 - Duration

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/434cd15d-8fb3-462c-a004-bcd0d3a60201
    """
    PSObject = PSObjectMeta(['System.TimeSpan', 'System.ValueType', 'System.Object'], tag='TS')

    def __init__(self, *args, **kwargs):
        super(PSDuration, self).__init__()


class PSByte(PSObject, int):
    """[MS-PSRP] 2.2.5.1.6 - Unsigned Byte

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/6e25153d-77b6-4e21-b5fa-6f986895171a
    """
    PSObject = PSObjectMeta(['System.Byte', 'System.ValueType', 'System.Object'], tag='By')

    def __init__(self, *args, **kwargs):
        super(PSByte, self).__init__()


class PSSByte(PSObject, int):
    """[MS-PSRP] 2.2.5.1.7 - Signed Byte

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/8046c418-1531-4c43-9b9d-fb9bceace0db
    """
    PSObject = PSObjectMeta(['System.SByte', 'System.ValueType', 'System.Object'], tag='SB')

    def __init__(self, *args, **kwargs):
        super(PSSByte, self).__init__()


class PSUInt16(PSObject, int):
    """[MS-PSRP] 2.2.5.1.8 - Unsigned Short

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/33751ca7-90d0-4b5e-a04f-2d8798cfb419
    """
    PSObject = PSObjectMeta(['System.UInt16', 'System.ValueType', 'System.Object'], tag='U16')

    def __init__(self, *args, **kwargs):
        super(PSUInt16, self).__init__()


class PSInt16(PSObject, int):
    """[MS-PSRP] 2.2.5.1.9 - Signed Short

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e0ed596d-0aea-40bb-a254-285b71188214
    """
    PSObject = PSObjectMeta(['System.Int16', 'System.ValueType', 'System.Object'], tag='I16')

    def __init__(self, *args, **kwargs):
        super(PSInt16, self).__init__()


class PSUInt(PSObject, int):
    """[MS-PSRP] 2.2.5.1.10 - Unsigned Int
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/7b904471-3519-4a6a-900b-8053ad975c08
    """
    PSObject = PSObjectMeta(['System.UInt32', 'System.ValueType', 'System.Object'], tag='U32')

    def __init__(self, *args, **kwargs):
        super(PSUInt, self).__init__()


class PSInt(PSObject, int):
    """[MS-PSRP] 2.2.5.1.11 - Signed Int
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/9eef96ba-1876-427b-9450-75a1b28f5668
    """
    PSObject = PSObjectMeta(['System.Int32', 'System.ValueType', 'System.Object'], tag='I32')

    def __init__(self, *args, **kwargs):
        super(PSInt, self).__init__()


class PSUInt64(PSObject, large_int):
    """[MS-PSRP] 2.2.5.1.12 - Unsigned Long
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d92cd5d2-59c6-4a61-b517-9fc48823cb4d
    """
    PSObject = PSObjectMeta(['System.UInt64', 'System.ValueType', 'System.Object'], tag='U64')

    def __init__(self, *args, **kwargs):
        super(PSUInt64, self).__init__()


class PSInt64(PSObject, large_int):
    """[MS-PSRP] 2.2.5.1.13 - Signed Long
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/de124e86-3f8c-426a-ab75-47fdb4597c62
    """
    PSObject = PSObjectMeta(['System.Int64', 'System.ValueType', 'System.Object'], tag='I64')

    def __init__(self, *args, **kwargs):
        super(PSInt64, self).__init__()


class PSSingle(PSObject, float):
    """[MS-PSRP] 2.2.5.1.14 - Float
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/d8a5a9ab-5f52-4175-96a3-c29afb7b82b8
    """
    PSObject = PSObjectMeta(['System.Single', 'System.ValueType', 'System.Object'], tag='Sg')

    def __init__(self, *args, **kwargs):
        super(PSSingle, self).__init__()


class PSDouble(PSObject, float):
    """[MS-PSRP] 2.2.5.1.15 - Double
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/02fa08c5-139c-4e98-a13e-45784b4eabde
    """
    PSObject = PSObjectMeta(['System.Double', 'System.ValueType', 'System.Object'], tag='Db')

    def __init__(self, *args, **kwargs):
        super(PSDouble, self).__init__()


class PSDecimal(PSObject, decimal.Decimal):
    """[MS-PSRP] 2.2.5.1.16 - Decimal
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/0f760f90-fa46-49bd-8868-001e2c29eb50
    """
    PSObject = PSObjectMeta(['System.Decimal', 'System.ValueType', 'System.Object'], tag='D')

    def __init__(self, *args, **kwargs):
        super(PSDecimal, self).__init__()


class PSByteArray(PSObject, bytes):
    """[MS-PSRP] 2.2.5.1.17 - Array of Bytes
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/489ed886-34d2-4306-a2f5-73843c219b14
    """
    PSObject = PSObjectMeta(['System.Byte[]', 'System.Array', 'System.Object'], tag='BA')

    def __init__(self, *args, **kwargs):
        super(PSByteArray, self).__init__()


class PSGuid(PSObject, uuid.UUID):
    """[MS-PSRP] 2.2.5.1.18 - GUID
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c30c37fa-692d-49c7-bb86-b3179a97e106
    """
    PSObject = PSObjectMeta(['System.Guid', 'System.ValueType', 'System.Object'], tag='G')

    def __setattr__(self, name, value):
        # UUID raises TypeError on __setattr__ and there are cases where we need to override the psobject attribute.
        if name == 'psobject':
            self.__dict__['psobject'] = value
            return

        super(PSGuid, self).__setattr__(name, value)


class PSUri(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.19 - URI
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/4ac73ac2-5cf7-4669-b4de-c8ba19a13186
    """
    PSObject = PSObjectMeta(['System.Uri', 'System.Object'], tag='URI')

    def __init__(self, *args, **kwargs):
        super(PSUri, self).__init__()


PSNull = None
"""[MS-PSRP] 2.2.5.1.20 - Null Value
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/402f2a78-5771-45ae-bf33-59f6e57767ca
XML Element: <Nil>
"""


class PSVersion(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.21 - Version
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/390db910-e035-4f97-80fd-181a008ff6f8
    """
    PSObject = PSObjectMeta(['System.Version', 'System.Object'], tag='Version')

    def __init__(self, *args, **kwargs):
        super(PSVersion, self).__init__()


class PSXml(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.22 - XML Document
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/df5908ab-bb4d-45e4-8adc-7258e5a9f537
    """
    PSObject = PSObjectMeta(['System.Xml.XmlDocument', 'System.Xml.XmlNode', 'System.Object'], tag='XD')

    def __init__(self, *args, **kwargs):
        super(PSXml, self).__init__()


class PSScriptBlock(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.23 - ScriptBlock
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/306af1be-6be5-4074-acc9-e29bd32f3206
    """
    PSObject = PSObjectMeta(['System.Management.Automation.ScriptBlock', 'System.Object'], tag='SBK')

    def __init__(self, *args, **kwargs):
        super(PSScriptBlock, self).__init__()


class PSSecureString(PSObject, six.text_type):
    """[MS-PSRP] 2.2.5.1.24 - Secure String
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/69b9dc01-a843-4f91-89f8-0205f021a7dd

    Note: A SecureString is not actually encrypted in memory on the Python host but just a way to mark a string to
    encrypt as a SecureString across the wire.
    """
    PSObject = PSObjectMeta(['System.Security.SecureString', 'System.Object'], tag='SS')

    def __init__(self, *args, **kwargs):
        super(PSSecureString, self).__init__()


class PSStack(PSObject, list):
    """[MS-PSRP] 2.2.5.2.6.1 - Stack
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/e9cf648e-38fe-42ba-9ca3-d89a9e0a856a
    """
    PSObject = PSObjectMeta(['System.Collections.Stack', 'System.Object'], tag='STK')

    def __getitem__(self, item):
        try:
            return list.__getitem__(self, item)
        except TypeError:
            return super(PSStack, self).__getitem__(item)

    def __setitem__(self, key, value):
        if isinstance(key, six.string_types):
            return super(PSStack, self).__setitem__(key, value)
        else:
            return list.__setitem__(self, key, value)


class PSQueue(PSObject, Queue):
    """[MS-PSRP] 2.2.5.2.6.2 - Queue
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/ade9f023-ac30-4b7e-be17-900c02a6f837
    """
    PSObject = PSObjectMeta(['System.Collections.Queue', 'System.Object'], tag='QUE')

    def __getitem__(self, item):
        try:
            return Queue.__getitem__(self, item)
        except TypeError:
            return super(PSQueue, self).__getitem__(item)

    def __setitem__(self, key, value):
        if isinstance(key, six.string_types):
            return super(PSQueue, self).__setitem__(key, value)
        else:
            return Queue.__setitem__(self, key, value)


class PSList(PSObject, list):
    """[MS-PSRP] 2.2.5.2.6.3 - List
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/f4bdb166-cefc-4d49-848c-7d08680ae0a7
    """
    # Would prefer an Generic.List<T> but regardless of the type a list is always deserialized by PowerShell as an
    # ArrayList so just do that here.
    PSObject = PSObjectMeta(['System.Collections.ArrayList', 'System.Object'], tag='LST')

    def __getitem__(self, item):
        try:
            return list.__getitem__(self, item)
        except TypeError:
            return super(PSList, self).__getitem__(item)

    def __setitem__(self, key, value):
        if isinstance(key, six.string_types):
            return super(PSList, self).__setitem__(key, value)
        else:
            return list.__setitem__(self, key, value)


class PSDict(PSObject, dict):
    """[MS-PSRP] 2.2.5.2.6.4 - Dictionaries
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c4e000a2-21d8-46c0-a71b-0051365d8273
    """
    PSObject = PSObjectMeta(['System.Collections.Hashtable', 'System.Object'], tag='DCT')

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            return super(PSDict, self).__getitem__(item)

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)


class PSCredential(PSObject):

    PSObject = PSObjectMeta(
        type_names=['System.Management.Automation.PSCredential', 'System.Object'],
        adapted_properties=[
            PSPropertyInfo('UserName', ps_type=PSString),
            PSPropertyInfo('Password', ps_type=PSSecureString),
        ],
        rehydrate=True,
    )

    def __init__(self, UserName=None, Password=None):
        self.UserName = UserName
        self.Password = Password
