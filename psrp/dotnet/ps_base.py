# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Defines the base objects used to manage the various PSObject.

This file contains the base classes and the various metadata/glue that is used to represent a PSObject as a PowerShell
class. It also contains some of the more fundamental base types like PSIntegerBase/PSGenericBase/PSEnumBase/PSFlagBase
that are inherited by multiple primitive and complex objects for unifying common code.

Also define some helper functions to replicate functionality in PowerShell/.NET like `-is`, `Add-Member` and so on.
"""

import abc
import inspect
import queue
import types
import typing


class _UnsetValue(object):
    """ Used to mark a property with an unset value. """
    def __new__(cls, *args, **kwargs):
        return cls  # pragma: no cover


class _Singleton(type):
    """ Singleton used by TypeRegistry to ensure only 1 registry exists. """
    __instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls.__instances:
            cls.__instances[cls] = super().__call__(*args, **kwargs)

        return cls.__instances[cls]


class TypeRegistry(metaclass=_Singleton):
    """Registry of all the Python classes that implement PSObject.

    This singleton is used to store all the classes that implement PSObject and the .NET type it implements. This is
    used for deserialization to provide a dynamic list of Python classes that can be dehydrated.
    """

    def __init__(self):
        self.registry: typing.Dict[str, _PSMetaType] = {}
        self.psrp_registry: typing.Dict[int, _PSMetaTypePSRP] = {}

    def register(
            self,
            type_name: str,
            cls: '_PSMetaType',
    ):
        """ Register a type that can be used for rehydration. """
        if type_name not in self.registry:
            self.registry[type_name] = cls

    def register_psrp_message(
            self,
            message_type: int,
            cls: '_PSMetaTypePSRP',
    ):
        """ Register a PSRP message type. """
        if message_type not in self.psrp_registry:
            self.psrp_registry[message_type] = cls

    def rehydrate(
            self,
            type_names: typing.List[str],
    ) -> 'PSObject':
        """ Rehydrate a blank instance based on the type names. """

        type_name = type_names[0] if type_names else None
        if type_name and type_name in self.registry:
            # Cannot call __init__ as it may be validating input arguments which the serializer does not specify when
            # rehydrating that type.
            cls = self.registry[type_name]
            obj = cls.__new__(cls)

        else:
            # The type is not registered, return a PSObject with the type names set to 'Deserialized.<TN>'.
            obj = PSObject()
            obj.PSObject.type_names = [f'Deserialized.{tn}' for tn in type_names]

        return obj


class PSObjectMeta:
    """The PowerShell PSObject metadata.

    This describes the metadata around the PSObject such as the properties and ETS info. This information is used by
    Python to (de)serialize the Python class to a .NET type through CLIXML. This should be assigned as the `PSObject`
    class attribute for any time that inherits from `PSObject`.

    Using `rehydrate=True` (default) will register the type_name of the class so the deserializer will return an
    instance of that class when it comes to deserializing that type. A rehydrated object is created without calling
    __init__() so any validation or set up that occurs in that function when normally creating the class instance will
    not occur during deserialization and only the properties in CLIXML will be set on the class instance. When
    `rehydrate=False` then the deserialized object will be an instance of `class:PSObject` with the type names
    containing the `Deserialized.` prefix.

    Setting `tag` should only be set by the builtin types to pypsrp.

    Args:
        type_names: List of .NET type names that the type implements, this should contains at least 1 type.
        adapted_properties: List of adapted properties, these are native to the .NET type.
        extended_properties: List of extended properties, these are added to the .NET type by PowerShell.
        rehydrate: Whether the type should be registered as rehydratable or not.
        tag: The CLIXML element tag, this is designed for internal use.

    Attributes:
        type_names (List[str]): See args.
        adapted_properties (List[PSPropertyInfo]): See args.
        extended_properties (List[PSPropertyInfo]): See args.
        rehydrate (bool): See args.
        tag (str): See args (Internal use only).
    """

    def __init__(
            self,
            type_names: typing.List[str],
            adapted_properties: typing.Optional[typing.List['PSPropertyInfo']] = None,
            extended_properties: typing.Optional[typing.List['PSPropertyInfo']] = None,
            rehydrate: bool = True,
            tag: str = 'Obj',
    ):
        self.type_names = type_names
        self.adapted_properties = adapted_properties or []
        self.extended_properties = extended_properties or []
        self.rehydrate = rehydrate
        self.tag = tag

        self._to_string: typing.Optional[str] = None
        self._instance: typing.Optional[PSObject] = None

    @property
    def to_string(self) -> typing.Optional[str]:
        """The string representation of the object.

        The value to use for the `<ToString>` element of the serialized object. Will favour an explicit `to_string`
        value if set otherwise it will fall back to the value of `str(instance)` that the meta is for.
        """
        if self._instance is None or self._to_string is not None:
            return self._to_string

        # If the instance class of this object has an explicit __str__ method defined we use that as the to_string
        # value. We only want to check up to the PSObject() parent class in the mro because that falls back to this
        # property.
        for cls in type(self._instance).__mro__:
            if cls == PSObject:
                break

            if '__str__' in cls.__dict__:
                return str(self._instance)

    @to_string.setter
    def to_string(
            self,
            value: str,
    ):
        """ Explicitly set the `to_string` value. """
        self._to_string = value

    def set_instance(
            self,
            instance: 'PSObject',
    ):
        """ Creates a copy of the existing meta and assign to the class instance. """
        meta_kwargs = self._copy_kwargs()
        # TODO: Copy base class kwargs

        copy = type(self)(**meta_kwargs)
        copy._instance = instance  # Assign a reference to the instance the PSObject is for.
        instance.PSObject = copy
        a = ''

    def _copy_kwargs(self) -> typing.Dict[str, typing.Any]:
        """ Generate the kwargs used for copying the instance. """
        kwargs = {
            'adapted_properties': [],
            'extended_properties': [],
        }
        for prop_name, prop_value in kwargs.items():
            for prop in getattr(self, prop_name):
                prop_value.append(prop.copy())

        kwargs['type_names'] = list(self.type_names)
        kwargs['rehydrate'] = self.rehydrate
        kwargs['tag'] = self.tag

        return kwargs


class PSObjectMetaEnum(PSObjectMeta):
    """The PowerShell PSObject metadata for an enum type.

     This is the meta object to be used for any PSObject enum types that derive from `PSEnumBase`. This contains the
     same information as `PSObjectMeta` plus specific extras only used for enums.

     Attributes:
         enum_map (List[Tuple[int, str]]): A list of enum values and their label.
     """

    def __init__(
            self,
            *args,
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.enum_map = []


class PSObjectMetaGeneric(PSObjectMeta):
    """The PowerShell PSObject metadata for a generic type.

    This is the meta object to be used for any PSObject generic types that derive from `PSGenericBase`. It contains the
    same information as `PSObjectMeta` plus extra information used for building a generic type. A generic type cannot
    have `rehydrate=True`.

    Args:
        type_names: List of .NET type names that the type implements, this should contains at least 1 type.
        required_types: The number of generic types that must be specified when creating the object.

    Attributes:
        required_types (int): See args.
        generic_types (Tuple[_PSMetaType, ...]): A tuple of the generic types used when the instance class was created.
    """

    def __init__(
            self,
            type_names: typing.List[str],
            required_types: int,
            *args,
            **kwargs
    ):
        super().__init__(type_names, rehydrate=False, *args, **kwargs)
        self.required_types = required_types
        self.generic_types = ()

    def set_instance(
            self,
            instance: 'PSObject',
    ):
        super().set_instance(instance)
        instance.PSObject.generic_types = self.generic_types

    def _copy_kwargs(self) -> typing.Dict[str, typing.Any]:
        kwargs = super()._copy_kwargs()
        kwargs.pop('rehydrate')
        kwargs['required_types'] = self.required_types
        return kwargs


class PSObjectMetaPSRP(PSObjectMeta):
    """The PowerShell PSObject metadata for a PSRP message type.

    This is the meta object to be used for any PSObject types that are used as a PSRP message. It contains the same
    information as `PSObjectMeta` plus the message type identifier used internally.

    Args:
        psrp_message_type: The PSRP message type identifier

    Attributes:
        psrp_message_type (int): See args.
    """

    def __init__(
            self,
            psrp_message_type: int,
            *args,
            **kwargs
    ):
        type_names = []
        if 'type_names' in kwargs:
            type_names = kwargs.pop('type_names')

        super().__init__(type_names=type_names, *args, **kwargs)
        self.psrp_message_type = psrp_message_type

    def _copy_kwargs(self) -> typing.Dict[str, typing.Any]:
        kwargs = super()._copy_kwargs()
        kwargs['psrp_message_type'] = self.psrp_message_type
        return kwargs


class PSPropertyInfo(metaclass=abc.ABCMeta):
    """Base Property metadata for an object's properties.

    This is an abstract class that defines most of the behaviour when it comes to getting and setting a property. The
    three types of properties that are implemented are:

        PSAliasProperty:
            A property that points to another property, or Python attribute. This essentially creates a getter that
            calls ps_object['alias'].

        PSNoteProperty:
            A property that contains it's own value like a normal attribute/property in Python.

        PSScriptProperty:
            A property that uses a callable to get and optionally set a value from the ps_object.

    The `optional` kwarg controls the behaviour when serializing the object to CLIXML. If `True` and the property value
    is `None` then the element will be omitted from the CLIXML.

    The `mandatory` kwarg controls whether the default `__init__()` function added to PSObjects without their own
    `__init__()` will validate that property was specified by the caller. This has no control over the serialization
    behaviour and any classes that define their own `__init__()` need to do their own validation.

    Args:
        name: The name of the property.
        optional: The property will be omitted in the CLIXML output when serializing the object and the value is None.
        mandatory: The property must be defined when creating a PSObject.
        ps_type: If set, the property value will be casted to this PSObject type.
        value: The default value to set for the property.
        getter: A callable to get the property value based on the caller's desired logic. Must not be set with `value`.
        setter: A callable to set the property value based on the caller's desired logic. Must not be set with `value`.

    Attributes:
        name (str): See args.
        ps_type (type): See args.
        optional (bool): See args.
        mandatory (bool): See args.
    """

    def __init__(
            self,
            name: str,
            optional: bool = False,
            mandatory: bool = False,
            ps_type: typing.Optional[type] = None,
            value: typing.Optional[typing.Any] = _UnsetValue,
            getter: typing.Optional[typing.Callable[['PSObject'], typing.Any]] = None,
            setter: typing.Optional[typing.Callable[['PSObject', typing.Any], None]] = None,
    ):
        self.name = name
        self.ps_type = ps_type
        self.optional = optional
        self.mandatory = mandatory

        self._value = _UnsetValue

        self._getter = None
        if getter:
            self.getter = getter

        self._setter = None
        if setter:
            self.setter = setter

        if value != _UnsetValue:
            if getter:
                raise ValueError(f"Cannot set property value for '{self.name}' with a getter")

            # The PSObject is required when setting a value for a custom setter. Because we do not set a value if there
            # is a getter/setter present then this can be None without causing any issues.
            self.set_value(value, None)

    @abc.abstractmethod
    def copy(self) -> 'PSPropertyInfo':
        """ Create a copy of the property. """
        pass  # pragma: no cover

    @property
    def getter(self) -> typing.Optional[typing.Callable[['PSObject'], typing.Any]]:
        """ Returns the getter callable for the property if one was set. """
        return self._getter

    @getter.setter
    def getter(
            self,
            getter: typing.Callable[['PSObject'], None],
    ):
        if self._value != _UnsetValue:
            raise ValueError(f"Cannot add getter for '{self.name}': existing value already set")

        if getter is None:
            raise ValueError(f"Cannot unset property getter for '{self.name}'")

        self._validate_callable(getter, 1, 'getter')
        self._getter = getter

    @property
    def setter(self) -> typing.Optional[typing.Callable[['PSObject', typing.Any], None]]:
        """ Returns the setter callable for the property if one was set. """
        return self._setter

    @setter.setter
    def setter(
            self,
            setter: typing.Optional[typing.Callable[['PSObject', typing.Any], None]],
    ):
        if self.getter is None:
            raise ValueError(f"Cannot set property setter for '{self.name}' without an existing getter")

        elif setter is None:
            self._setter = None

        else:
            self._validate_callable(setter, 2, 'setter')
            self._setter = setter

    def get_value(
            self,
            ps_object: 'PSObject',
    ) -> typing.Any:
        """Get the property value.

        Gets the value of the property. If the property value is a callable then the value is invoked with the
        ps_object as an argument and the resulting value is casted to the `ps_type` if it is set.

        Args:
            ps_object: The PSObject instance the property is on. This is used when invoking a getter callable.

        Returns:
            (typing.Any): The value of the property.
        """
        getter = self.getter

        if getter:
            raw_value = getter(ps_object)
            value = self._cast(raw_value)

        else:
            value = self._value

        if value == _UnsetValue:
            value = None

        return value

    def set_value(
            self,
            value: typing.Any,
            ps_object: typing.Optional['PSObject'],
    ):
        """Set the property value.

        Sets the value of the property to the value specified. The value will be casted to the property's `ps_type` if
        defined unless it is a callable or `None`. Trying to set `None` on a `mandatory` property will also fail.

        Args:
            value: The value to set on the property.
            ps_object: The PSObject instance the property is on. This is used when invoking the setter callable.
        """
        setter = self.setter
        if setter:
            setter(ps_object, value)

        elif self.getter:
            raise ValueError(f"Cannot set value for a getter property '{self.name}' without a setter callable")

        else:
            self._value = self._cast(value)

    def _cast(self, value):
        """ Try to cast the raw value to the property's ps_type if possible. """
        if (
            value is not None and
            self.ps_type is not None and
            not isinstance(value, self.ps_type)
        ):
            return self.ps_type(value)

        else:
            return value

    def _validate_callable(
            self,
            func: typing.Callable,
            expected_count: int,
            use: str,
    ):
        """ Validates the callable has the required argument count for use as a property getter/setter. """
        if not isinstance(func, types.FunctionType):
            raise TypeError(f"Invalid {use} callable for property '{self.name}': expecting callable not "
                            f"{type(func).__qualname__}")

        parameters = list(inspect.signature(func).parameters.values())
        required_count = 0
        total_count = 0

        for param in parameters:
            if param.kind in [inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD]:
                # func(arg1, .., /) or func(arg1, ...) - keep track of how many and if they must be set.
                total_count += 1
                if param.default == inspect.Parameter.empty:
                    required_count += 1

            elif param.kind == inspect.Parameter.VAR_POSITIONAL:
                # Once we've reached *args we've counted all the positional args that could be used. It also means the
                # callable accepts an arbitrary amount of args so our expected count will be met.
                total_count = expected_count
                break

        def plural(name, count):
            s = '' if count == 1 else 's'
            return f'{count} {name}{s}'

        base_err = f"Invalid {use} callable for property '{self.name}': signature expected " \
                   f"{plural('parameter', expected_count)} but"
        if required_count > expected_count:
            raise TypeError(f"{base_err} {plural('required parameter', required_count)} were found")

        elif total_count < expected_count:
            raise TypeError(f"{base_err} {plural('parameter', total_count)} were found")


class PSAliasProperty(PSPropertyInfo):
    """Alias Property

    This is a property that gets a value based on another property or attribute of the PSObject. It is designed to
    replicate the functionality of `PSAliasProperty`_. During serialization the alias property will just copy the
    target it is point to. You cannot set a value to an alias property, see `PSScriptProperty` which allows the caller
    to define a way to get and set properties on an object dynamically.

    ..Note:
        When an object that has an alias property is deserialized, the property is converted to a `PSNoteProperty` and
        the alias will no longer exists.

    Args:
        name: The name of the property.
        alias: The name of the property or attribute to point to.
        optional: The property will be omitted in the CLIXML output when serializing the object and the value is None.
        ps_type: If set, the property value will be casted to this PSObject type.

    Attributes:
        alias (str): The target of the alias.

    .. _PSAliasProperty:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.psaliasproperty
    """

    def __init__(
            self,
            name: str,
            alias: str,
            optional: bool = False,
            ps_type: typing.Optional[type] = None,

    ):
        self.alias = alias
        super().__init__(name, optional=optional, ps_type=ps_type, getter=lambda s: s[alias])

    def copy(self) -> 'PSAliasProperty':
        return PSAliasProperty(self.name, self.alias, self.optional, self.ps_type)


class PSNoteProperty(PSPropertyInfo):
    """Note Property

    This is a property that stores a value as a name-value pair. Is is designed to replicate the functionality of
    `PSNoteProperty`_ and is typically the type of property to use when creating a PSObject.

    ..Note:
        See PSPropertyInfo for more information on the `mandatory` argument.

    Args:
        name: The name of the property.
        value: The property value to set, if omitted the default is `None`.
        optional: The property will be omitted in the CLIXML output when serializing the object and the value is None.
        mandatory: The property must be defined when creating a PSObject.
        ps_type: If set, the property value will be casted to this PSObject type.

    .. _PSNoteProperty:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.psnoteproperty
    """

    def __init__(
            self,
            name: str,
            value: typing.Optional[typing.Any] = _UnsetValue,
            optional: bool = False,
            mandatory: bool = False,
            ps_type: typing.Optional[type] = None,
    ):
        super().__init__(name, optional=optional, mandatory=mandatory, ps_type=ps_type, value=value)

    def copy(self) -> 'PSNoteProperty':
        return PSNoteProperty(self.name, self._value, self.optional, self.mandatory, self.ps_type)


class PSScriptProperty(PSPropertyInfo):
    """Script Property

    This is a property that can get and optionally set another property or attribute of a PSObject at runtime. It is
    designed to replicate the functionality of `PSScriptProperty`_.

    The getter callable must be a callable that has only 1 argument that is the PSObject the property is a member of.
    This allows the caller to retrieve a property of the PSObject at runtime or any other source as needed.

    The setter callable must be a callable that has only 2 arguments, the first being the value that needs to be set
    and the second is the PSObject the property is a member of. A setter must be defined on the property for a value to
    be set.

    Args:
        name: The name of the property.
        getter: The callable to run when getting a value for this property.
        setter: The callable to run when setting a value for this property.
        optional: The property will be omitted in the CLIXML output when serializing the object and the value is None.
        mandatory: The property must be defined when creating a PSObject.
        ps_type: If set, the property value will be casted to this PSObject type.

    .. _PSScriptProperty:
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.psscriptproperty
    """

    def __init__(
            self,
            name: str,
            getter: typing.Callable[['PSObject'], typing.Any],
            setter: typing.Optional[typing.Callable[['PSObject', typing.Any], None]] = None,
            optional: bool = False,
            mandatory: bool = False,
            ps_type: typing.Optional[type] = None,
    ):
        if getter is None:
            raise TypeError(f"Cannot create script property '{name}' with getter as None")

        if mandatory and not setter:
            raise TypeError(f"Cannot create mandatory {self.__class__.__qualname__} property '{name}' without a "
                            f"setter callable")

        super().__init__(name, optional=optional, mandatory=mandatory, ps_type=ps_type, getter=getter, setter=setter)

    def copy(self) -> 'PSScriptProperty':
        return PSScriptProperty(self.name, self.getter, self.setter, self.optional, self.mandatory, self.ps_type)


class _PSMetaType(type):
    """The meta type for all PowerShell objects.

    This is the meta type that all PowerShell objects are based on. This type has 3 main functions that is done when
    a class that is based on this type is created:

        1. The class has a PSObject class attribute, if not already set it is the PSObjectMeta with no types or props.
        2. Registers the .NET type in the `:class:TypeRegistry` if has `rehydrate=True` in the PSObject metadata.
        3. Adds an `__init__` function to validate and set all the registered properties in the PSObject metadata.

    The `TypeRegistry` is used by the deserializer so that it can recreate the registered Python object for that type
    instead of a generic PSObject.

    The `__init__` function is only added to the class when `__init__` has not already been defined on that class or
    any of its parents.

    This class is used internally and is not designed for public consumption. You should inherit from the existing
    base classes that have already set this as their metaclass.
    """
    __registry = TypeRegistry()

    def __init__(
            cls,
            name,
            bases,
            attributes,
            meta_type: type = PSObjectMeta,
    ):
        super().__init__(name, bases, attributes)

        # Make sure the cls as a valid PSObject set.
        if not hasattr(cls, 'PSObject'):
            setattr(cls, 'PSObject', PSObjectMeta([]))

        if not isinstance(cls.PSObject, meta_type):
            raise TypeError(f"Invalid PSObject type '{type(cls.PSObject).__qualname__}' for '{cls.__qualname__}', "
                            f"must be '{meta_type.__name__}'")

        # Register the type for rehydration if it is set to and contains at least 1 type name.
        if cls.PSObject.rehydrate and cls.PSObject.type_names:
            cls.__registry.register(cls.PSObject.type_names[0], cls)

        # We don't want to inherit the types and properties for PSObject and anything deriving from PSGenericBase.
        if not (
                (cls.__module__ == _PSMetaType.__module__ and cls.__qualname__ == 'PSObject') or
                issubclass(cls, globals().get('PSGenericBase', ()))
        ):
            base_cls = cls.__mro__[1]
            cls.PSObject.type_names.extend(base_cls.PSObject.type_names)
            cls.PSObject.adapted_properties.extend(base_cls.PSObject.adapted_properties)
            cls.PSObject.extended_properties.extend(base_cls.PSObject.extended_properties)

            # If the class has the default tag, always inherit the base class tag
            if cls.PSObject.tag == 'Obj':
                cls.PSObject.tag = base_cls.PSObject.tag
                
    def __call__(cls, *args, **kwargs):
        # Skip creating a new object if we are trying to cast to the same type again.
        if len(args) == 1 and type(args[0]) == cls:
            return args[0]
        
        return super().__call__(*args, **kwargs)


class _PSMetaTypeEnum(_PSMetaType):
    """The meta type for all PowerShell enum objects.

    This is the meta type that extends `:class:_PSMetaType` to support enum objects. In addition to the work that
    `_PSMetaType` adds to the class, this also does the following:

        1. Validates the enum class also inherits from `:class:PSIntegerBase`.
        2. Casts the class attributes to an instance of that class like a Python enum.
        3. Creates a map of the enum names and values and assigns it to the PSObject metadata.

    This class is used internally and is not designed for public consumption. You should inherit from the existing
    base classes that have already set this as their metaclass.
    """

    def __init__(
            cls,
            name,
            bases,
            attributes,
    ):
        super().__init__(name, bases, attributes, meta_type=PSObjectMetaEnum)

        # No need for the further validation for the base enum classes.
        if cls.__module__ == _PSMetaType.__module__ and cls.__qualname__ in ['PSEnumBase', 'PSFlagBase']:
            return

        if not issubclass(cls, PSIntegerBase):
            raise TypeError(f"Enum type {cls.__qualname__} must also inherit a "
                            f"{PSIntegerBase.__qualname__} type")

        # Convert the class attributes representing the enum values to an instance of that class.
        ps_object = cls.PSObject
        for k, v in attributes.items():
            if k.startswith('__') or k == 'PSObject':
                continue

            enum_val = cls(v)
            setattr(cls, k, enum_val)

            # Make sure the class' PSObject has the enum map. Special edge case for none -> None as None is a
            # reserved keyword in Python but the string should still show the capitalised version.
            if k == 'none':
                k = 'None'
            ps_object.enum_map.append((v, k))


class _PSMetaTypeGeneric(_PSMetaType):
    """The meta type for all PowerShell generic objects.

    This is the meta type that extends `:class:_PSMetaType` to support generic objects. In addition to the work that
    `_PSMetaType` adds to the class, this adds the `__getitem__` function to each class that generates the actual
    generic class implementation.

    This class is used internally and is not designed for public consumption. You should inherit from the existing
    base classes that have already set this as their metaclass.
    """

    def __init__(
            cls,
            name,
            bases,
            attributes,
    ):
        super().__init__(name, bases, attributes, meta_type=PSObjectMetaGeneric)

    def __getitem__(
            cls,
            item: typing.Union[_PSMetaType, typing.Tuple[_PSMetaType, ...]],
    ) -> _PSMetaType:
        """ Return a dynamic class instance using the type(s) specified as the item. """
        if isinstance(item, _PSMetaType):
            item = (item,)

        elif not isinstance(item, tuple):
            raise TypeError(f'Type list to {cls.__name__}[...] must be 1 or more PSObject types')

        required_types = cls.PSObject.required_types
        if len(item) != required_types:
            plural = '' if required_types == 1 else 's'
            raise TypeError(f'Type list to {cls.__name__}[...] must contain {required_types} PSObject '
                            f'type{plural}')

        def _get_generic_type(
                ps_type: _PSMetaType,
        ) -> str:
            """ Calculate the type to use for a generic type. """
            if ps_type.PSObject.type_names:
                value = ps_type.PSObject.type_names[0]

            # If there are no explicit types, use PSObject if there are extended properties, otherwise Object.
            elif ps_type.PSObject.extended_properties:
                value = 'System.Management.Automation.PSObject'

            else:
                value = 'System.Object'

            return value

        type_names = '],['.join([_get_generic_type(t) for t in item])
        type_names = [f'{_get_generic_type(cls)}`{required_types}[[{type_names}]]']
        if len(cls.PSObject.type_names) > 1:
            type_names.extend(cls.PSObject.type_names[1:])

        ps_object = PSObjectMetaGeneric(
            required_types=required_types,
            type_names=type_names,
            adapted_properties=cls.PSObject.adapted_properties,
            extended_properties=cls.PSObject.extended_properties,
            tag=cls.PSObject.tag,
        )
        ps_object.generic_types = item

        ps_type_names = '_'.join(t.__name__ for t in item)
        base_classes = list(cls.__bases__)
        base_classes.insert(0, cls)
        return _PSMetaType(
            f'{cls.__name__}_{ps_type_names}',
            tuple(base_classes),
            {
                'PSObject': ps_object,
            },
        )


class _PSMetaTypePSRP(_PSMetaType):
    """The meta type for all PowerShell PSRP message objects.

    This is the meta type that extends `:class:_PSMetaType` to support PSRP message objects. In addition to the work
    that `_PSMetaType` adds to the class, this also registers the PSRP message type identifier in the type registry.

    This class is used internally and is not designed for public consumption. You should inherit from the existing
    base classes that have already set this as their metaclass.
    """

    def __init__(
            cls,
            name,
            bases,
            attributes,
    ):
        super().__init__(name, bases, attributes, meta_type=PSObjectMetaPSRP)
        TypeRegistry().register_psrp_message(cls.PSObject.psrp_message_type, cls)


class PSObject(metaclass=_PSMetaType):
    """The base PSObject type.

    This is the base PSObject type that all PS object classes must inherit. It controls all the behaviour around
    getting and setting attributes that are based on PowerShell properties in a way that is similar to PowerShell
    itself.

    This object can also be used as a blank PSObject which the caller can build up dynamically with their own
    properties at runtime.
    """

    def __new__(cls, *args, **kwargs):
        if super().__new__ is object.__new__ and cls.__init__ is not object.__init__:
            obj = super().__new__(cls)
        else:
            obj = super().__new__(cls, *args, **kwargs)

        # Make sure the class instance has a copy of the class PSObject so they aren't shared. Also add a reference to
        # the instance for that PSObject.
        cls.PSObject.set_instance(obj)

        return obj

    def __init__(self, *args, **kwargs):
        # Favour extended properties in case there is one with the same name. This is how PowerShell's ETS works.
        prop_entries = {p.name: p for p in self.PSObject.adapted_properties}
        prop_entries.update({p.name: p for p in self.PSObject.extended_properties})

        # Make sure the number of positional args specified do not exceed the number of kwargs present.
        if len(args) > len(prop_entries):
            raise TypeError(f"__init__() takes {len(prop_entries) + 1} positional arguments but {len(args) + 1} "
                            f"were given")

        # Convert the args to kwargs based on the property order and check that they aren't also defined as a kwarg.
        caller_args = dict(zip(prop_entries.keys(), args))
        for name in caller_args.keys():
            if name in kwargs:
                raise TypeError(f"__init__() got multiple values for argument '{name}'")
        caller_args.update(kwargs)

        # Validate that any mandatory props were specified.
        # Cannot use set as it breaks the ordering which we want to preserve for the error msg.
        mandatory_props = [p.name for p in prop_entries.values() if p.mandatory]
        specified_props = list(caller_args.keys())
        missing_props = [p for p in mandatory_props if p not in specified_props]
        if missing_props:
            missing_list = "', '".join(missing_props)
            raise TypeError(f"__init__() missing {len(missing_props)} required arguments: '{missing_list}'")

        # Check that all the kwargs match the existing properties of the object and set the properties.
        for prop_name, raw_value in caller_args.items():
            if prop_name not in prop_entries:
                raise TypeError(f"__init__() got an unexpected keyword argument '{prop_name}'")

            setattr(self, prop_name, raw_value)

    @property
    def PSBase(self):
        """ The raw .NET object without the extended type system properties. """
        raise NotImplementedError()  # pragma: no cover

    @property
    def PSAdapted(self):
        """ A dict of all the adapted properties. """
        raise NotImplementedError()  # pragma: no cover

    @property
    def PSExtended(self):
        """ A dict of all the extended properties."""
        raise NotImplementedError()  # pragma: no cover

    @property
    def PSTypeNames(self) -> typing.List[str]:
        """ Shortcut to PSObject.type_names, one of PowerShell's reserved properties. """
        return self.PSObject.type_names

    def __setattr__(self, key, value):
        # __getattribute__ uses PSObject so bypass all that and just set it directly.
        if key == 'PSObject':
            return super().__setattr__(key, value)

        # Get the raw untainted __dict__ value which does not include our object's PS properties that self.__dict__
        # will return. We use this to see whether we need to set the PSObject property or the Python object attribute.
        d = super().__getattribute__('__dict__')

        if key not in d:
            ps_object = self.PSObject

            # Extended props take priority, once we find a match we stopped checking.
            for prop_type in ['extended', 'adapted']:
                properties = getattr(ps_object, f'{prop_type}_properties')
                for prop in properties:
                    if prop.name == key:
                        prop.set_value(value, self)
                        return

        # If the key already exists in the __dict__ or it's a new attribute that's not a registered property, just
        # set the key/value to the object itself.
        super().__setattr__(key, value)

    def __getattribute__(self, item):
        # Use __getattribute__ instead of self.PSObject to avoid a recursive call.
        ps_object = super().__getattribute__('PSObject')

        # Extended props take priority over adapted props, by checking that last we ensure the prop will have that
        # value if there are duplicates.
        ps_properties = {}
        for prop_type in ['adapted', 'extended']:
            properties = getattr(ps_object, f'{prop_type}_properties')
            for prop in properties:
                ps_properties[prop.name] = prop

        # We want to favour the normal attributes Python would return before falling back to the properties on the
        # PSObject.
        try:
            val = super().__getattribute__(item)
        except AttributeError:
            if item not in ps_properties:
                raise

            return ps_properties[item].get_value(self)

        # A special case exists when returning __dict__. We want to have __dict__ return both the Python attributes as
        # well as the PSObject properties. This allows debuggers and people calling functions like vars()/dirs() to see
        # the PSObject properties automatically.
        if item == '__dict__':
            val = val.copy()  # Make sure we don't actually mutate the pure __dict__.
            val.update({name: prop.get_value(self) for name, prop in ps_properties.items()})

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
            return self.PSObject.to_string

        else:
            return super().__str__()


class PSIntegerBase(PSObject, int):
    """Base class for integer based primitive types.

    This is the base class to use for primitive integer types. It defines common functions required to seamlessly use
    numerical operators like `|`, `<`, `&`, etc while preserving the type. It should not be initialised directly but is
    inherited by the various primitive integer types.
    """
    MinValue = 0
    MaxValue = 0

    def __new__(cls, *args, **kwargs):
        if cls == PSIntegerBase:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'integer types.')

        if args and args[0] is None:
            # In .NET integer cannot be null and PowerShell casts it to 0.
            num = 0
        else:
            num = super().__new__(cls, *args, **kwargs)

        if cls != type(num):
            # If the value is not the exact instance recreate it from an actual int.
            return super().__new__(cls, int(num))

        if num < cls.MinValue or num > cls.MaxValue:
            raise ValueError(f"Cannot create {cls.__qualname__} with value '{num}': Value must be between "
                             f"{cls.MinValue} and {cls.MaxValue}.")

        return num

    def __init__(self, x, base=10, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __abs__(self):
        return type(self)(super().__abs__())

    def __add__(self, *args, **kwargs):
        return type(self)(super().__add__(*args, **kwargs))

    def __and__(self, *args, **kwargs):
        return type(self)(super().__and__(*args, **kwargs))

    def __divmod__(self, *args, **kwargs):
        quotient, remainder = super().__divmod__(*args, **kwargs)
        return type(self)(quotient), remainder

    def __floordiv__(self, *args, **kwargs):
        return type(self)(super().__floordiv__(*args, **kwargs))

    def __invert__(self):
        return type(self)(super().__invert__())

    def __lshift__(self, *args, **kwargs):
        return type(self)(super().__lshift__(*args, **kwargs))

    def __mod__(self, *args, **kwargs):
        return type(self)(super().__mod__(*args, **kwargs))

    def __mul__(self, *args, **kwargs):
        return type(self)(super().__mul__(*args, **kwargs))

    def __neg__(self):
        return type(self)(super().__neg__())

    def __or__(self, *args, **kwargs):
        return type(self)(super().__or__(*args, **kwargs))

    def __pos__(self):
        return type(self)(super().__pos__())

    def __pow__(self, *args, **kwargs):
        return type(self)(super().__pow__(*args, **kwargs))

    def __rshift__(self, *args, **kwargs):
        return type(self)(super().__rshift__(*args, **kwargs))

    def __sub__(self, *args, **kwargs):
        return type(self)(super().__sub__(*args, **kwargs))

    def __xor__(self, *args, **kwargs):
        return type(self)(super().__xor__(*args, **kwargs))


class PSEnumBase(PSObject, metaclass=_PSMetaTypeEnum):
    """The base enum PSObject type.

    This is the base enum PSObject type that all enum complex objects should inherit from. While we cannot use the
    `enum` module as a PSObject has a different metaclass we can try and replicate some of the functionality here. Any
    objects that inherit `PSEnumBase` should also inherit one of the integer PS types like `PSInt` and any other class
    attributes (apart from PSObject) are treated as enum value. An example enum would look like:

    .. code-block:: python

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
    PSObject = PSObjectMetaEnum(
        type_names=[
            'System.Enum',
            'System.ValueType',
            'System.Object',
        ],
    )

    def __new__(cls, *args, **kwargs):
        if cls in [PSEnumBase, PSFlagBase]:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'enum types.')

        return super().__new__(cls, *args, **kwargs)

    def __str__(self):
        # The enum map is stored in the instance's class PSObject not the instance's PSObject.
        enum_map = dict((k, v) for k, v in self.__class__.PSObject.enum_map)

        return enum_map.get(self, 'Unknown')
    
    def __repr__(self):
        return f'{self.__class__.__qualname__}.{self!s}'


class PSFlagBase(PSEnumBase):
    """The base flags enum PSObject type.

    This is like `PSEnumBase` but supports having multiple values set like `[FlagsAttribute]` in .NET. Using any
    bitwise operations will preserve the type so `MyFlags.Flag1 | MyFlags.Flag2` will still be an instance of
    `MyFlags`.

    Like `PSEnumBase`, an implementing type needs to inherit both `PSFlagBase` as well as one of the integer PS types
    like `PSInt`. An example flag enum would look like:

    .. code-block:: python

        class MyFlags(PSFlagBase, PSInt):
            PSObject = PSObjectMeta(
                type_names=['System.MyFlags', 'System.Enum', 'System.ValueType', 'System.Object'],
                rehydrate=True,
            )

            Flag1 = 1
            Flag2 = 2
            Flag3 = 4
    """
    PSObject = PSObjectMetaEnum([])

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

    def __repr__(self):
        type_name = self.__class__.__qualname__
        flags = str(self).split(', ')
        
        return ' | '.join([f'{type_name}.{f}' for f in flags])


class PSGenericBase(PSObject, metaclass=_PSMetaTypeGeneric):
    """Base class for generic based types.

    This is the base class to use for generic types. It cannot be instantiated directly but it exposes a way to
    dynamically define a generic type based on user input. The PSObject attribute must be a `PSObjectMetaGeneric`
    object that defines both the type names and the number of types that are required when creating the object. Because
    generic types aren't preserved when they are serialized this is mostly used for specific use cases by the various
    PSRP message types.
    """
    PSObject = PSObjectMetaGeneric(type_names=[], required_types=0)

    def __new__(cls, *args, **kwargs):
        if cls.PSObject.required_types == 0 or not cls.PSObject.type_names:
            # Either instantiating PSGenericBase or a class that is inheriting this PSObject.
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'generic types.')

        elif not cls.PSObject.generic_types:
            # Instantiating a generic object directly and not one from 'Obj[type]()'.
            plural = '' if cls.PSObject.required_types == 1 else 's'
            raise TypeError(f'Type {cls.__name__} cannot be instantiated; use {cls.__name__}[...]() to define the '
                            f'{cls.PSObject.required_types} generic type{plural} required.')

        return super().__new__(cls, *args, **kwargs)


class PSDictBase(PSObject, dict):
    """The base dictionary type.

    This is the base dictionary PSObject type that all dictionary like objects should inherit from. It cannot be
    instantiated directly and is meant to be used as a base class for any .NET dictionary types.

    Note:
        While you can implement your own custom dictionary .NET type like
        `System.Collections.Generic.Dictionary<TKey, TValue>`, any dictionary based .NET types will be deserialized by
        the remote PowerShell runspace as `System.Collections.Hashtable`_. This .NET type is represented by
        `:class:psrp.dotnet.complex_types.PSDict`.

    .. _System.Collections.Hashtable:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.hashtable?view=net-5.0
    """
    PSObject = PSObjectMeta([], tag='DCT')

    def __new__(cls, *args, **kwargs):
        if cls == PSDictBase:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'dictionary types.')
        return super().__new__(cls, *args, **kwargs)

    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            return super().__getitem__(item)

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)


class _PSListBase(PSObject, list):
    """ Common list base class for PSListBase and PSStackBase. """

    def __new__(cls, *args, **kwargs):
        if cls in [_PSListBase, PSListBase, PSStackBase]:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'list types.')
        return super().__new__(cls, *args, **kwargs)

    def __init__(self, seq=(), *args, **kwargs):
        super().__init__(*args, **kwargs)
        list.__init__(self, seq)

    def __getitem__(self, item):
        try:
            return list.__getitem__(self, item)
        except TypeError:
            return super().__getitem__(item)

    def __setitem__(self, key, value):
        if isinstance(key, str):
            return super().__setitem__(key, value)
        else:
            return list.__setitem__(self, key, value)


class PSListBase(_PSListBase):
    """The base list type.

    This is the base list PSObject type that all list like objects should inherit from. It cannot be instantiated
    directly and is meant to be used as a base class for any .NET list types.

    Note:
        While you can implement your own custom list .NET type like `System.Collections.Generic.List<T>`, any list
        based .NET types will be deserialized by the remote PowerShell runspace as `System.Collections.ArrayList`_.
        This .NET type is represented by `:class:psrp.dotnet.complex_types.PSList`.

    .. _System.Collections.ArrayList:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.arraylist?view=net-5.0
    """
    # Would prefer an Generic.List<T> but regardless of the type a list is always deserialized by PowerShell as an
    # ArrayList so just do that here.
    PSObject = PSObjectMeta([], tag='LST')


class PSQueueBase(PSObject, queue.Queue):
    """The base queue type.

    This is the base queue PSObject type that all queue like objects should inherit from. It cannot be instantiated
    directly and is meant to be used as a base class for any .NET queue types.

    Note:
        While you can implement your own custom queue .NET type like `System.Collections.Generic.Queue<T>`, any queue
        based .NET types will be deserialized by the remote PowerShell runspace as `System.Collections.Queue`_. This
        .NET type is represented by `:class:psrp.dotnet.complex_types.PSQueue`.

    .. _System.Collections.Queue:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.queue?view=net-5.0
    """
    PSObject = PSObjectMeta([], tag='QUE')

    def __new__(cls, *args, **kwargs):
        if cls == PSQueueBase:
            raise TypeError(f'Type {cls.__qualname__} cannot be instantiated; it can be used only as a base class for '
                            f'queue types.')

        que = super().__new__(cls)

        # Need to make sure __init__ is always called when creating the instance as rehydration will only call __new__
        # and certain props are set in __init__ to make a queue useful.
        queue.Queue.__init__(que, *args, **kwargs)

        return que

    def __init__(self, *args, **kwargs):
        pass  # We cannot call the base __init__() function in ase any properties are set.


class PSStackBase(_PSListBase):
    """The base stack type.

    This is the base stack PSObject type that all stack like objects should inherit from. It cannot be instantiated
    directly and is meant to be used as the base class for any .NET stack types. A stack is a last-in, first out
    collection but Python does not have a native stack type so this just replicates the a Python list.

    Note:
        While you can implement your own custom stack .NET type like `System.Collections.Generic.Stack<T>`, any stack
        based .NET types will be deserialized by the remote PowerShell runspace as `System.Collections.Stack`_. This
        .NET type is represented by `:class:psrp.dotnet.complex_types.PSStack`.

    .. System.Collections.Stack:
        https://docs.microsoft.com/en-us/dotnet/api/system.collections.stack?view=net-5.0
    """
    PSObject = PSObjectMeta([], tag='STK')


def add_member(
        obj: typing.Union[_PSMetaType, PSObject],
        prop: PSPropertyInfo,
        force: bool = False,
):
    """Add an extended property.

    This can add an extended property to a PSObject class or a specific instance of a class. This replicates some of
    the functionality in `Update-TypeData`_ and `Add-Member`_ in PowerShell. If a property under the same name already
    exists under that PSObject then `force=True` is required to replace it. The same applies if there is an existing
    adapted property on the object.

    Args:
        obj: The PSObject class or an instance of a PSObject class to add the extended property to.
        prop: The property to add to the object or class.
        force: Overwrite the existing property (True) or fail (Fail).

    .. _Update-TypeData:
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/update-typedata
    .. _Add-Member:
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-member
    """
    prop_name = prop.name
    adapted_properties = {p.name: i for i, p in enumerate(obj.PSObject.adapted_properties)}
    extended_properties = {p.name: i for i, p in enumerate(obj.PSObject.extended_properties)}

    insert_idx = len(obj.PSObject.extended_properties)
    if prop_name in adapted_properties or prop_name in extended_properties:
        if not force:
            raise RuntimeError(f"Property '{prop_name}' already exists on PSObject, use force=True to overwrite it")

        # If we had a duplicated extended prop, swap the older with the new one, adapted props stays the same.
        if prop_name in extended_properties:
            insert_idx = extended_properties[prop_name]
            obj.PSObject.extended_properties.pop(insert_idx)

    obj.PSObject.extended_properties.insert(insert_idx, prop)


def add_alias_property(
        obj: typing.Union[PSObject, _PSMetaType],
        name: str,
        alias: str,
        ps_type: typing.Optional[type] = None,
        force: bool = False,
):
    """Add an alias property to a PSObject.

    Adds an alias as an extended property to a PSObject class or a specific instance of a class.

    Args:
        obj: The PSObject to add the alias to.
        name: The name of the new alias property.
        alias: The alias target.
        ps_type: Optional PSObject type that the alias value will get casted to.
        force: Overwrite the existing property (True) or fail (Fail).
    """
    add_member(obj, PSAliasProperty(name, alias, ps_type=ps_type), force=force)


def add_note_property(
        obj: typing.Union[PSObject, _PSMetaType],
        name: str,
        value: typing.Any,
        ps_type: typing.Optional[type] = None,
        force: bool = False,
):
    """Add a note property to a PSObject.

    Adds a note property as an extended property to a PSObject class or a specific instance of a class. A note property
    is a simple key/value pair with a static value.

    Args:
        obj: The PSObject to add the note property to.
        name: The name of the new note property.
        value: The value of the new note property
        ps_type: Optional PSObject type that the value will get casted to.
        force: Overwrite the existing property (True) or fail (Fail).
    """
    add_member(obj, PSNoteProperty(name, value, ps_type=ps_type), force=force)


def add_script_property(
        obj: typing.Union[PSObject, _PSMetaType],
        name: str,
        getter: typing.Callable[['PSObject'], typing.Any],
        setter: typing.Optional[typing.Callable[['PSObject', typing.Any], None]] = None,
        ps_type: typing.Optional[type] = None,
        force: bool = False,
):
    """Add a script property to a PSObject.

    Adds a script property as an extended property to a PSObject class or a specific instance of a class. A script
    property has a callable getter and optional setter function that is run when the property's value is requested or
    set.

    Args:
        obj: The PSObject to add the alias to.
        name: The name of the new alias property.
        getter: The callable to run when getting a value for this property.
        setter: The callable to run when setting a value for this property.
        ps_type: Optional PSObject type that the alias value will get casted to.
        force: Overwrite the existing property (True) or fail (Fail).
    """
    add_member(obj, PSScriptProperty(name, getter, setter=setter, ps_type=ps_type), force=force)


def ps_isinstance(
        obj: PSObject,
        other: typing.Union[_PSMetaType, typing.Tuple[_PSMetaType, ...], str, typing.Tuple[str, ...]],
        ignore_deserialized: bool = False,
) -> bool:
    """Checks the inheritance of a PSObject.

    This checks if a PSObject is an instance of another PSObject. Instead of checking based on the Python inheritance
    rules it checks based on the .NET TypeNames set for that instance. The check will loop through the `PSTypeNames` of
    the obj passed in and see if any of those types match the first `PSTypeName` of any of the `other` objects
    referenced.

    If `check_deserialized=True`, then any types starting with `Deserialized.` will also match against the
    non-deserialized types, e.g. `Deserialized.System.Collections.Hashtable` will be an instance of
    `System.Collections.Hashtable`.

    Args:
        obj: The object to check if it is inherited from the other types.
        other: The type to check if obj is inherited from. Can also be a list of .NET types as a string.
        ignore_deserialized: Whether to treat `Deserialized.*` instances as they would be serialized.

    Returns:
        (bool): Whether the obj is inherited from any of the other types in .NET.
    """
    def strip_deserialized(type_names):
        if not ignore_deserialized:
            return type_names

        new_names = []
        for name in type_names:
            if name.startswith('Deserialized.'):
                name = name[13:]

            new_names.append(name)

        return new_names

    if not isinstance(other, (list, tuple)):
        other = [other]

    raw_other_types = []
    for o in other:
        if isinstance(o, str):
            raw_other_types.append(o)
        else:
            raw_other_types.append(o.PSObject.type_names[0])

    obj_types = set(strip_deserialized(obj.PSTypeNames))
    desired_types = set(strip_deserialized(raw_other_types))
    matching_types = obj_types & desired_types

    return bool(matching_types)
