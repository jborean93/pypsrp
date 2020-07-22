# Python to .NET Type Information

This is a guide on how to write .NET types as a Python class and the behaviour of these classes on deserialization.
This is all based on the new V2 serialization work that has recently been implementation. To ensure the changes didn't
break any existing scripts using the new serializer is an opt-in choice but it will be the defaults in a future version
of `pypsrp`.


## Behaviour of PowerShell Objects

PowerShell objects are effectively .NET types with an extended type system. This allows an existing .NET type to be
extended with extra properties that don't exist in the base .NET type. While there are many types of properties when an
object is serialized it categorises them into 2 different types:

* Adapted Properties `<Props>`: The base properties that exist on the .NET type
* Extended Properties `<MS>`: Extra properties added by PowerShell

Some key behaviours of PowerShell objects are:

* An adapted and extended property can share the same name, when accessed in PowerShell the extended property is favoured
* Property names can be any anything except `$null`, or one of the following reserved names
    * `PSObject` - the metadata of the object, i.e. properties, type names of the object
    * `PSBase` - the object but with the extended properties stripped out
    * `PSAdapted` - all the adapted properties
    * `PSExtended` - all the extended properties
    * `PSTypeNames` - a list of type names that the object implements
* Property names in PowerShell are also case insensitive
* Properties can be accessed through an index and not dot notation, i.e. `$obj['PropertyName']`
    * When dealing with indexable objects like a hashtable, the index will lookup the property first then the object

### Accessing Properties in Python

The goal of `pypsrp` is to try and replicate the same behaviour around .NET objects that are deserialized to a Python
 object as best as it can. It is largely successful except for these key differences:

* Properties are case sensitive in Python
* When dealing with a dict and using the index lookup, it will lookup the dict elements first before it looks at the properties
* A `System.Boolean/bool` in PowerShell can have extended properties, Python does not allow us to subclass the `bool` type so these properties are dropped
* The `PSBase` property is not implemented, will just return `None` for now
* PowerShell automatically adds the `PSComputerName` and `RunspaceId` extended property to each object returned from a remote runspace, `pypsrp` does not TODO: Should we do this?

In PowerShell you commonly access properties in 2 main ways

```powershell
# Using the dot notation
$obj.PropertyName

# Using an index lookup
$obj['PropertyName']
```

On a deserialized object, the property values are stored in `obj.PSObject` depending on the property type but they can
be accessed like a normal attribute or through an index lookup like:

```python
# Using the dot notation
obj.PropertyName

# Using an index lookup
obj['PropertyName']
```

There are a few limitations when it comes to the Python implementation:

* You cannot do `obj."Property Name"`
    * Python is a lot stricter on what valid attribute names are
    * If you need to access a complex property name use the index lookup notation, e.g. `obj['Property Name']`
* Using the index lookup to access a property requires a native string
    * This is not a problem on Python 3 as native strings are already unicode, so you can do `obj['café']`
    * On Python 2 a native string is technically a byte string so you will be fine when dealing with pure ASCII character
    * When dealing with non-ASCII chars like `é`, Python may encode that value using a different encoding so the lookup will fail
    * For Python 2 you need to use a UTF-8 encoded native string, i.e. `obj[u'café'.encode('utf-8')]`

You can also access the same reserved property names like `PSObject`, `PSBase`, `PSTypeNames`, etc on a Python instance
of a .NET object. The information it returns is similar to PowerShell but with some minor differences:

* `PSBase`: Isn't implemented right now and will return `None`, use `PSAdapted` to get the adapted properties of the object.
* `PSAdapted`: Just returns a dict where the keys are the adapted properties of the object
* `PSExtended`: Also returns a dict where the keys are the extended properties of the object

If you want to see all the properties of an object, similar to how `$obj | Select-Object -Property *` works you can use
the `vars(obj)` function just like a normal Python object.

```python
vars(obj)

# TODO: Give real example here
```

You could also loop through `obj.PSObject.adapted_properties` and `obj.PSObject.extended_properties` and view each
property manually.


## Class Mapping

So far we've covered object properties in PowerShell and how they work in their Python equivalents the next step is to
talk about the underlying class types and how they translate into Python and vice versa.

In [MS-PSRP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/602ee78e-9a19-45ad-90fa-bb132b7cecec)
there are three different types of objects:

* [Primitive types](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/c8c85974-ffd7-4455-84a8-e49016c20683)
* [Complex types](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/406ad572-1ede-43e0-b063-e7291cda3e63)
* Enum types - they are complex types but we consider them separate here

### Primitive Types

Primitive types are fundamental types that contain a value and optional properties. When it comes to working with
primitive types for PSRP in Python, there exists a Python class for each primitive in `pypsrp.dotnet` that subclasses
both `PSObject` as well as the Python type it closely resembles. Here is the mapping of the primitive types:

| .NET | pypsrp.dotnet | Python Type (2/3) | Native |
|-|-|-|-|
| System.String | PSString | unicode/str | Y |
| System.Char | PSChar | int¹ | N |
| System.Boolean | PSBool² | bool | Y |
| System.DateTime | PSDateTime | datetime.datetime | Y |
| System.TimeSpan | PSDuration | unicode/str | N |
| System.Byte | PSByte | int | N |
| System.SByte | PSSByte | int | N |
| System.UInt16 | PSUInt16 | int | N |
| System.Int16 | PSInt16 | int | N |
| System.UInt32 | PSUInt | int | N |
| System.Int32 | PSInt | int | Y |
| System.UInt64 | PSUInt64 | long/int | N |
| System.Int64 | PSInt64 | long/int | N |
| System.Single | PSSingle | float | Y |
| System.Double | PSDouble | float | N |
| System.Decimal | PSDecimal | decimal.Decimal | Y |
| System.Byte[] | PSByteArray | str/bytes | Y |
| System.Guid | PSGuid | uuid.UUID | Y |
| System.Uri | PSUri | unicode/str | N |
| $null | PSNull | None | Y |
| System.Version | PSVersion | unicode/str | N |
| System.Xml.XmlDocument | PSXml | unicode/str | N |
| System.Management.Automation.ScriptBlock | PSScriptBlock | unicode/str | N |
| System.Security.SecureString | PSSecureString³ | unicode/str | N |

¹ - While the base Python type is an `int`, doing `PSChar('1')` will get the char based on the string value. Do `PSChar(1)` if you want the `PSChar` to represent `\u0001`.
² - While there is a `pypsrp.dotnet` entry for these .NET types, they do not inherit `PSObject` so they cannot handle extended properties
³ - A `PSSecureString` can be used to encrypt strings that traverse across the wire but the string in Python is not encrypted in memory, it acts like a normal string.

If `Native` is `Y`, then `pypsrp` will automatically convert that native Python type to the .NET type for you.
Otherwise the `pypsrp.dotnet` implementation must be used if you want to serialize a particular .NET type. For example
if I was to pass in an `int` as an object, `pypsrp` will automatically serialize that to a `System.Int32` but say I
wanted that to be a `System.UInt16` object I would need to pass in a `PSUInt16` instance instead.

When a primitive type is deserialized, the instance will be the `pypsrp.dotnet` type. Due to how inheritance works you
can do all of the following:

```python
import pypsrp.dotnet as dotnet

...
output = ps.invoke()[0]  # Our example outputs an Int32 value

assert isinstance(output, dotnet.PSObject)  # Works for all except bool and $null
assert isinstance(output, dotnet.PSInt)
assert isinstance(output, int)
```

One last thing to note is that all string based types like `PSString`, `PSUri`, etc are all based on the text type of
the Python version that is running. On Python 2 this is the `unicode` type created by string prefixed with `u""` and
on Python 3 this is a native string, the `u""` prefix still works though. If writing Python 2 and 3 compatible code I
recommend always using the `u""` prefix for string values or by importing `from __future__ import unicode_literals`.
This avoids any ambiguity with native strings on Python 2 which are treated as a `Byte[]/PSByteArray` value.

### Complex Types

Complex types are the opposite of a primitive type. While primitive objects can be extended to include extended
properties they are still considered a primitive object because it's a single value. A complex object typically is a
class instance that contains both adapted and extended properties. They can also include container like object such
as a dict, list, stack, queue, etc.

While `pypsrp` supports (de)serialization of effectively any complex object, there are a few .NET complex types that
are mapped to a specific Python class. These are:

| .NET | pypsrp.dotnet | Python Type (2/3) | Native | Rehydrate |
|-|-|-|-|-|
| System.Collections.ArrayList¹ | PSList | list | Y | Y |
| System.Collections.Hashtable¹ | PSDict | dict | Y | Y |
| System.Collections.Stack¹ | PSStack | list | N | Y |
| System.Collections.Queue¹ | PSQueue | Queue.Queue/queue.Queue | Y | Y |
| System.Management.Automation.PSCustomObject | PSCustomObject | type² | Y | Y |
| System.Management.Automation.PSCredential | PSCredential | - | N | Y |

¹ - Other .NET types that are similar to this type are always deserialized to this .NET type, `pypsrp` acts the same, e.g. an` [Object[]]` will become a `PSList`
² - Unless the type used is already a native implementation for another .NET type, it will automatically be serialized as a `PSCustomObject`

Like a primitive object, when `Native` is `Y`, those Python types are automatically serialized to the .NET type it
represents. If you wish to use a specific .NET type that does not natively do this, you need to use the
`pypsrp.dotnet.PS<type>` class that represents the .NET type you desire or create your own.

### Enum Types

While technically a complex type I consider enums in PSRP to be a separate type of object that straddles both a
primitive and complex type. Because of its uniqueness they are implemented slightly differently and have a few caveats
in Python.

There are 2 base enum types that can be used

* `pypsrp.dotnet.PSEnumBase`: Inherits `PSObject`, used for enum types that should be set with a single value
* `pypsrp.dotnet.PSFlagBase`: Inherits `PSEnumBase` but has special behaviour to allow multiple values to be set

Like with .NET enums, the enums that inherit `PSEnumBase` or `PSFlagBase` must also inherit one of the
[numeric types](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/integral-numeric-types)
like:

* `pypsrp.dotnet.PSByte`
* `pypsrp.dotnet.PSSByte`
* `pypsrp.dotnet.PSUInt16`
* `pypsrp.dotnet.PSInt16`
* `pypsrp.dotnet.PSUInt`
* `pypsrp.dotnet.PSInt` (this is typically what you want to use)
* `pypsrp.dotnet.PSUInt64`
* `pypsrp.dotnet.PSInt64`

When defining an enum a `PSObject` class attribute must be set as per any other `PSObject` type but any other class
attributes are considered an enum label/value.

There are a few things when it comes to implementing your own enum type

* The enum names should match the .NET type, don't implement your own custom labels as the label is used to compute the `<ToString>` value in the CLIXML
* If there is an enum label called `None`, use `none` instead
* You must inherit from both `PSEnumBase/PSFlagBase` and one of the numeric types
* If you don't mark the class with `rehydrate=True` then a deserialized instance of that enum will just be the primitive value of whatever numeric type the enum is based on
* Because the instance inherits `int` in the end, you can utilise various numeric operators like bitwise and, bitwise or, addition, etc

Here is an example of an basic enum [System.IO.FileMode](https://docs.microsoft.com/en-us/dotnet/api/system.io.filemode?view=netcore-3.1):

```python
import pypsrp.dotnet as pynet


class IOFileMode(pynet.PSEnumBase, pynet.PSInt):

    PSObject = pynet.PSObjectMeta(
        type_names=['System.IO.FileMode', 'System.Enum', 'System.ValueType', 'System.Object'],
        rehydrate=True,
    )

    Append = 6
    Create = 2
    CreateNew = 1
    Open = 3
    OpenOrCreate = 4
    Truncate = 5
```

When you want to get an enum value just do `IOFileMode.Append` or with whatever label you need. Any instances of
`PSEnumBase` will automatically convert the raw `int` value to an instance of that type, i.e. `IOFileMode.Append` will
be `IOFileMode(6)`.

Here is an example of a basic enum [System.IO.FileShare](https://docs.microsoft.com/en-us/dotnet/api/system.io.fileshare?view=netcore-3.1)
that uses the `[FlagsAttributes]` to allow multiple values to be set.

```python
import pypsrp.dotnet as pynet


class IOFileShare(pynet.PSFlagBase, pynet.PSInt):

    PSObject = pynet.PSObjectMeta(
        type_names=['System.IO.FileShare', 'System.Enum', 'System.ValueType', 'System.Object'],
        rehydrate=True,
    )

    Delete = 4
    Inheritable = 16
    none = 0
    Read = 1
    ReadWrite = 3
    Write = 2
```

Enums, like primitive objects can have further extended properties added to it if that is desired.


## Implementing .NET Type in Python

When implementing your own Python class to represent a .NET type there are few things you need to consider/understand:

* The property names of the .NET class must match up with the ones defined on the Python class
    * You can use the `@property` alias as a decorator if you wish to use things like to access attributes using the more pythonic `snake_case` format
* When an object is serialized, property values are sourced from the property object inside `PSObject`
    * Using a `@property` decorator to generate a calculated property value won't work
    * The workaround is to set the property value to a function that is called during deserialization
* Methods defined on the Python class are not transferred to PowerShell, only properties are
* Whether you want the type to be rehydrated on deserialization or not
    * This affects the `__init__()` signature as a rehydratable object must not have any required arguments 

All custom .NET types in PowerShell that you implement *SHOULD* inherit from `pypsrp.dotnet.PSObject`. Any classes that
do not inherit this type will be treated as a `PSCustomObject` which is explained a bit later. A class that inherits
`PSObject` must have a class attribute `PSObject` that is set to an instance of `pypsrp.dotnet.PSObjectMeta`. The
`PSObjectMeta` can be initialized with the following value:

* `type_names`: (Required) A list of .NET types the object inherits, i.e. `['System.String', 'System.Object']`
* `adapted_properties`: A list of `pypsrp.dotnet.PSPropertyInfo` instances that define the adapted properties of the object
* `extended_properties`: A list of `pypsrp.dotnet.PSPropertyInfo` instances that define the extended properties of the object
* `rehydrate`: Whether this type can be rehydrated (deserialized to this type) or not 
* `tag`: The CLIXML tag element value to use, this should not be used for end users as all complex types are `Obj`

The `adapted_properties` and `extended_properties` kwargs take a list of `pypsrp.dotnet.PSPropertyInfo` objects that
define the properties of the object itself. Once a property has been defined on the object it is immediately
gettable/settable like a normal attribute of an instance. The kwargs that `PSPropertyInfo` access are

* `name`: The name of the property
* `optional`: Whether this property is optional or not. If `True` then during serialization an unset property will have a `<Nil />` value, otherwise it is omitted altogether
* `ps_type`: The primitive type (complex types aren't supported) to use when serializing an object. If set the property value will be casted to this type before it is serialized

The `rehydrate` kwarg is used during serialization to determine the Python type that is used for the deserialized
value. If `True` then any .NET objects that implement the same `type_names` will be a Python instance of the actual
type. If `False` then the returned Python object will be a `pypsrp.dotnet.PSObject` will all the same properties set
and the `obj.PSObject.type_names` will have `Deserialized.<type name>` on them. The only requirement for a class with
`rehydrate=True` is that it's `__init__()` signature must have no mandatory arguments. When an instance of that class
is created during de-serialization, it is just called with `Object()`. The main benefit `rehydrate=True` offers is it
allows you do an `isinstance(obj, MyType)` check and control some extra instance init behaviour when the instance is
created.

Here is an example of how `pypsrp` implemented the [PSCredential](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0)
type.

```python
from pypsrp.dotnet import (
    PSObject,
    PSObjectMeta,
    PSPropertyInfo,
    PSString,
    PSSecureString,
)


class PSCredential(PSObject):

    PSObject = PSObjectMeta(
        type_names=['System.Management.Automation.PSCredential', 'System.Object'],
        adapted_properties=[
            PSPropertyInfo('UserName', ps_type=PSString),
            PSPropertyInfo('Password', ps_type=PSSecureString),
        ],
        rehydrate=True,  # Because __init__ does not have any required args, we can rehydrate this object.
    )

    def __init__(self, UserName=None, Password=None):
        self.UserName = UserName
        self.Password = Password
```

We can see that the `type_names` is set to the types that the object inherits starting from top down and the adapted
properties and the types they should be coerced to when being serialized. The `__init__` method is not required but
added as a convenience for people who want to create an object in one line.

Creating your own types is usually just about getting the metadata of the type and defining it under `PSObject`. You
can expand on it however you wish. To help with creating your own classes I've written a PowerShell function called
[ConvertTo-PythonClass](ConvertTo-PythonClass.ps1) that you can use to generate a skeleton class in Python. This
skeleton can adjusted based on your requirements to include extra methods/properties for use on the Python side.

```powershell
$obj = Get-Item -Path C:\Windows
$obj | ConvertTo-PythonClass -AddDoc -Rehydrate

# import pypsrp.dotnet as pynet
#
#
# class PSDirectoryInfo(pynet.PSObject):
#     """Python class for System.IO.DirectoryInfo
#
#     This is an auto-generated Python class for the System.IO.DirectoryInfo .NET class.
#     """
#     PSObject = pynet.PSObjectMeta(
#         type_names=[
#             'System.IO.DirectoryInfo',
#             'System.IO.FileSystemInfo',
#             'System.MarshalByRefObject',
#             'System.Object',
#         ],
#         adapted_properties=[
#             pynet.PSPropertyInfo('Parent'),
#             pynet.PSPropertyInfo('Root'),
#             pynet.PSPropertyInfo('FullName', ps_type=PSString),
#             pynet.PSPropertyInfo('Extension', ps_type=PSString),
#             pynet.PSPropertyInfo('Name', ps_type=PSString),
#             pynet.PSPropertyInfo('Exists', ps_type=PSBool),
#             pynet.PSPropertyInfo('CreationTime', ps_type=PSDateTime),
#             pynet.PSPropertyInfo('CreationTimeUtc', ps_type=PSDateTime),
#             pynet.PSPropertyInfo('LastAccessTime', ps_type=PSDateTime),
#             pynet.PSPropertyInfo('LastAccessTimeUtc', ps_type=PSDateTime),
#             pynet.PSPropertyInfo('LastWriteTime', ps_type=PSDateTime),
#             pynet.PSPropertyInfo('LastWriteTimeUtc', ps_type=PSDateTime),
#             pynet.PSPropertyInfo('Attributes'),
#         ],
#         extended_properties=[
#             pynet.PSPropertyInfo('PSPath', ps_type=PSString),
#             pynet.PSPropertyInfo('PSParentPath', ps_type=PSString),
#             pynet.PSPropertyInfo('PSChildName', ps_type=PSString),
#             pynet.PSPropertyInfo('PSDrive'),
#             pynet.PSPropertyInfo('PSProvider'),
#             pynet.PSPropertyInfo('PSIsContainer', ps_type=PSBool),
#             pynet.PSPropertyInfo('Mode', ps_type=PSString),
#             pynet.PSPropertyInfo('ModeWithoutHardLink', ps_type=PSString),
#             pynet.PSPropertyInfo('BaseName'),
#             pynet.PSPropertyInfo('Target', ps_type=PSString),
#             pynet.PSPropertyInfo('LinkType', ps_type=PSString),
#         ],
#         rehydrate=True,
#     )
```

One really common object that is used in PowerShell is the [PSCustomObject](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscustomobject?view=powershellsdk-7.0.0)
object. This is typically created using `[PSCustomObject]@{ ... }` and `pypsrp` has 2 ways of implementing the same
concept.

```python
from pypsrp.dotnet import PSCustomObject

# Using PSObjectObject({'key': 'value'})
ps_custom_object = PSCustomObject({
    'PropertyName': 'name',
    'AnotherProperty': 1,
})

# Using a plain Python class
class MyPSCustomObject:

    def __init__(self, PropertyName, AnotherProperty):
        self.PropertyName = PropertyName
        self.AnotherProperty = AnotherProperty

ps_custom_object = MyPSCustomObject('name', 1)
```

The first example is a lot simpler and works in a similar way to how `[PSCustomObject]$hash` works but the latter
allows you to control more aspect when generating the object such as mandatory arguments, calculated properties,
custom methods on the Python side, etc. When the serializer detects an object that does not inherit
`pypsrp.dotnet.PSObject` it does the following:

* If it's a known native type like `str`, `int`, it will serialize it as the [primitive type it maps to](#primitive-types)
* Otherwise is creates a `PSCustomObject` with it's properties set to all the instances properties and attributes

When it comes to deserializing a `PSCustomObject`, there is no rehydration behaviour. It will always be deserialized as
a `pypsrp.dotnet.PSCustomObject`.


## Deserialization Behaviour

Here is a brief overview of how `pypsrp` deserializes CLIXML to an object

* Check if the CLIXML is a basic primitive type or not (XML tag != `Obj`).
    * If it's a primitive type, create new instance for the matching type and return it
* When it's a complex object, it will search the `TypeRegistry` to see if the type has been registered
    * If the type is registered a new blank instance of the registered class for that type is created
    * If the type is not registered, or the init above failed, a blank `PSObject` is created
    * In the latter case the `PSTypeNames` for the next object are prefixed with `Deserialized.<TypeName>`
* If the CLIXML contains a `<ToString>` value, that is registered to the object's metadata so `str(obj)` outputs that value
* It will scan all adapted and extended properties in the CLIXML and add them to the value
    * Even if a rehydrated object was used and did not have that property in the class metadata it will still be added to the new instance
    * This also applies to enums and extended primitive objects
* If the object wraps a dictionary (XML tag == `DCT`)
    * The value becomes `pypsrp.dotnet.PSDict` and is populated with the dict elements
* If the object wraps a stack (XML tag == `STK`)
    * The value becomes `pypsrp.dotnet.PSStack` and is populated with the stack elements
* If the object wraps a queue (XML tag == `QUE`)
    * The value becomes `pypsrp.dotnet.PSQueue` and is populated with the queue elements
* If the object wraps a list (XML tag == `LST` or `IE`)
    * The value becomes `pypsrp.dotnet.PSList` and is populated with the list elements
* If the object contains a remaining value
    * If the type names match a *registered rehydratable* enum, the enum value is set to this primitive value
    * Else the value now becomes an instance of the primitive value specified instead of a `PSObject`

The end result is:

* Primitive objects are returned as primitive objects with any extra extended properties that may be present
* Enums are returned as that enum if the enum type was registered with `rehydrate=True` at the class definition, otherwise the returned object is the primitive value the enum represents
* Dictionaries are returned as `pypsrp.dotnet.PSDict`
* Stacks are returned as `pypsrp.dotnet.PSStack`
* Queues are returned as `pypsrp.dotnet.PSQueue`
* Lists are returned as `pypsrp.dotnet.PSList`
* Other objects are returned as that object if the type was registered with `rehydrate=True` at the class definition, otherwise a `pypsrp.dotnet.PSObject` is created and has the extended properties set

The `TypeRegistry` mentioned above is a special singleton created by `pypsrp` that contains all the types that inherit
`PSObject` and set `rehydrate=True` in it's metadata. This registry is used to deserialize CLIXML to the proper Python
type if available. The only differences between a rehydrated and plain `PSObject` object are:

* A rehydrated object is an instance of that registered type, so any methods or properties are accessible
* A non-rehydrated object is an instance of `pypsrp.dotnet.PSObject`, all the properties are still available
* A rehydrated object keeps the type names under `obj.PSTypeNames` the way they were in the CLIXML
* A non-rehydrated object will prefix all of its type names under `obj.PSTypeNames` with `Deserialized.`.

## Add-Member

In PowerShell you can add extra properties to an existing object using the [Add-Member](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-member?view=powershell-7)
cmdlet. You can achieve a similar thing in `pypsrp` by adding a new `pypsrp.dotnet.PSPropertyInfo` to the instance's
desired `PSObject` property list.

TODO: Add examples


## Update-TypeData

Similar to `Add-Member`, the [Update-TypeData](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/update-typedata?view=powershell-7)
allows you to add extra properties and methods to an existing type that is automatically inherited by any instance of
that type. This allows you to do something like setting an alias of property to another name like:

```powershell
Update-TypeData -TypeName 'System.DateTime' -MemberType ScriptProperty -MemberName 'Quarter' -Value {
  if ($this.Month -in @(1,2,3)) {"Q1"}
  elseif ($this.Month -in @(4,5,6)) {"Q2"}
  elseif ($this.Month -in @(7,8,9)) {"Q3"}
  else {"Q4"}
}
```

TODO: Implement this behaviour in Python.
