# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import binascii
import datetime
import logging
import re
import sys
import uuid

from copy import (
    copy,
)

from cryptography.hazmat.primitives.padding import (
    PKCS7,
)

from decimal import (
    Decimal,
)

from six import (
    binary_type,
    integer_types,
    string_types,
    text_type,
)

from pypsrp.complex_objects import (
    ApartmentState,
    Color,
    CommandMetadataCount,
    CommandOrigin,
    Coordinates,
    ComplexObject,
    CultureInfo,
    DictionaryMeta,
    GenericComplexObject,
    HostMethodIdentifier,
    InformationalRecord,
    KeyInfoDotNet,
    ListMeta,
    ObjectMeta,
    ParameterMetadata,
    PipelineResultTypes,
    ProgressRecordType,
    PSCredential,
    PSThreadOptions,
    QueueMeta,
    RemoteStreamOptions,
    SessionStateEntryVisibility,
    Size,
    StackMeta,
)

from pypsrp.dotnet import (
    PSByte,
    PSByteArray,
    PSChar,
    PSCustomObject,
    PSDateTime,
    PSDecimal,
    PSDict,
    PSDouble,
    PSDuration,
    PSEnumBase,
    PSGuid,
    PSInt16,
    PSInt,
    PSInt64,
    PSList,
    PSObject,
    PSPropertyInfo,
    PSQueue,
    PSSByte,
    PSScriptBlock,
    PSSecureString,
    PSSingle,
    PSStack,
    PSString,
    PSUInt16,
    PSUInt,
    PSUInt64,
    PSUri,
    PSVersion,
    PSXml,
    TypeRegistry,
)

from pypsrp.exceptions import (
    SerializationError,
)

from pypsrp.messages import (
    DebugRecord,
    ErrorRecord,
    InformationRecord,
    VerboseRecord,
    WarningRecord,
)

from pypsrp._utils import (
    to_bytes,
    to_string,
    to_unicode,
)

try:
    from queue import Queue, Empty
except ImportError:  # pragma: no cover
    from Queue import Queue, Empty

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
    element_type = ET._Element
else:  # pragma: no cover
    import xml.etree.ElementTree as ET
    element_type = ET.Element

log = logging.getLogger(__name__)


class _SerializerBase(object):

    def __init__(self, cipher=None):
        self.obj_id = 0
        self.obj = {}
        self.tn_id = 0
        self.tn = {}

        self.cipher = cipher
        # Finds C0, C1, and surrogate pairs in a unicode string for us to encode according to the PSRP rules.
        if sys.maxunicode == 65535:  # pragma: no cover
            # Using a narrow Python build or Python 2.x, the regex we to find surrogate pairs is different than a wide
            # build or on Python 3
            self._serial_str = re.compile(u"[\u0000-\u001F]|[\u007F-\u009F]|[\uD800-\uDBFF][\uDC00-\uDFFF]")
        else:  # pragma: no cover
            self._serial_str = re.compile(u'[\u0000-\u001F\u007F-\u009F\U00010000-\U0010FFFF]')

        # To support surrogate UTF-16 pairs we need to use a UTF-16 regex so we can replace the UTF-16 string
        # representation with the actual UTF-16 byte value and then decode that.
        self._deserial_str = re.compile(b"\\x00_\\x00x([\\0\\w]{8})\\x00_")
        self._dt_fraction_pattern = re.compile(r'\.(\d+)(.*)')

    def _deserialize_datetime(self, value):
        # DateTime values from PowerShell are in the format 'YYYY-MM-DDTHH:MM-SS[.100's of nanoseconds]Z'.
        # Unfortunately datetime can only be resolved to microseconds so we need to extract the fraction of seconds
        # edit it to be microseconds and preserve the nanoseconds ourselves.

        datetime_str = value[:19]
        fraction_tz_section = value[19:]
        nanoseconds = 0

        fraction_match = self._dt_fraction_pattern.match(fraction_tz_section)
        if fraction_match:
            # We have fractional seconds, need to rewrite as microseconds and keep the nanoseconds ourselves.
            fractional_seconds = fraction_match.group(1)
            if len(fractional_seconds) > 6:
                # .NET should only be showing 100's of nanoseconds but just to be safe we will calculate that based
                # on the length of the fractional seconds found.
                nanoseconds = int(fractional_seconds[-1:]) * (10 ** (3 + 6 - len(fractional_seconds)))
                fractional_seconds = fractional_seconds[:-1]

            timezone_section = fraction_match.group(2)

            datetime_str += '.%s%s' % (fractional_seconds, timezone_section)
        else:
            # No fractional seconds, just use strptime on the original value.
            datetime_str = value

        dt = PSDateTime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S.%f%z')
        dt.nanosecond = nanoseconds

        return dt

    def _deserialize_secure_string(self, value):
        if self.cipher is None:
            # cipher is not set up so we can't decrypt the string, just return
            # the raw element
            return value

        ss_string = base64.b64decode(value.text)
        decryptor = self.cipher.decryptor()
        decrypted_bytes = decryptor.update(ss_string) + decryptor.finalize()

        unpadder = PKCS7(self.cipher.algorithm.block_size).unpadder()
        unpadded_bytes = unpadder.update(decrypted_bytes) + unpadder.finalize()
        decrypted_string = to_unicode(unpadded_bytes, 'utf-16-le')

        return decrypted_string

    def _deserialize_string(self, value):
        if value is None:
            return ""

        def rplcr(matchobj):
            # The matched object is the UTF-16 byte representation of the UTF-8 hex string value. We need to decode the
            # byte str to unicode and then unhexlify that hex string to get the actual bytes of the _x****_ value, e.g.
            # group(0) == b"\x00_\x00x\x000\x000\x000\x00A\x00_"
            # group(1) == b"\x000\x000\x000\x00A"
            # unicode (from utf-16-be) == u"000A"
            # returns b"\x00\x0A"
            match_hex = matchobj.group(1)
            hex_string = to_unicode(match_hex, encoding='utf-16-be')
            return binascii.unhexlify(hex_string)

        # Need to ensure we start with a unicode representation of the string so that we can get the actual UTF-16
        # bytes value from that string.
        unicode_value = to_unicode(value)
        unicode_bytes = to_bytes(unicode_value, encoding='utf-16-be')
        bytes_value = re.sub(self._deserial_str, rplcr, unicode_bytes)
        return to_unicode(bytes_value, encoding='utf-16-be')

    def _get_obj_id(self, obj=None):
        # Do a basic sanity check to see if the object has already been serialized and use the same ID. This is only
        # done in SerializerV2().
        if obj is not None and id(obj) in self.obj:
            return self.obj[id(obj)]

        ref_id = str(self.obj_id)
        self.obj_id += 1
        return ref_id

    def _serialize_datetime(self, value):
        # .NET supports DateTime to a 100 nanosecond precision so we need to manually massage the data from Python
        # to suit that precision if available.
        fraction_seconds = ""
        nanoseconds = getattr(value, 'nanosecond', None)
        if value.microsecond or nanoseconds:
            fraction_seconds = value.strftime('.%f')

            if nanoseconds:
                fraction_seconds += str(int(nanoseconds / 100))

        timezone = 'Z'
        if value.tzinfo:
            utc_offset = value.strftime('%z')
            timezone = "%s:%s" % (utc_offset[:3], utc_offset[3:])

        dt_str = value.strftime("%Y-%m-%dT%H:%M:%S{0}{1}".format(fraction_seconds, timezone))

        return to_unicode(dt_str)

    def _serialize_secure_string(self, value):
        if self.cipher is None:
            raise SerializationError("Cannot generate secure string as cipher "
                                     "is not initialised")

        # Convert the string to a UTF-16 byte string as that is what is expected in Windows. If a byte string (native
        # string in Python 2) was passed in, the sender must make sure it is a valid UTF-16 representation and not
        # UTF-8 or else the server will fail to decrypt the secure string in most cases.
        string_bytes = to_bytes(value, encoding='utf-16-le')

        padder = PKCS7(self.cipher.algorithm.block_size).padder()
        padded_data = padder.update(string_bytes) + padder.finalize()

        encryptor = self.cipher.encryptor()
        ss_value = encryptor.update(padded_data) + encryptor.finalize()
        ss_string = to_string(base64.b64encode(ss_value))

        return ss_string

    def _serialize_string(self, value):
        if value is None:
            return None

        def rplcr(matchobj):
            surrogate_char = matchobj.group(0)
            byte_char = to_bytes(surrogate_char, encoding='utf-16-be')
            hex_char = to_unicode(binascii.hexlify(byte_char)).upper()
            hex_split = [hex_char[i:i + 4] for i in range(0, len(hex_char), 4)]

            return u"".join([u"_x%s_" % i for i in hex_split])

        string_value = to_unicode(value)

        # Before running the translation we need to make sure _ before x is encoded, normally _ isn't encoded except
        # when preceding x. The MS-PSRP docs don't state this but the _x0000_ matcher is case insensitive so we need to
        # make sure we escape _X as well as _x.
        string_value = re.sub(u"(?i)_(x)", u"_x005F_\\1", string_value)
        string_value = re.sub(self._serial_str, rplcr, string_value)

        return string_value

    def _get_types_from_obj(self, element):
        obj_types = [e.text for e in element.findall("TN/T")]

        if len(obj_types) > 0:
            ref_id = element.find("TN").attrib['RefId']
            self.tn[ref_id] = obj_types

        tn_ref = element.find("TNRef")
        if tn_ref is not None:
            ref_id = tn_ref.attrib['RefId']
            obj_types = self.tn[ref_id]

        return obj_types


class Serializer(_SerializerBase):

    def __init__(self):
        super(Serializer, self).__init__()

    def serialize(self, value, metadata=None, parent=None, clear=True):
        """
        Serializes a raw value or class into an XML Element that can be sent
        over to the remote host.

        :param value: The value to serialize
        :param metadata: Any extra metadata to control how to serialize the
            value, if None then the value will be inferred by the type
        :param parent: Whether to append the element onto a parent element
        :param clear: Whether to clear the Obj and TN reference map, this
            should only be True when initially calling serialize
        :return: The XML Element from the serializied value
        """
        if clear:
            self._clear()

        if isinstance(value, element_type):
            if metadata is not None and metadata.name is not None:
                value.attrib['N'] = metadata.name

            if parent is not None:
                parent.append(value)

            return value

        metadata = metadata or ObjectMeta()
        if metadata.tag == "*":
            metadata.tag = self._get_tag_from_value(value)

        pack_function = {
            # primitive types
            'S': lambda m, d: self._serialize_string(d),
            'ToString': lambda d: self._serialize_string(d),
            'C': lambda m, d: str(ord(d)),
            'B': lambda m, d: str(d).lower(),
            'DT': lambda m, d: None,
            'TS': lambda m, d: str(d),
            'By': lambda m, d: str(d),
            'SB': lambda m, d: str(d),
            'U16': lambda m, d: str(d),
            'I16': lambda m, d: str(d),
            'U32': lambda m, d: str(d),
            'I32': lambda m, d: str(d),
            'U64': lambda m, d: str(d),
            'I64': lambda m, d: str(d),
            'Sg': lambda m, d: str(d),
            'Db': lambda m, d: str(d),
            'D': lambda m, d: str(d),
            'BA': lambda m, d: to_string(base64.b64encode(d)),
            'G': lambda m, d: str(d),
            'URI': lambda m, d: self._serialize_string(d),
            'Version': lambda m, d: str(d),
            'XD': lambda m, d: self._serialize_string(d),
            'SBK': lambda m, d: self._serialize_string(d),
            'SS': lambda m, d: self._serialize_secure_string(d),
            'Obj': self._serialize_obj,
            "ObjDynamic": self._serialize_dynamic_obj,
            'LST': self._serialize_lst,
            'IE': self._serialize_ie,
            'QUE': self._serialize_que,
            'STK': self._serialize_stk,
            'DCT': self._serialize_dct
        }[metadata.tag]

        if value is None:
            if metadata.optional:
                return
            element = ET.Element("Nil")
        else:
            element_value = pack_function(metadata, value)
            if isinstance(element_value, string_types):
                element = ET.Element(metadata.tag)
                element.text = element_value
            else:
                element = element_value

        if metadata.name is not None:
            element.attrib['N'] = metadata.name

        if parent is not None:
            parent.append(element)

        return element

    def deserialize(self, element, metadata=None, clear=True):
        if clear:
            self._clear()

        if isinstance(element, string_types):
            element_string = element
            try:
                element = ET.fromstring(element)
            except ET.ParseError as err:
                log.warning("Failed to parse data '%s' as XML, return raw "
                            "xml: %s" % (element_string, str(err)))
                return element_string
        else:
            xml_string = ET.tostring(element, encoding='utf-8', method='xml')
            element_string = to_string(xml_string)

        metadata = metadata or ObjectMeta()
        if metadata.tag == "*":
            metadata.tag = element.tag

        # get the object types so we store the TN Ref ids for later use
        obj_types = self._get_types_from_obj(element)

        # check if it is a primitive object
        unpack_function = {
            # Primitive types
            'S': lambda d: self._deserialize_string(d.text),
            'ToString': lambda d: self._deserialize_string(d.text),
            'C': lambda d: chr(int(d.text)),
            'B': lambda d: d.text.lower() == "true",
            'DT': lambda d: d.text,
            'TS': lambda d: d.text,
            'By': lambda d: int(d.text),
            'SB': lambda d: int(d.text),
            'U16': lambda d: int(d.text),
            'I16': lambda d: int(d.text),
            'U32': lambda d: int(d.text),
            'I32': lambda d: int(d.text),
            'U64': lambda d: int(d.text),
            'I64': lambda d: int(d.text),
            'Sg': lambda d: float(d.text),
            'Db': lambda d: float(d.text),
            'D': lambda d: d.text,  # TODO: deserialize this
            'BA': lambda d: base64.b64decode(d.text),
            'G': lambda d: uuid.UUID(d.text),
            'URI': lambda d: self._deserialize_string(d.text),
            'Nil': lambda d: None,
            'Version': lambda d: d.text,
            'XD': lambda d: self._deserialize_string(d.text),
            'SBK': lambda d: self._deserialize_string(d.text),
            'SS': lambda d: self._deserialize_secure_string(d),

            # references an object already deserialized
            'Ref': lambda d: self.obj[d.attrib['RefId']],
        }.get(element.tag)

        if unpack_function is not None:
            return unpack_function(element)

        # not a primitive object, so try and decode the complex object
        if type(metadata) == ObjectMeta and metadata.object is None:
            structures = {
                "Selected.Microsoft.PowerShell.Commands.GenericMeasureInfo":
                    ObjectMeta("Obj", object=CommandMetadataCount),
                "System.Array": ListMeta(),
                "System.Collections.ArrayList": ListMeta(),
                "System.Collections.Hashtable": DictionaryMeta(),
                "System.Collections.Generic.List": ListMeta(),
                "System.Collections.Queue": QueueMeta(),
                "System.Collections.Stack": StackMeta(),
                "System.ConsoleColor": ObjectMeta("Obj", object=Color),
                "System.Management.Automation.CommandOrigin":
                    ObjectMeta("Obj", object=CommandOrigin),
                "System.Management.Automation.DebugRecord":
                    ObjectMeta("Obj", object=DebugRecord),
                "System.Management.Automation.ErrorRecord":
                    ObjectMeta("Obj", object=ErrorRecord),
                "System.Management.Automation.Host.Coordinates":
                    ObjectMeta("Obj", object=Coordinates),
                "System.Management.Automation.Host.KeyInfo":
                    ObjectMeta("Obj", object=KeyInfoDotNet),
                "System.Management.Automation.Host.Size":
                    ObjectMeta("Obj", object=Size),
                "System.Management.Automation.InformationalRecord":
                    ObjectMeta("Obj", object=InformationalRecord),
                "System.Management.Automation.InformationRecord":
                    ObjectMeta("Obj", object=InformationRecord),
                "System.Management.Automation.ParameterMetadata":
                    ObjectMeta("Obj", object=ParameterMetadata),
                "System.Management.Automation.ProgressRecordType":
                    ObjectMeta("Obj", object=ProgressRecordType),
                "System.Management.Automation.PSBoundParametersDictionary":
                    DictionaryMeta(),
                "System.Management.Automation.PSCredential":
                    ObjectMeta("Obj", object=PSCredential),
                "System.Management.Automation.PSObject":
                    ObjectMeta("ObjDynamic", object=GenericComplexObject),
                "System.Management.Automation.PSPrimitiveDictionary":
                    DictionaryMeta(),
                "System.Management.Automation.PSTypeName": ObjectMeta("S"),
                "System.Management.Automation.Remoting.RemoteHostMethodId":
                    ObjectMeta("Obj", object=HostMethodIdentifier),
                "System.Management.Automation.Runspaces.ApartmentState":
                    ObjectMeta("Obj", object=ApartmentState),
                "System.Management.Automation.Runspaces.PipelineResultTypes":
                    ObjectMeta("Obj", object=PipelineResultTypes),
                "System.Management.Automation.Runspaces.PSThreadOptions":
                    ObjectMeta("Obj", object=PSThreadOptions),
                "System.Management.Automation.Runspaces.RemoteStreamOptions":
                    ObjectMeta("Obj", object=RemoteStreamOptions),
                "System.Management.Automation.SessionStateEntryVisibility":
                    ObjectMeta("Obj", object=SessionStateEntryVisibility),
                "System.Management.Automation.VerboseRecord":
                    ObjectMeta("Obj", object=VerboseRecord),
                "System.Management.Automation.WarningRecord":
                    ObjectMeta("Obj", object=WarningRecord),
                "System.Globalization.CultureInfo":
                    ObjectMeta("Obj", object=CultureInfo),

                # Fallback to the GenericComplexObject
                "System.Object":
                    ObjectMeta("ObjDynamic", object=GenericComplexObject),

                # Primitive types
                "System.String": ObjectMeta("S"),
                "System.Char": ObjectMeta("C"),
                "System.Boolean": ObjectMeta("B"),
                "System.DateTime": ObjectMeta("DT"),
                # None: ObjectMeta("TS"), # duration timespan
                "System.Byte": ObjectMeta("By"),
                "System.SByte": ObjectMeta("SB"),
                "System.UInt16": ObjectMeta("U16"),
                "System.Int16": ObjectMeta("I16"),
                "System.UInt32": ObjectMeta("U32"),
                "System.Int32": ObjectMeta("I32"),
                "System.UInt64": ObjectMeta("U64"),
                "System.Int64": ObjectMeta("I64"),
                "System.Single": ObjectMeta("Sg"),
                "System.Double": ObjectMeta("Db"),
                "System.Decimal": ObjectMeta("D"),
                # None: ObjectMeta("BA"), # Byte array base64 encoded
                "System.Guid": ObjectMeta("G"),
                "System.Uri": ObjectMeta("URI"),
                "System.Version": ObjectMeta("Version"),
                "System.Xml.XmlDocument": ObjectMeta("XD"),
                "System.Management.Automation.ScriptBlock": ObjectMeta("SBK"),
                "System.Security.SecureString": ObjectMeta("SS"),
            }

            # fallback to GenericComplexObject if no types were defined
            if metadata.tag == "Obj" and len(obj_types) == 0:
                obj_types = ["System.Object"]

            metadata = None
            for obj_type in obj_types:
                if obj_type.startswith("Deserialized.System."):
                    obj_type = obj_type[13:]

                is_list = False
                if obj_type.endswith("[]"):
                    obj_type = obj_type[0:-2]
                    is_list = True
                elif obj_type.startswith("System.Collections."
                                         "Generic.List`1[["):
                    list_info = obj_type[35:-1]
                    obj_type = list_info.split(",")[0]
                    is_list = True
                elif obj_type.startswith("System.Collections.ObjectModel."
                                         "Collection`1[["):
                    list_info = obj_type[45:-1]
                    obj_type = list_info.split(",")[0]
                    is_list = True
                elif obj_type.startswith("System.Collections.ObjectModel."
                                         "ReadOnlyCollection`1[["):
                    list_info = obj_type[53:-1]
                    obj_type = list_info.split(",")[0]
                    is_list = True
                elif obj_type.startswith("System.Collections.Generic."
                                         "Dictionary`2[["):
                    dict_meta = obj_type[41:-2].split("],[")
                    key_type = structures.get(dict_meta[0].split(",")[0],
                                              ObjectMeta())
                    value_type = structures.get(dict_meta[1].split(",")[0],
                                                ObjectMeta())
                    metadata = DictionaryMeta(dict_key_meta=key_type,
                                              dict_value_meta=value_type)
                    break

                obj_meta = structures.get(obj_type)
                if obj_meta is not None:
                    metadata = obj_meta
                    if is_list:
                        metadata = ListMeta(list_value_meta=metadata)
                    break

        # we were unable to find the complex object type so just return the
        # element
        if metadata is None:
            obj = element_string
        elif metadata.tag == "Obj":
            obj = self._deserialize_obj(element, metadata)
        elif metadata.tag == "ObjDynamic":
            obj = self._deserialize_dynamic_obj(element, metadata)
        elif metadata.tag == "LST":
            obj = self._deserialize_lst(element, metadata)
        elif metadata.tag == "QUE":
            obj = self._deserialize_que(element)
        elif metadata.tag == "STK":
            obj = self._deserialize_stk(element)
        elif metadata.tag == "DCT":
            obj = self._deserialize_dct(element)
        else:
            log.warning("Unknown metadata tag type '%s', failed to "
                        "deserialize object" % metadata.tag)
            obj = element_string

        if element.tag == "Obj":
            self.obj[element.attrib['RefId']] = obj

        if isinstance(obj, ComplexObject):
            obj._xml = element_string

        return obj

    def _clear(self):
        self.obj_id = 0
        self.obj = {}
        self.tn = {}
        self.tn_id = 0

    def _get_tag_from_value(self, value):
        # Get's the XML tag based on the value type, this is a simple list
        # and explicit tagging is recommended.

        value_type = type(value)
        if value_type == int:
            return "I32"
        elif value_type == bool:
            return "B"
        elif value_type == float:
            return "Sg"
        elif value_type == str:
            return "S"
        elif value_type == bytes:
            # This will only occur in Python 3 as a byte string in Python 2 is
            # a str. If users on that platform want a BA then they need to
            # explicitly set the metadata themselves
            return "BA"
        elif value_type == uuid.UUID:
            return "G"
        elif value_type == list:
            return "LST"
        elif value_type == dict:
            return "DCT"
        elif isinstance(value, Queue):
            return "QUE"
        elif isinstance(value, GenericComplexObject):
            return "ObjDynamic"
        elif isinstance(value, ComplexObject):
            return "Obj"
        else:
            # catch all, this probably isn't right but will not throw an
            # error
            return "S"

    def _serialize_obj(self, metadata, value):
        obj = ET.Element("Obj", RefId=self._get_obj_id())

        if len(value._types) > 0:
            self._create_tn(obj, value._types)

        to_string_value = value._to_string
        if to_string_value is not None:
            ET.SubElement(obj, "ToString").text = \
                self._serialize_string(to_string_value)

        for attr, property_meta in value._property_sets:
            attr_value = getattr(value, attr)
            self._create_obj(obj, attr_value, meta=property_meta)

        def serialize_prop(parent, properties):
            if len(properties) == 0:
                return
            parent = ET.SubElement(obj, parent)
            for attr, property_meta in properties:
                attr_value = getattr(value, attr)
                self._create_obj(parent, attr_value, meta=property_meta)

        serialize_prop("MS", value._extended_properties)
        serialize_prop("Props", value._adapted_properties)

        return obj

    def _serialize_dynamic_obj(self, metadata, value):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
        self.obj[obj.attrib["RefId"]] = value

        if len(value.types) > 0:
            self._create_tn(obj, value.types)

        if value.to_string is not None:
            ET.SubElement(obj, "ToString").text = \
                self._serialize_string(value.to_string)

        for prop in value.property_sets:
            self._create_obj(obj, prop)

        def set_properties(element, prop_name):
            prop_keys = list(getattr(value, prop_name).keys())
            if len(prop_keys) == 0:
                return

            parent = ET.SubElement(obj, element)
            prop_keys.sort()
            for key in prop_keys:
                prop = getattr(value, prop_name)[key]
                self._create_obj(parent, prop, key=key)

        set_properties("MS", "extended_properties")
        set_properties("Props", "adapted_properties")

        return obj

    def _serialize_que(self, metadata, values):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
        if not isinstance(metadata, QueueMeta):
            metadata = QueueMeta(name=metadata.name,
                                 optional=metadata.optional)
        self._create_tn(obj, metadata.list_types)

        que = ET.SubElement(obj, "QUE")
        while True:
            try:
                value = values.get(block=False)
                self.serialize(value, metadata.list_value_meta, parent=que,
                               clear=False)
            except Empty:
                break

        return obj

    def _serialize_stk(self, metadata, values):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
        self._create_tn(obj, metadata.list_types)

        stk = ET.SubElement(obj, "STK")
        while True:
            try:
                value = values.pop()
                self.serialize(value, metadata.list_value_meta, parent=stk,
                               clear=False)
            except IndexError:
                break

        return obj

    def _serialize_ie(self, metadata, values):
        return self._serialize_lst(metadata, values, tag="IE")

    def _serialize_lst(self, metadata, values, tag="LST"):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
        if not isinstance(metadata, ListMeta):
            metadata = ListMeta(name=metadata.name,
                                optional=metadata.optional)
        self._create_tn(obj, metadata.list_types)

        lst = ET.SubElement(obj, tag)
        for value in iter(values):
            entry_meta = copy(metadata.list_value_meta)
            self.serialize(value, entry_meta, parent=lst,
                           clear=False)

        return obj

    def _serialize_dct(self, metadata, values):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
        if not isinstance(metadata, DictionaryMeta):
            metadata = DictionaryMeta(name=metadata.name,
                                      optional=metadata.optional)
        self._create_tn(obj, metadata.dict_types)

        dct = ET.SubElement(obj, "DCT")

        # allow dicts to be defined as a tuple so that the order is kept
        if isinstance(values, tuple):
            iterator = values
        else:
            iterator = values.items()

        for key, value in iterator:
            en = ET.SubElement(dct, "En")
            key_meta = copy(metadata.dict_key_meta)
            value_meta = copy(metadata.dict_value_meta)
            self.serialize(key, key_meta, parent=en, clear=False)
            self.serialize(value, value_meta, parent=en, clear=False)

        return obj

    def _deserialize_obj(self, element, metadata):
        obj = metadata.object()
        self.obj[element.attrib['RefId']] = obj

        to_string_value = element.find("ToString")
        if to_string_value is not None:
            obj._to_string = self._deserialize_string(to_string_value.text)

        def deserialize_property(prop_tag, properties):
            for attr, property_meta in properties:
                if attr == "invocation_info":
                    a = ""
                property_name = "Unknown"
                property_filter = ""
                if property_meta.name is not None:
                    property_name = property_meta.name
                    property_filter = "[@N='%s']" % property_meta.name

                tags = [property_meta.tag]
                # The below tags are actually seen as Obj in the parent element
                if property_meta.tag in ["DCT", "LST", "IE", "QUE", "STK",
                                         "ObjDynamic"]:
                    tags = ["Obj", "Ref"]

                val = None
                for tag in tags:
                    val = element.find("%s%s%s" % (prop_tag, tag,
                                                   property_filter))
                    if val is not None:
                        break

                if val is None and not property_meta.optional:
                    val = element.find("%sNil%s" % (prop_tag, property_filter))
                    if val is None:
                        obj_name = str(obj) if obj._to_string is not None \
                            else "Unknown"
                        err_msg = "Mandatory return value for '%s' was not " \
                                  "found on object %s"\
                                  % (property_name, obj_name)
                        raise SerializationError(err_msg)
                    val = None
                elif val is not None:
                    val = self.deserialize(val, property_meta, clear=False)

                setattr(obj, attr, val)

        deserialize_property("", obj._property_sets)
        deserialize_property("Props/", obj._adapted_properties)
        deserialize_property("MS/", obj._extended_properties)

        return obj

    def _deserialize_dynamic_obj(self, element, metadata):
        obj = metadata.object()
        self.obj[element.attrib['RefId']] = obj

        for obj_property in element:
            if obj_property.tag == "TN":
                for obj_type in obj_property:
                    obj.types.append(obj_type.text)
                self.tn[obj_property.attrib['RefId']] = obj.types
            elif obj_property.tag == "TNRef":
                obj.types = self.tn[obj_property.attrib['RefId']]
            elif obj_property.tag == "Props":
                for adapted_property in obj_property:
                    key = adapted_property.attrib['N']
                    value = self.deserialize(adapted_property, clear=False)
                    obj.adapted_properties[key] = value
            elif obj_property.tag == "MS":
                for extended_property in obj_property:
                    key = extended_property.attrib['N']
                    value = self.deserialize(extended_property, clear=False)
                    obj.extended_properties[key] = value
            elif obj_property.tag == "ToString":
                value = self.deserialize(obj_property, clear=False)
                obj.to_string = value
            else:
                value = self.deserialize(obj_property, clear=False)
                obj.property_sets.append(value)

        return obj

    def _deserialize_lst(self, element, metadata=None):
        list_value = []
        value_meta = getattr(metadata, "list_value_meta", None)

        entries = element.find("LST")
        for entry in entries:
            entry_value = self.deserialize(entry, value_meta, clear=False)
            list_value.append(entry_value)

        return list_value

    def _deserialize_que(self, element):
        queue = Queue()

        entries = element.find("QUE")
        for entry in entries:
            entry_value = self.deserialize(entry, clear=False)
            queue.put(entry_value)

        return queue

    def _deserialize_stk(self, element):
        # no native Stack object in Python so just use a list
        stack = []

        entries = element.find("STK")
        for entry in entries:
            entry_value = self.deserialize(entry, clear=False)
            stack.append(entry_value)

        return stack

    def _deserialize_dct(self, element):
        dictionary = {}
        entries = element.findall("DCT/En")
        for entry in entries:
            key = entry.find("*[@N='Key']")
            value = entry.find("*[@N='Value']")

            key = self.deserialize(key, clear=False)
            value = self.deserialize(value, clear=False)
            dictionary[key] = value

        return dictionary

    def _create_tn(self, parent, types):
        main_type = types[0]
        ref_id = self.tn.get(main_type, None)
        if ref_id is None:
            ref_id = self.tn_id
            self.tn_id += 1
            self.tn[main_type] = ref_id

            tn = ET.SubElement(parent, "TN", RefId=str(ref_id))
            for type_name in types:
                ET.SubElement(tn, "T").text = type_name
        else:
            ET.SubElement(parent, "TNRef", RefId=str(ref_id))

    def _create_obj(self, parent, obj, key=None, meta=None):
        if isinstance(obj, ComplexObject):
            for ref, value in self.obj.items():
                if value == obj:
                    sub_element = ET.SubElement(parent, "Ref", RefId=ref)
                    if key is not None:
                        sub_element.attrib["N"] = key
                    return

        if meta is None:
            meta = ObjectMeta(name=key)
        self.serialize(obj, metadata=meta, parent=parent, clear=False)


class SerializerV2(_SerializerBase):
    """The Python object serializer.

    This is the new and improved serializer that is used to convert Python objects to CLIXML and vice versa. It should
    be used over Serializer() as it is able to handle more Python objects than before as well as providing a simpler
    interface for serializing to specific .NET types. A SerializerV2() instance should not be reused for multiple
    messages.

    See the `examples` folder for more information on how to create your own objects or how to deal with deserialized
    objects.
    """

    def serialize(self, value):  # type: (any) -> ET.Element
        """ Serialize a Python object to a XML element based on the CLIXML value. """
        if value is None:
            return ET.Element("Nil")
        elif isinstance(value, bool):
            element = ET.Element('B')
            element.text = to_unicode(str(value).lower())
        elif isinstance(value, (PSByteArray, binary_type)):
            element = ET.Element('BA')
            element.text = to_unicode(base64.b64encode(value))
        elif isinstance(value, (PSDateTime, datetime.datetime)):
            element = ET.Element('DT')
            element.text = self._serialize_datetime(value)
        elif isinstance(value, (PSGuid, uuid.UUID)):
            element = ET.Element('G')
            element.text = to_unicode(str(value))

        # Integer types
        elif isinstance(value, PSChar):
            element = ET.Element('C')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSSByte):
            element = ET.Element('SB')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSInt16):
            element = ET.Element('I16')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSInt64):
            element = ET.Element('I64')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSByte):
            element = ET.Element('By')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSUInt16):
            element = ET.Element('U16')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSUInt):
            element = ET.Element('U32')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSUInt64):
            element = ET.Element('U64')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, (PSInt, integer_types)):
            element = ET.Element('I32')
            element.text = to_unicode(str(int(value)))
        elif isinstance(value, PSDouble):
            element = ET.Element('Db')
            element.text = to_unicode(str(value)).upper()
        elif isinstance(value, (PSSingle, float)):
            element = ET.Element('Sg')
            element.text = to_unicode(str(value)).upper()
        elif isinstance(value, (PSDecimal, Decimal)):
            element = ET.Element('D')
            element.text = to_unicode(str(value))

        # String types
        elif isinstance(value, PSDuration):
            element = ET.Element('TS')
            element.text = to_unicode(value)
        elif isinstance(value, PSScriptBlock):
            element = ET.Element('SBK')
            element.text = self._serialize_string(value)
        elif isinstance(value, PSSecureString):
            element = ET.Element('SS')
            element.text = self._serialize_secure_string(value)
        elif isinstance(value, PSUri):
            element = ET.Element('URI')
            element.text = self._serialize_string(value)
        elif isinstance(value, PSVersion):
            element = ET.Element('Version')
            element.text = to_unicode(str(value))
        elif isinstance(value, PSXml):
            element = ET.Element('XD')
            element.text = self._serialize_string(value)

        elif isinstance(value, (PSString, text_type)):
            element = ET.Element('S')
            element.text = self._serialize_string(value)

        else:
            # Any remaining types are considered a complex object.
            element = ET.Element('Obj', RefId=self._get_obj_id(obj=value))

        if element.tag == 'Obj' or isinstance(value, PSEnumBase) or \
                (isinstance(value, PSObject) and
                 (value.PSObject.adapted_properties or value.PSObject.extended_properties)):
            is_complex = element.tag == 'Obj'
            # Default to a PSCustomObject if the value does not already have a PSObject attribute on it.
            ps_object = getattr(value, 'PSObject', PSCustomObject.PSObject)

            # Check if the value is a primitive type with extra properties and make sure we wrap it inside an Obj.
            if not is_complex or isinstance(value, PSEnumBase):
                sub_element = element
                element = ET.Element('Obj', RefId=self._get_obj_id(obj=value))
                element.append(sub_element)

            # Only add the type names if not a primitive object or explicit type_names were set on the PSObject.
            if ps_object.type_names and ps_object.tag == 'Obj':
                type_names = ps_object.type_names
                main_type = type_names[0]
                ref_id = self.tn.get(main_type, None)
                if ref_id is None:
                    ref_id = self.tn_id
                    self.tn_id += 1
                    self.tn[main_type] = ref_id

                    tn = ET.SubElement(element, "TN", RefId=str(ref_id))
                    for type_name in type_names:
                        ET.SubElement(tn, "T").text = type_name
                else:
                    ET.SubElement(element, "TNRef", RefId=str(ref_id))

            no_props = True
            for xml_name, properties in [('Props', ps_object.adapted_properties),
                                         ('MS', ps_object.extended_properties)]:
                if not properties:
                    continue

                no_props = False
                prop_elements = ET.SubElement(element, xml_name)
                for prop in properties:
                    prop_value = prop.value

                    # If it's an optional property and the value is not set, omit it from the CLIXML.
                    if prop_value is None and prop.optional:
                        continue

                    # Cast it to the proper type.
                    elif prop_value is not None and prop.ps_type:
                        prop_value = prop.ps_type(prop_value)

                    # If the value is a function/lambda, get the real value.
                    elif callable(prop_value):
                        prop_value = prop_value()

                    prop_element = self.serialize(prop_value)
                    prop_element.attrib['N'] = self._serialize_string(prop.name)
                    prop_elements.append(prop_element)

            if isinstance(value, PSStack):
                stk_element = ET.SubElement(element, 'STK')

                for stk_entry in value:
                    stk_element.append(self.serialize(stk_entry))

            elif isinstance(value, (PSQueue, Queue)):
                que_element = ET.SubElement(element, 'QUE')

                while True:
                    try:
                        que_entry = self.serialize(value.get(block=False))
                    except Empty:
                        break
                    else:
                        que_element.append(que_entry)

            elif isinstance(value, (PSList, list)):
                lst_element = ET.SubElement(element, 'LST')

                for lst_entry in value:
                    lst_element.append(self.serialize(lst_entry))

            elif isinstance(value, (PSDict, dict)):
                dct_element = ET.SubElement(element, 'DCT')

                for dct_key, dct_value in value.items():
                    en_element = ET.SubElement(dct_element, 'En')

                    s_dct_key = self.serialize(dct_key)
                    s_dct_key.attrib['N'] = 'Key'
                    en_element.append(s_dct_key)

                    s_dct_value = self.serialize(dct_value)
                    s_dct_value.attrib['N'] = 'Value'
                    en_element.append(s_dct_value)

            else:
                # ToString should only be set if explicitly defined or if not a primitive object.
                if is_complex or ps_object.to_string or isinstance(value, PSEnumBase):
                    try:
                        to_string_value = ps_object.to_string or str(value)
                    except Exception:
                        to_string_value = None  # in case __str__ raises an exception, don't include it

                    ET.SubElement(element, 'ToString').text = self._serialize_string(to_string_value)

                if is_complex and no_props and not isinstance(value, PSObject):
                    # If this was a complex object but no properties were defined we consider this a normal Python
                    # class instance to serialize. We use the instance attributes and properties to create the CLIXML.
                    prop_element = None
                    for prop in dir(value):
                        prop_value = getattr(value, prop)

                        if prop == 'PSObject' or prop.startswith('__') or callable(prop_value):
                            continue

                        elif not prop_element:
                            prop_element = ET.SubElement(element, 'MS')

                        sub_element = self.serialize(prop_value)
                        sub_element.attrib['N'] = self._serialize_string(prop)
                        prop_element.append(sub_element)

        return element

    def deserialize(self, element):  # type: (ET.Element) -> any
        """ Deserializes a XML element of the CLIXML value to a Python type. """
        # These types are pure primitive types and we don't need to do anything special when de-serializing
        if element.tag == 'ToString':
            return self._deserialize_string(element.text)
        elif element.tag == 'Nil':
            return None
        elif element.tag == 'B':
            # Technically can be an extended primitive but due to limitations in Python we cannot subclass bool.
            return element.text.lower() == "true"
        elif element.tag == 'Ref':
            return self.obj[element.attrib['RefId']]

        if element.tag == 'By':
            value = PSByte(element.text)
        elif element.tag == 'BA':
            value = PSByteArray(base64.b64decode(element.text))
        elif element.tag == 'C':
            value = PSChar(int(element.text))
        elif element.tag == 'DT':
            value = self._deserialize_datetime(element.text)
        elif element.tag == 'D':
            value = PSDecimal(element.text)
        elif element.tag == 'Db':
            value = PSDouble(element.text)
        elif element.tag == 'TS':
            value = PSDuration(element.text)
        elif element.tag == 'G':
            value = PSGuid(element.text)
        elif element.tag == 'I16':
            value = PSInt16(element.text)
        elif element.tag == 'I32':
            value = PSInt(element.text)
        elif element.tag == 'I64':
            value = PSInt64(element.text)
        elif element.tag == 'SB':
            value = PSSByte(element.text)
        elif element.tag == 'SBK':
            value = PSScriptBlock(self._deserialize_string(element.text))
        elif element.tag == 'SS':
            value = PSSecureString(self._deserialize_secure_string(element))
        elif element.tag == 'Sg':
            value = PSSingle(element.text)
        elif element.tag == 'S':
            value = PSString(self._deserialize_string(element.text))
        elif element.tag == 'U16':
            value = PSUInt16(element.text)
        elif element.tag == 'U32':
            value = PSUInt(element.text)
        elif element.tag == 'U64':
            value = PSUInt64(element.text)
        elif element.tag == 'URI':
            value = PSUri(self._deserialize_string(element.text))
        elif element.tag == 'Version':
            value = PSVersion(element.text)
        elif element.tag == 'XD':
            value = PSXml(self._deserialize_string(element.text))
        elif element.tag == 'Obj':
            value = TypeRegistry().rehydrate(self._get_types_from_obj(element))

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

                elif obj_entry.tag == 'DCT':
                    value = PSDict([(self.deserialize(dict_entry.find('*/[@N="Key"]')),
                                     self.deserialize(dict_entry.find('*/[@N="Value"]')))
                                    for dict_entry in obj_entry])

                elif obj_entry.tag == 'STK':
                    value = PSStack([self.deserialize(stack_entry) for stack_entry in obj_entry])

                elif obj_entry.tag == 'QUE':
                    value = PSQueue()
                    for queue_entry in obj_entry:
                        value.put(self.deserialize(queue_entry))

                elif obj_entry.tag in ['LST', 'IE']:
                    value = PSList([self.deserialize(list_entry) for list_entry in obj_entry])

                elif obj_entry.tag != 'TN':
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
                for prop_group_name, prop_xml in props.items():
                    if prop_xml is None:
                        continue

                    existing_properties = dict((p.name, p) for p in getattr(value.PSObject, prop_group_name))

                    for obj_property in prop_xml:
                        prop_name = self._deserialize_string(obj_property.attrib['N'])
                        prop_value = self.deserialize(obj_property)

                        # Check if the value's PSObject already has the property defined and use those values,
                        # otherwise add a new property.
                        if prop_name in existing_properties:
                            prop_info = existing_properties[prop_name]

                        else:
                            prop_info = PSPropertyInfo(prop_name, ps_type=type(prop_value))

                        prop_info.value = prop_value
                        getattr(value.PSObject, prop_group_name).append(prop_info)
        else:
            raise ValueError("Unknown element found: %s" % element.tag)

        return value
