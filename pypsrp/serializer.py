# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import binascii
import logging
import sys
import uuid

from six import string_types

from pypsrp.complex_objects import ApartmentState, Color, Coordinates, \
    ComplexObject, DictionaryMeta, GenericComplexObject, \
    HostMethodIdentifier, InformationalRecord, ListMeta, ObjectMeta, \
    PipelineResultTypes, ProgressRecordType, PSThreadOptions, QueueMeta, \
    RemoteStreamOptions, Size, StackMeta
from pypsrp.exceptions import SerializationError
from pypsrp.messages import DebugRecord, ErrorRecord, InformationRecord, \
    VerboseRecord, WarningRecord
from pypsrp._utils import to_bytes, to_string, to_unicode

try:
    # used for Secure Strings and is an optional import with this library
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError:
    pass

try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
    element_type = ET.ElementBase
else:  # pragma: no cover
    import xml.etree.ElementTree as ET
    element_type = ET.Element

log = logging.getLogger(__name__)


class Serializer(object):

    def __init__(self):
        self.obj_id = 0
        self.obj = {}
        self.tn_id = 0
        self.tn = {}

        self.cipher = None

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
            'C': lambda m, d: ord(d),
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
            if isinstance(element_value, str):
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
            element = ET.fromstring(element)
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
            'C': lambda d: chr(d.text),
            'B': lambda d: d.text.lower() == "true",
            'DT': lambda d: None,
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
            'D': lambda d: None,
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
        if metadata.object is None:
            # TODO: Handle something like
            # System.Collections.Generic.List`1[[System.String, mscorlib,
            # Version=4.0.0.0, Culture=neutral,
            # PublicKeyToken=b77a5c561934e089]]
            structures = {
                "System.Array": ListMeta(),
                "System.Management.Automation.DebugRecord":
                    ObjectMeta("Obj", object=DebugRecord),
                "System.Management.Automation.ErrorRecord":
                    ObjectMeta("Obj", object=ErrorRecord),
                "System.Management.Automation.Host.Coordinates":
                    ObjectMeta("Obj", object=Coordinates),
                "System.Management.Automation.Host.Size":
                    ObjectMeta("Obj", object=Size),
                "System.Management.Automation.InformationalRecord":
                    ObjectMeta("Obj", object=InformationalRecord),
                "System.Management.Automation.InformationRecord":
                    ObjectMeta("Obj", object=InformationRecord),
                "System.Management.Automation.ProgressRecordType":
                    ObjectMeta("Obj", object=ProgressRecordType),
                "System.Management.Automation.PSPrimitiveDictionary":
                    DictionaryMeta(),
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
                "System.Management.Automation.VerboseRecord":
                    ObjectMeta("Obj", object=VerboseRecord),
                "System.Management.Automation.WarningRecord":
                    ObjectMeta("Obj", object=WarningRecord),
                "System.Collections.Hashtable": DictionaryMeta(),
                "System.Collections.Queue": QueueMeta(),
                "System.Collections.Stack": StackMeta(),
                "System.ConsoleColor": ObjectMeta("Obj", object=Color),

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
                # None: ObjectMeta("BA"), # Byte array base64e ncoded
                "System.Guid": ObjectMeta("G"),
                "System.Uri": ObjectMeta("URI"),
                "System.Version": ObjectMeta("Version"),
                "System.Xml.XmlDocument": ObjectMeta("XD"),
                "System.Management.Automation.ScriptBlock": ObjectMeta("SBK"),
                "System.Security.SecureString": ObjectMeta("SS"),
            }
            metadata = None
            for obj_type in obj_types:
                is_list = False
                if obj_type.endswith("[]"):
                    obj_type = obj_type[0:-2]
                    is_list = True

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
            obj = self._deserialize_lst(element)
        elif metadata.tag == "QUE":
            obj = self._deserialize_que(element)
        elif metadata.tag == "STK":
            obj = self._deserialize_stk(element)
        elif metadata.tag == "DCT":
            obj = self._deserialize_dct(element)
        else:
            # was a primitive type in an object so need to get the value
            # extended property in that object
            element = element.find("MS/%s[@N='V']" % metadata.tag)

            # couldn't find the value, just return the XML string
            if element is None:
                return element_string

            # TODO: Add to Obj RefId
            return self.deserialize(element, metadata, clear=False)

        if element.tag == "Obj":
            self.obj[element.attrib['RefId']] = obj

        if isinstance(obj, ComplexObject):
            obj._xml = element_string

        return obj

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
        elif value_type == uuid:
            return "G"
        elif value_type == list:
            return "LST"
        elif value_type == dict:
            return "DCT"
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
            self.serialize(attr_value, property_meta, parent=obj, clear=False)

        if len(value._extended_properties) > 0:
            ms = ET.SubElement(obj, "MS")
            for attr, property_meta in value._extended_properties:
                attr_value = getattr(value, attr)
                self.serialize(attr_value, property_meta, parent=ms,
                               clear=False)

        if len(value._adapted_properties) > 0:
            props = ET.SubElement(obj, "Props")
            for attr, property_meta in value._adapted_properties:
                attr_value = getattr(value, attr)
                self.serialize(attr_value, property_meta, parent=props,
                               clear=False)

        return obj

    def _serialize_dynamic_obj(self, metadata, value):
        obj = ET.Element("Obj", RefId=self._get_obj_id())

        if len(value.types) > 0:
            self._create_tn(obj, value.types)

        if value.to_string is not None:
            ET.SubElement(obj, "ToString").text = \
                self._serialize_string(value.to_string)

        for key, property in value.property_sets.items():
            metadata = ObjectMeta(name=key)
            self.serialize(property, metadata=metadata, parent=obj,
                           clear=False)

        if len(value.extended_properties.keys()) > 0:
            ms = ET.SubElement(obj, "MS")
            for key, property in value.extended_properties.items():
                metadata = ObjectMeta(name=key)
                self.serialize(property, metadata=metadata, parent=ms,
                               clear=False)

        if len(value.adapted_properties.keys()) > 0:
            props = ET.SubElement(obj, "Props")
            for key, property in value.adapted_properties.items():
                metadata = ObjectMeta(name=key)
                self.serialize(property, metadata=metadata, parent=props,
                               clear=False)

        return obj

    def _serialize_que(self, metadata, values):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
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
        self._create_tn(obj, metadata.list_types)

        lst = ET.SubElement(obj, tag)
        for value in iter(values):
            self.serialize(value, metadata.list_value_meta, parent=lst,
                           clear=False)

        return obj

    def _serialize_dct(self, metadata, values):
        obj = ET.Element("Obj", RefId=self._get_obj_id())
        self._create_tn(obj, metadata.dict_types)

        dct = ET.SubElement(obj, "DCT")

        # allow dicts to be defined as a tuple so that the order is kept
        if isinstance(values, tuple):
            iterator = values
        else:
            iterator = values.items()

        for key, value in iterator:
            en = ET.SubElement(dct, "En")
            self.serialize(key, metadata.dict_key_meta, parent=en,
                           clear=False)
            self.serialize(value, metadata.dict_value_meta, parent=en,
                           clear=False)

        return obj

    def _serialize_string(self, value):
        if sys.version_info[0] == 2:
            unichr_func = unichr
        else:
            unichr_func = chr

        char_ranges = [
            # C0 Control Chars - U+0000 - U+001F
            (0, 32),
            # C1 Control Chars - U+007F - U+009F
            (127, 160),
            # TODO: also encode UTF surrogate characters as well
        ]

        translation = {}
        for char_range in char_ranges:
            for i in range(char_range[0], char_range[1]):
                utf_bytes = to_bytes(unichr_func(i), encoding='utf-16-be')
                hex_string = binascii.hexlify(utf_bytes)
                translation[i] = '_x%s_' % to_string(hex_string)

        string_value = str(value)

        # before running the translation we need to make sure _ before x is
        # encoded, normally _ isn't encoded except when preceding x
        string_value = string_value.replace("_x", "_x005f_x")

        # now translate our string with the map provided
        string_value = to_unicode(string_value).translate(translation)

        return to_string(string_value)

    def _serialize_secure_string(self, value):
        if self.cipher is None:
            raise SerializationError("Cannot generate secure string as cipher "
                                     "is not initialised")

        # convert the string to a UTF-16 byte string as that is what is
        # expected in Windows. If a byte string (native string in Python 2) was
        # passed in, the sender must make sure it is a valid UTF-16
        # representation and not UTF-8 or else the server will fail to decrypt
        # the secure string in most cases
        string_bytes = to_bytes(value, encoding='utf-16-le')

        padder = PKCS7(self.cipher.algorithm.block_size).padder()
        padded_data = padder.update(string_bytes) + padder.finalize()

        encryptor = self.cipher.encryptor()
        ss_value = encryptor.update(padded_data) + encryptor.finalize()
        ss_string = to_string(base64.b64encode(ss_value))

        return ss_string

    def _deserialize_obj(self, element, metadata):
        obj = metadata.object()

        to_string_value = element.find("ToString")
        if to_string_value is not None:
            obj._to_string = self._deserialize_string(to_string_value.text)

        def deserialize_property(prop_tag, properties):
            for attr, property_meta in properties:
                property_filter = ""
                if property_meta.name is not None:
                    property_filter = "[@N='%s']" % property_meta.name

                tag = property_meta.tag
                # The below tags are actually seen as Obj in the parent element
                if tag in ["DCT", "LST", "IE", "QUE", "STK", "ObjDynamic"]:
                    tag = "Obj"
                val = element.find("%s%s%s" % (prop_tag, tag, property_filter))

                if val is None and not property_meta.optional:
                    val = element.find("%sNil%s" % (prop_tag, property_filter))
                    if val is None:
                        raise SerializationError(
                            "Mandatory return value was not found"
                        )
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

        for property in element:
            # TODO: what if TNRef is used instead
            if property.tag == "TN":
                for type in property:
                    obj.types.append(type.text)
            elif property.tag == "Props":
                for adapted_property in property:
                    key = adapted_property.attrib['N']
                    value = self.deserialize(adapted_property, clear=False)
                    obj.adapted_properties[key] = value
            elif property.tag == "MS":
                for extended_property in property:
                    key = extended_property.attrib['N']
                    value = self.deserialize(extended_property, clear=False)
                    obj.extended_properties[key] = value
            elif property.tag == "ToString":
                value = self.deserialize(property, clear=False)
                obj.to_string = value
            else:
                value = self.deserialize(property, clear=False)
                obj.property_sets.append(value)

        return obj

    def _deserialize_lst(self, element):
        list = []

        entries = element.find("LST")
        for entry in entries:
            entry_value = self.deserialize(entry, clear=False)
            list.append(entry_value)

        return list

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

    def _deserialize_string(self, value):
        # TODO: actually implement this
        return value

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

    def _clear(self):
        self.obj_id = 0
        self.obj = {}
        self.tn = {}
        self.tn_id = 0

    def _get_obj_id(self):
        ref_id = str(self.obj_id)
        self.obj_id += 1
        return ref_id

    def _get_types_from_obj(self, element):
        obj_types = [e.text for e in element.findall("TN/T")]

        if len(obj_types) > 0:
            ref_id = element.find("TN").attrib['RefId']
            self.tn[ref_id] = obj_types

        tn_ref = element.find("TNRef")
        if tn_ref is not None:
            ref_id = tn_ref.attrib['RefId']
            obj_types = self.tn[ref_id]

        # could be a Complex object like Size/Coordinates that set the type
        # with the <S N="T">type</S> extended property
        type_element = element.find("MS/S[@N='T']")
        if type_element is not None:
            obj_types.append(type_element.text)

        return obj_types

    def _create_tn(self, parent, types):
        main_type = types[0]
        ref_id = self.tn.get(main_type, None)
        if ref_id is None:
            ref_id = self.tn_id
            self.tn_id += 1
            self.tn[main_type] = ref_id

            tn = ET.SubElement(parent, "TN", RefId=str(ref_id))
            for type in types:
                ET.SubElement(tn, "T").text = type
        else:
            ET.SubElement(parent, "TNRef", RefId=str(ref_id))
