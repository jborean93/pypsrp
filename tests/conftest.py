import base64
import os
import re
import struct
import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import yaml

from pypsrp._utils import to_bytes, to_string
from pypsrp.exceptions import AuthenticationError, WinRMTransportError
from pypsrp.powershell import Fragment
from pypsrp.wsman import NAMESPACES, WSMan

from . import assert_xml_diff


class TransportFake(object):
    def __init__(self, test_name, server, port, username, password, ssl, path, auth):
        """
        This is a fake transport stub that takes in known requests and responds
        back with the already created response. This is used in cases when a
        real WinRM endpoint is not available or a fake one was requested for
        a predefined apth

        :param test_name: The name of the test which is used to get the
            messages to send to the server
        """
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.path = path
        self.auth = auth
        self.endpoint = "%s://%s:%d/%s" % ("https" if ssl else "http", server, port, path)
        self.session = None

        # used in the test only
        for key, value in NAMESPACES.items():
            ET.register_namespace(key, value)

        self._uuid_pattern = re.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
        self._test_name = test_name
        self._msg_counter = 0
        self._psrp_fragments = {}  # used to store PSRP fragments as they come in
        meta_path = os.path.join(os.path.dirname(__file__), "responses/%s.yml" % test_name)

        if os.path.exists(meta_path):
            with open(meta_path, "rb") as o:
                self._test_meta = yaml.load(o, Loader=yaml.SafeLoader)
        else:
            raise Exception("Test metadata yml file does not exist at %s" % meta_path)

        self._test_msg_key = "messages"

    def close(self):
        return

    def send(self, message):
        current_msg = self._test_meta[self._test_msg_key][self._msg_counter]
        actual = self._normalise_xml(message, generify=False, psrp_fragment_type="actual")
        expected = self._normalise_xml(
            current_msg["request"], overrides=current_msg.get("overrides", None), psrp_fragment_type="expected"
        )
        failure_msg = "Message %d request for test %s does not match expectation\nActual:   %s\nExpected: %s" % (
            self._msg_counter,
            self._test_name,
            actual,
            expected,
        )
        assert_xml_diff(actual, expected, msg=failure_msg)

        for obj_id in list(self._psrp_fragments.keys()):
            details = self._psrp_fragments[obj_id]
            if not details["end"]:
                continue

            fragment_ids = list(details["actual"].keys())
            fragment_ids.sort()

            actual_obj = b""
            expected_obj = b""
            for i in range(0, fragment_ids[-1] + 1):
                actual_obj += details["actual"][i]
                expected_obj += details["expected"][i]

            actual_destination = struct.unpack("<I", actual_obj[:4])[0]
            actual_message_type = struct.unpack("<I", actual_obj[4:8])[0]
            actual_message = self._normalise_xml(actual_obj[40:], generify=False)
            expected_destination = struct.unpack("<I", expected_obj[:4])[0]
            expected_message_type = struct.unpack("<I", expected_obj[4:8])[0]
            expected_message = self._normalise_xml(expected_obj[40:], generify=False)

            assert actual_destination == expected_destination
            assert actual_message_type == expected_message_type

            # Only do the XML compare if the message had data, otherwise just
            # compare the actual values
            failure_msg = (
                "PSRP Message object %d for test %s does not match "
                "expectation\nActual:    %s\nExpected: %s" % (obj_id, self._test_name, actual_message, expected_message)
            )
            assert_xml_diff(actual_message, expected_message, msg=failure_msg)

            # Remove the fragments for the obj as we've verified them
            del self._psrp_fragments[obj_id]

        response = self._normalise_xml(current_msg["response"])
        self._msg_counter += 1

        # check if test metadata indicates we want to raise an exception here
        # instead of returning the response
        if "transport_error" in current_msg.keys():
            raise WinRMTransportError(
                current_msg["transport_error"]["protocol"], current_msg["transport_error"]["code"], response
            )
        elif current_msg.get("auth_error", False):
            raise AuthenticationError("Failed to authenticate the user %s with %s" % (self.username, self.auth))

        if "timeout" in current_msg.keys():
            time.sleep(current_msg["timeout"])

        return response

    def _normalise_xml(self, xml, generify=True, overrides=None, psrp_fragment_type=None):
        if not xml:
            return xml

        overrides = overrides if overrides is not None else []

        if generify:
            # convert all UUID values to the blank UUID
            xml = re.sub(self._uuid_pattern, "00000000-0000-0000-0000-000000000000", xml)

            xml_obj = ET.fromstring(to_bytes(xml))

            # convert the To hostname in the headers to the generic one
            to_field = xml_obj.find("s:Header/wsa:To", NAMESPACES)
            if to_field is not None:
                to_field.text = self.endpoint

            for override in overrides:
                override_element = xml_obj.find(override["path"], NAMESPACES)
                if override.get("text"):
                    override_element.text = override["text"]
                attributes = override.get("attributes", {})
                for attr_key, attr_value in attributes.items():
                    override_element.attrib[attr_key] = attr_value
        else:
            xml_obj = ET.fromstring(to_bytes(xml))

        # PSRP message contain another set of XML messages that have been
        # base64 encoded. We need to strip these out and compare them
        # separately once all the fragments have been received.
        if psrp_fragment_type:
            creation_xml = xml_obj.find(
                "s:Body/rsp:Shell/{http://schemas.microsoft.com/powershell}creationXml", NAMESPACES
            )
            if creation_xml is not None:
                creation_xml.text = self._generify_fragment(creation_xml.text, psrp_fragment_type)

            connect_xml = xml_obj.find("s:Body/rsp:Connect/pwsh:connectXml", NAMESPACES)
            if connect_xml is not None:
                connect_xml.text = self._generify_fragment(connect_xml.text, psrp_fragment_type)

            # when resource uri is PowerShell we know the Send/Command messages
            # contain PSRP fragments and we need to generify them
            exp_res_uri = "http://schemas.microsoft.com/powershell/"
            res_uri = xml_obj.find("s:Header/wsman:ResourceURI", NAMESPACES)
            if res_uri is not None:
                res_uri = res_uri.text

            streams = xml_obj.findall("s:Body/rsp:Send/rsp:Stream", NAMESPACES)
            if res_uri is not None and res_uri.startswith(exp_res_uri) and len(streams) > 0:
                for stream in streams:
                    stream.text = self._generify_fragment(stream.text, psrp_fragment_type)

            command = xml_obj.find("s:Body/rsp:CommandLine/rsp:Arguments", NAMESPACES)
            if res_uri is not None and res_uri.startswith(exp_res_uri) and command is not None:
                command.text = self._generify_fragment(command.text, psrp_fragment_type)

        return to_string(ET.tostring(xml_obj, encoding="utf-8"))

    def _simplify_namespaces(self, namespaces, element):
        namespaces.update(element.nsmap)

        tag_details = element.tag.split("}", 1)
        if len(tag_details) < 2:
            new_tag = element.tag
        else:
            ns = tag_details[0][1:]
            namespace_tag = namespaces.keys()[namespaces.values().index(ns)]
            new_tag = "%s:%s" % (namespace_tag, tag_details[1])

        new_attributes = {}
        for key, value in element.attrib.items():
            new_attributes[key] = value

        new_element = ET.Element(new_tag, attrib=new_attributes)
        new_element.text = element.text

        for child_element in element:
            new_child = self._simplify_namespaces(namespaces, child_element)
            new_element.append(new_child)

        return new_element

    def _generify_fragment(self, fragment, fragment_type):
        f_data = base64.b64decode(fragment)
        new_value = b""
        idx = 0

        while idx < len(f_data):
            frag = Fragment.unpack(f_data[idx:])[0]

            length = struct.unpack(">I", f_data[idx + 17 : idx + 21])[0]
            m_data = f_data[idx + 21 : idx + length + 21]

            # We store the fragments for later comparison
            fragment_buffer = self._psrp_fragments.get(frag.object_id, None)
            if fragment_buffer is None:
                fragment_buffer = {"actual": {}, "expected": {}, "end": False}
                self._psrp_fragments[frag.object_id] = fragment_buffer

            fragment_buffer[fragment_type][frag.fragment_id] = m_data
            if frag.end:
                fragment_buffer["end"] = True

            # We don't add the actual message to make the initial message
            # comparison easier
            new_value += f_data[idx : idx + 21]
            idx += length + 21
        return base64.b64encode(new_value).decode("utf-8")


@pytest.fixture(scope="function")
def wsman_conn(request, monkeypatch):
    test_params = request.param
    if not isinstance(test_params, list) or len(test_params) != 2:
        raise Exception("Cannot run winrm_transport fixture without the allow real and test name set")

    allow_real = test_params[0]
    test_name = test_params[1]

    # these need to be set to run against a proper server
    username = os.environ.get("PYPSRP_USERNAME", None)
    password = os.environ.get("PYPSRP_PASSWORD", None)
    server = os.environ.get("PYPSRP_SERVER", None)

    # these are optional vars that can further control the transport setup
    auth = os.environ.get("PYPSRP_AUTH", "negotiate")
    port = int(os.environ.get("PYPSRP_PORT", "5986"))
    ssl = port != 5985

    if allow_real and username is not None and password is not None and server is not None:
        wsman = WSMan(
            server, port=port, username=username, password=password, ssl=ssl, auth=auth, cert_validation=False
        )
    else:
        # Mock out UUID's so they are not a problem when comparing messages
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")

        monkeypatch.setattr(uuid, "uuid4", mockuuid)
        transport = TransportFake(test_name, "fakehost", port, "username", "password", ssl, "wsman", auth)
        wsman = WSMan("")
        wsman.transport = transport

    with wsman:
        yield wsman

    # used as an easy way to be results for a test, requires the _test_messages
    # to be uncommented in pypsrp/wsman.py
    test_messages = getattr(wsman.transport, "_test_messages", None)
    if test_messages is not None:
        yaml_text = yaml.dump({"messages": test_messages}, default_flow_style=False, width=9999)
        print(yaml_text)
