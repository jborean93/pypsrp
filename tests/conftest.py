import base64
import os
import re
import struct
import sys
import time
import uuid
import yaml

import pytest

from pypsrp.exceptions import AuthenticationError, WinRMTransportError
from pypsrp.transport import TransportHTTP
from pypsrp.wsman import NAMESPACES
from pypsrp._utils import to_bytes, to_string

import xml.etree.ElementTree as ETNew
if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET


class TransportFake(object):

    def __init__(self, test_name, server, port, username, password, ssl, path,
                 auth):
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
        self.endpoint = "%s://%s:%d/%s" \
                        % ("https" if ssl else "http", server, port, path)
        self.session = None

        # used in the test only
        for key, value in NAMESPACES.items():
            ET.register_namespace(key, value)

        self._uuid_pattern = re.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]"
                                        "{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
        self._test_name = test_name
        self._msg_counter = 0
        meta_path = os.path.join(os.path.dirname(__file__),
                                 'responses/%s.yml' % test_name)

        if os.path.exists(meta_path):
            with open(meta_path, 'rb') as o:
                self._test_meta = yaml.load(o)
        else:
            raise Exception("Test metadata yml file does not exist at %s"
                            % meta_path)

        # override the messages used if a particular python version is set
        # lxml serializes messages a bit differently which is quite
        # problemtatic for the PSRP messages embeded in the WSMAN bodies
        current_version = "%s%s" % (sys.version_info[0], sys.version_info[1])
        node_entries = self._test_meta.keys()
        if "messages-py%s" % current_version in node_entries:
            self._test_msg_key = "messages-py%s" % current_version
        else:
            self._test_msg_key = "messages"

    def send(self, message):
        current_msg = self._test_meta[self._test_msg_key][self._msg_counter]
        message = self._normalise_xml(message, generify=False)
        request = self._normalise_xml(
            current_msg['request'],
            overrides=current_msg.get('overrides', None)
        )
        response = self._normalise_xml(current_msg['response'])
        assert message == request, "Message %d request for test %s does not " \
                                   "match expectation\nActual:   %s\n" \
                                   "Expected: %s" % (self._msg_counter,
                                                     self._test_name,
                                                     message, request)
        self._msg_counter += 1

        # check if test metadata indicates we want to raise an exception here
        # instead of returning the response
        if 'transport_error' in current_msg.keys():
            raise WinRMTransportError(
                current_msg['transport_error']['protocol'],
                current_msg['transport_error']['code'], response
            )
        elif current_msg.get('auth_error', False):
            raise AuthenticationError("Failed to authenticate the user %s "
                                      "with %s" % (self.username, self.auth))

        if 'timeout' in current_msg.keys():
            time.sleep(current_msg['timeout'])

        return response

    def _normalise_xml(self, xml, generify=True, overrides=None):
        overrides = overrides if overrides is not None else []

        if generify:
            # convert all UUID values to the blank UUID
            xml = re.sub(self._uuid_pattern,
                         "00000000-0000-0000-0000-000000000000", xml)

            xml_obj = ET.fromstring(to_bytes(xml))

            # convert the To hostname in the headers to the generic one
            to_field = xml_obj.find("s:Header/wsa:To", NAMESPACES)
            if to_field is not None:
                to_field.text = self.endpoint

            for override in overrides:
                override_element = xml_obj.find(override['path'], NAMESPACES)
                if override.get('text'):
                    override_element.text = override['text']
                attributes = override.get('attributes', {})
                for attr_key, attr_value in attributes.items():
                    override_element.attrib[attr_key] = attr_value

            # PSRP messages contain the runspace and pipeline ID that is
            # base64 encoded, this needs to be converted back to \x00 * 16
            # for mock test
            creation_xml = xml_obj.find("s:Body/rsp:Shell/{http://schemas."
                                        "microsoft.com/powershell}creationXml",
                                        NAMESPACES)
            if creation_xml is not None:
                self._generify_fragment(creation_xml)

            connect_xml = xml_obj.find("s:Body/rsp:Connect/pwsh:connectXml",
                                       NAMESPACES)
            if connect_xml is not None:
                self._generify_fragment(connect_xml)

            # when resource uri is PowerShell we know the Send/Command messages
            # contain PSRP fragments and we need to generify them
            exp_res_uri = "http://schemas.microsoft.com/powershell/"
            res_uri = \
                xml_obj.find("s:Header/wsman:ResourceURI", NAMESPACES)
            if res_uri is not None:
                res_uri = res_uri.text

            streams = xml_obj.findall("s:Body/rsp:Send/rsp:Stream", NAMESPACES)
            if res_uri is not None and res_uri.startswith(exp_res_uri) and \
                    len(streams) > 0:
                for stream in streams:
                    self._generify_fragment(stream)

            command = xml_obj.find("s:Body/rsp:CommandLine/rsp:Arguments",
                                   NAMESPACES)
            if res_uri is not None and res_uri.startswith(exp_res_uri) and \
                    command is not None:
                self._generify_fragment(command)
        else:
            xml_obj = ET.fromstring(to_bytes(xml))

        # convert the string to an XML object, for Python 2.6 (lxml) we need
        # to change the namespace handling to mimic the ElementTree way of
        # working so the string compare works
        if sys.version_info[0] == 2 and sys.version_info[1] < 7:
            namespaces = {}
            new_xml_obj = self._simplify_namespaces(namespaces, xml_obj)
            for key, value in namespaces.items():
                new_xml_obj.attrib["xmlns:%s" % key] = value

            xml_obj = new_xml_obj

        return to_string(ETNew.tostring(xml_obj, encoding='utf-8'))

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

        new_element = ETNew.Element(new_tag, attrib=new_attributes)
        new_element.text = element.text

        for child_element in element:
            new_child = self._simplify_namespaces(namespaces, child_element)
            new_element.append(new_child)

        return new_element

    def _generify_fragment(self, element):
        f_data = base64.b64decode(element.text)
        new_value = b""
        while len(new_value) != len(f_data):
            idx = len(new_value)
            length = struct.unpack(">I", f_data[idx + 17:idx + 21])[0]
            start_end_byte = \
                struct.unpack("B", f_data[idx + 16:idx + 17])[0]
            start = start_end_byte & 0x1 == 0x1
            m_data = f_data[idx + 21:idx + length + 21]

            if start:
                # replace the pid and rpid with \x00 * 16
                m_data = m_data[0:8] + b"\x00" * 32 + m_data[40:]

            new_value += f_data[idx:idx + 21] + m_data
        element.text = base64.b64encode(new_value).decode('utf-8')


@pytest.fixture(scope='module')
def winrm_transport(request, monkeypatch):
    test_params = request.param
    if not isinstance(test_params, list) or len(test_params) != 2:
        raise Exception("Cannot run winrm_transport fixture without the "
                        "allow real and test name set")

    allow_real = test_params[0]
    test_name = test_params[1]

    # these need to be set to run against a proper server
    username = os.environ.get('PYPSRP_USERNAME', None)
    password = os.environ.get('PYPSRP_PASSWORD', None)
    server = os.environ.get('PYPSRP_SERVER', None)

    # these are optional vars that can further control the transport setup
    auth = os.environ.get('PYPSRP_AUTH', 'negotiate')
    port = int(os.environ.get('PYPSRP_PORT', '5986'))
    ssl = port != 5985

    if allow_real and username is not None and password is not None and \
            server is not None:
        transport = TransportHTTP(server, port, username, password, ssl,
                                  auth=auth, cert_validation=False)
    else:
        # Mock out UUID's so they are not a problem when comparing messages
        def mockuuid():
            return uuid.UUID("00000000-0000-0000-0000-000000000000")
        monkeypatch.setattr(uuid, 'uuid4', mockuuid)
        transport = TransportFake(test_name, "fakehost", port, "username",
                                  "password", ssl, "wsman", auth)
    yield transport

    # used as an easy way to be results for a test, requires the _test_messages
    # to be uncommented in pypsrp/transport.py
    test_messages = getattr(transport, '_test_messages', None)
    if test_messages is not None:
        yaml_text = yaml.dump({"messages-py26": test_messages},
                              default_flow_style=False,
                              width=9999)
        print(yaml_text)
