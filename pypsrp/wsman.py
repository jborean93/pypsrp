# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import division

import ipaddress
import logging
import re
import requests
import sys
import uuid
import warnings

from requests.packages.urllib3.util.retry import Retry

from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import AuthenticationError, WinRMError, \
    WinRMTransportError, WSManFaultError
from pypsrp.negotiate import HTTPNegotiateAuth
from pypsrp._utils import to_string, to_unicode, get_hostname

try:
    from requests_credssp import HttpCredSSPAuth
except ImportError as err:  # pragma: no cover
    _requests_credssp_import_error = (
        "Cannot use CredSSP auth as requests-credssp is not installed: %s"
        % err
    )

    class HttpCredSSPAuth(object):
        def __init__(self, *args, **kwargs):
            raise ImportError(_requests_credssp_import_error)

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

SUPPORTED_AUTHS = ["basic", "certificate", "credssp", "kerberos",
                   "negotiate", "ntlm"]

AUTH_KWARGS = {
    "certificate": ["certificate_key_pem", "certificate_pem"],
    "credssp": ["credssp_auth_mechanism", "credssp_disable_tlsv1_2",
                "credssp_minimum_version"],
    "negotiate": ["negotiate_delegate", "negotiate_hostname_override",
                  "negotiate_send_cbt", "negotiate_service"],
}

# [MS-WSMV] 2.2.1 Namespaces
# https://msdn.microsoft.com/en-us/library/ee878420.aspx
NAMESPACES = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "xs": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsman": "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "wsmid": "http://schemas.dmtf.org/wbem/wsman/identify/1/wsmanidentity.xsd",
    "wsmanfault": "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault",
    "cim": "http://schemas.dmtf.org/wbem/wscim/1/common",
    "wsmv": "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
    "cfg": "http://schemas.microsoft.com/wbem/wsman/1/config",
    "sub": "http://schemas.microsoft.com/wbem/wsman/1/subscription",
    "rsp": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "m": "http://schemas.microsoft.com/wbem/wsman/1/machineid",
    "cert": "http://schemas.microsoft.com/wbem/wsman/1/config/service/"
            "certmapping",
    "plugin": "http://schemas.microsoft.com/wbem/wsman/1/config/"
              "PluginConfiguration",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wsdl": "http://schemas.xmlsoap.org/wsdl",
    "wst": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
    "wsp": "http://schemas.xmlsoap.org/ws/2004/09/policy",
    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "i": "http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd",
    "xml": "http://www.w3.org/XML/1998/namespace",
    "pwsh": "http://schemas.microsoft.com/powershell",
}


class WSManAction(object):
    # WS-Management URIs
    GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
    GET_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
    PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
    PUT_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse"
    CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
    CREATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/" \
                      "CreateResponse"
    DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
    DELETE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/" \
                      "DeleteResponse"
    ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
    ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/" \
                         "EnumerateResponse"
    PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
    PULL_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/" \
                    "PullResponse"

    # MS-WSMV URIs
    COMMAND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
    COMMAND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/CommandResponse"
    CONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect"
    CONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/ConnectResponse"
    DISCONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
                 "Disconnect"
    DISCONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/" \
                          "windows/shell/DisconnectResponse"
    RECEIVE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
    RECEIVE_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                       "shell/ReceiveResponse"
    RECONNECT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/" \
                "Reconnect"
    RECONNECT_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                         "shell/ReconnectResponse"
    SEND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
    SEND_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                    "shell/SendResponse"
    SIGNAL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
    SIGNAL_RESPONSE = "http://schemas.microsoft.com/wbem/wsman/1/windows/" \
                      "shell/SignalResponse"


class WSMan(object):

    def __init__(self, server, max_envelope_size=153600, operation_timeout=20,
                 port=None, username=None, password=None, ssl=True,
                 path="wsman", auth="negotiate", cert_validation=True,
                 connection_timeout=30, encryption='auto', proxy=None,
                 no_proxy=False, locale='en-US', data_locale=None,
                 read_timeout=30, reconnection_retries=0,
                 reconnection_backoff=2.0, **kwargs):
        """
        Class that handles WSMan transport over HTTP. This exposes a method per
        action that takes in a resource and the header metadata required by
        that resource.

        This is required by the pypsrp.shell.WinRS and
        pypsrp.powershell.RunspacePool in order to connect to the remote host.
        It uses HTTP(S) to send data to the remote host.

        https://msdn.microsoft.com/en-us/library/cc251598.aspx

        :param server: The hostname or IP address of the host to connect to
        :param max_envelope_size: The maximum size of the envelope that can be
            sent to the server. Use update_max_envelope_size() to query the
            server for the true value
        :param max_envelope_size: The maximum size of a WSMan envelope that
            can be sent to the server
        :param operation_timeout: Indicates that the client expects a response
            or a fault within the specified time.
        :param port: The port to connect to, default is 5986 if ssl=True, else
            5985
        :param username: The username to connect with
        :param password: The password for the above username
        :param ssl: Whether to connect over http or https
        :param path: The WinRM path to connect to
        :param auth: The auth protocol to use; basic, certificate, negotiate,
            credssp. Can also specify ntlm or kerberos to limit the negotiate
            protocol
        :param cert_validation: Whether to validate the server's SSL cert
        :param connection_timeout: The timeout for connecting to the HTTP
            endpoint
        :param read_timeout: The timeout for receiving from the HTTP endpoint
        :param encryption: Controls the encryption setting, default is auto
            but can be set to always or never
        :param proxy: The proxy URL used to connect to the remote host
        :param no_proxy: Whether to ignore any environment proxy vars and
            connect directly to the host endpoint
        :param locale: The wsmv:Locale value to set on each WSMan request. This
            specifies the language in which the client wants response text to
            be translated. The value should be in the format described by
            RFC 3066, with the default being 'en-US'
        :param data_locale: The wsmv:DataLocale value to set on each WSMan
            request. This specifies the format in which numerical data is
            presented in the response text. The value should be in the format
            described by RFC 3066, with the default being the value of locale.
        :param int reconnection_retries: Number of retries on connection
            problems
        :param float reconnection_backoff: Number of seconds to backoff in
            between reconnection attempts (first sleeps X, then sleeps 2*X,
            4*X, 8*X, ...)
        :param kwargs: Dynamic kwargs based on the auth protocol set
            # auth='certificate'
            certificate_key_pem: The path to the cert key pem file
            certificate_pem: The path to the cert pem file

            # auth='credssp'
            credssp_auth_mechanism: The sub auth mechanism to use in CredSSP,
                default is 'auto' but can be 'ntlm' or 'kerberos'
            credssp_disable_tlsv1_2: Use TLSv1.0 instead of 1.2
            credssp_minimum_version: The minimum CredSSP server version to
                allow

            # auth in ['negotiate', 'ntlm', 'kerberos']
            negotiate_send_cbt: Whether to send the CBT token on HTTPS
                connections, default is True

            # the below are only relevant when kerberos (or nego used kerb)
            negotiate_delegate: Whether to delegate the Kerb token to extra
                servers (credential delegation), default is False
            negotiate_hostname_override: Override the hostname used when
                building the server SPN
            negotiate_service: Override the service used when building the
                server SPN, default='WSMAN'
        """
        log.debug("Initialising WSMan class with maximum envelope size of %d "
                  "and operation timeout of %s"
                  % (max_envelope_size, operation_timeout))
        self.session_id = str(uuid.uuid4())
        self.locale = locale
        self.data_locale = data_locale
        if self.data_locale is None:
            self.data_locale = self.locale
        self.transport = _TransportHTTP(server, port, username, password, ssl,
                                        path, auth, cert_validation,
                                        connection_timeout, encryption, proxy,
                                        no_proxy, read_timeout,
                                        reconnection_retries,
                                        reconnection_backoff, **kwargs)
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout

        # register well known namespace prefixes so ElementTree doesn't
        # randomly generate them, saving packet space
        for key, value in NAMESPACES.items():
            ET.register_namespace(key, value)

        # This is the approx max size of a Base64 string that can be sent in a
        # SOAP message payload (PSRP fragment or send input data) to the
        # server. This value is dependent on the server's MaxEnvelopSizekb
        # value set on the WinRM service and the default is different depending
        # on the Windows version. Server 2008 (R2) detaults to 150KiB while
        # newer hosts are 500 KiB and this can be configured manually. Because
        # we don't know the OS version before we connect, we set the default to
        # 150KiB to ensure we are compatible with older hosts. This can be
        # manually adjusted with the max_envelope_size param which is the
        # MaxEnvelopeSizekb value * 1024. Otherwise the
        # update_max_envelope_size() function can be called and it will gather
        # this information for you.
        self.max_payload_size = self._calc_envelope_size(max_envelope_size)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def command(self, resource_uri, resource, option_set=None,
                selector_set=None, timeout=None):
        res = self.invoke(WSManAction.COMMAND, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def connect(self, resource_uri, resource, option_set=None,
                selector_set=None, timeout=None):
        res = self.invoke(WSManAction.CONNECT, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def create(self, resource_uri, resource, option_set=None,
               selector_set=None, timeout=None):
        res = self.invoke(WSManAction.CREATE, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def disconnect(self, resource_uri, resource, option_set=None,
                   selector_set=None, timeout=None):
        res = self.invoke(WSManAction.DISCONNECT, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def delete(self, resource_uri, resource=None, option_set=None,
               selector_set=None, timeout=None):
        res = self.invoke(WSManAction.DELETE, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def enumerate(self, resource_uri, resource=None, option_set=None,
                  selector_set=None, timeout=None):
        res = self.invoke(WSManAction.ENUMERATE, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def get(self, resource_uri, resource=None, option_set=None,
            selector_set=None, timeout=None):
        res = self.invoke(WSManAction.GET, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def pull(self, resource_uri, resource=None, option_set=None,
             selector_set=None, timeout=None):
        res = self.invoke(WSManAction.PULL, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def put(self, resource_uri, resource=None, option_set=None,
            selector_set=None, timeout=None):
        res = self.invoke(WSManAction.PUT, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def receive(self, resource_uri, resource, option_set=None,
                selector_set=None, timeout=None):
        res = self.invoke(WSManAction.RECEIVE, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def reconnect(self, resource_uri, resource=None, option_set=None,
                  selector_set=None, timeout=None):
        res = self.invoke(WSManAction.RECONNECT, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def send(self, resource_uri, resource, option_set=None,
             selector_set=None, timeout=None):
        res = self.invoke(WSManAction.SEND, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def signal(self, resource_uri, resource, option_set=None,
               selector_set=None, timeout=None):
        res = self.invoke(WSManAction.SIGNAL, resource_uri, resource,
                          option_set, selector_set, timeout)
        return res.find("s:Body", namespaces=NAMESPACES)

    def get_server_config(self, uri="config"):
        resource_uri = "http://schemas.microsoft.com/wbem/wsman/1/%s" % uri
        log.debug("Getting server config with URI %s" % resource_uri)
        return self.get(resource_uri)

    def update_max_payload_size(self, max_payload_size=None):
        """
        Updates the MaxEnvelopeSize set on the current WSMan object for all
        future requests.

        :param max_payload_size: The max size specified in bytes, if not set
            then the max size if retrieved dynamically from the server
        """
        if max_payload_size is None:
            config = self.get_server_config()
            max_size_kb = config.find("cfg:Config/"
                                      "cfg:MaxEnvelopeSizekb",
                                      namespaces=NAMESPACES).text
            max_payload_size = int(max_size_kb) * 1024

        max_envelope_size = self._calc_envelope_size(max_payload_size)
        self.max_envelope_size = max_payload_size
        self.max_payload_size = max_envelope_size

    def invoke(self, action, resource_uri, resource, option_set=None,
               selector_set=None, timeout=None):
        """
        Send a generic WSMan request to the host.

        :param action: The action to run, this relates to the wsa:Action header
            field.
        :param resource_uri: The resource URI that the action relates to, this
          relates to the wsman:ResourceURI header field.
        :param resource: This is an optional xml.etree.ElementTree Element to
            be added to the s:Body section.
        :param option_set: a wsman.OptionSet to add to the request
        :param selector_set: a wsman.SelectorSet to add to the request
        :param timeout: Override the default wsman:OperationTimeout value for
            the request, this should be an int in seconds.
        :return: The ET Element of the response XML from the server
        """
        s = NAMESPACES['s']
        envelope = ET.Element("{%s}Envelope" % s)

        header = self._create_header(action, resource_uri, option_set,
                                     selector_set, timeout)
        envelope.append(header)

        body = ET.SubElement(envelope, "{%s}Body" % s)
        if resource is not None:
            body.append(resource)

        message_id = header.find("wsa:MessageID", namespaces=NAMESPACES).text
        xml = ET.tostring(envelope, encoding='utf-8', method='xml')

        try:
            response = self.transport.send(xml)
        except WinRMTransportError as err:
            try:
                # try and parse the XML and get the WSManFault
                raise self._parse_wsman_fault(err.response_text)
            except ET.ParseError:
                # no XML message is present so not a WSManFault error
                log.error("Failed to parse WSManFault message on WinRM error"
                          " response, raising original WinRMTransportError")
                raise err

        response_xml = ET.fromstring(response)
        relates_to = response_xml.find("s:Header/wsa:RelatesTo",
                                       namespaces=NAMESPACES).text

        if message_id != relates_to:
            raise WinRMError("Received related id does not match related "
                             "expected message id: Sent: %s, Received: %s"
                             % (message_id, relates_to))
        return response_xml

    def _calc_envelope_size(self, max_envelope_size):
        # get a mock Header which should cover most cases where large fragments
        # are used
        empty_uuid = "00000000-0000-0000-0000-000000000000"

        selector_set = SelectorSet()
        selector_set.add_option("ShellId", empty_uuid)
        header = self._create_header(
            WSManAction.SEND,
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            selector_set=selector_set
        )

        # get a skeleton Body to calculate the size without the payload
        rsp = NAMESPACES['rsp']
        send = ET.Element("{%s}Send" % rsp)
        ET.SubElement(send, "{%s}Stream" % rsp, Name="stdin",
                      CommandId=empty_uuid).text = ""

        envelope = ET.Element("{%s}Envelope" % NAMESPACES['s'])
        envelope.append(header)
        envelope.append(send)
        envelope = ET.tostring(envelope, encoding='utf-8', method='xml')

        # add the Header and Envelope and pad some extra bytes to cover
        # slightly different scenarios, multiple options, different body types
        # while this isn't perfect it's better than wasting CPU cycles
        # calculating it per message and a few bytes don't make too much of a
        # difference
        envelope_size = len(envelope) + 256
        max_bytes_size = max_envelope_size - envelope_size

        # Data is sent as Base64 encoded which inflates the size, we need to
        # calculate how large that can be
        base64_size = int(max_bytes_size / 4 * 3)
        return base64_size

    def _create_header(self, action, resource_uri, option_set=None,
                       selector_set=None, timeout=None):
        log.debug("Creating WSMan header (Action: %s, Resource URI: %s, "
                  "Option Set: %s, Selector Set: %s"
                  % (action, resource_uri, option_set, selector_set))
        s = NAMESPACES['s']
        wsa = NAMESPACES['wsa']
        wsman = NAMESPACES['wsman']
        wsmv = NAMESPACES['wsmv']
        xml = NAMESPACES['xml']

        header = ET.Element("{%s}Header" % s)

        ET.SubElement(
            header,
            "{%s}Action" % wsa,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = action

        ET.SubElement(
            header,
            "{%s}DataLocale" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false",
                    "{%s}lang" % xml: self.data_locale}
        )

        ET.SubElement(
            header,
            "{%s}Locale" % wsman,
            attrib={"{%s}mustUnderstand" % s: "false",
                    "{%s}lang" % xml: self.locale}
        )

        ET.SubElement(
            header,
            "{%s}MaxEnvelopeSize" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = str(self.max_envelope_size)

        ET.SubElement(header, "{%s}MessageID" % wsa).text = \
            "uuid:%s" % str(uuid.uuid4()).upper()

        ET.SubElement(
            header,
            "{%s}OperationTimeout" % wsman
        ).text = "PT%sS" % str(timeout or self.operation_timeout)

        reply_to = ET.SubElement(header, "{%s}ReplyTo" % wsa)
        ET.SubElement(
            reply_to,
            "{%s}Address" % wsa,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/" \
                 "anonymous"

        ET.SubElement(
            header,
            "{%s}ResourceURI" % wsman,
            attrib={"{%s}mustUnderstand" % s: "true"}
        ).text = resource_uri

        ET.SubElement(
            header,
            "{%s}SessionId" % wsmv,
            attrib={"{%s}mustUnderstand" % s: "false"}
        ).text = "uuid:%s" % str(self.session_id).upper()

        ET.SubElement(header, "{%s}To" % wsa).text = self.transport.endpoint

        if option_set is not None:
            header.append(option_set.pack())

        if selector_set is not None:
            header.append(selector_set.pack())

        return header

    def close(self):
        self.transport.close()

    @staticmethod
    def _parse_wsman_fault(xml_text):
        xml = ET.fromstring(xml_text)
        code = None
        reason = None
        machine = None
        provider = None
        provider_path = None
        provider_fault = None

        fault = xml.find("s:Body/s:Fault", namespaces=NAMESPACES)
        if fault is not None:
            code_info = fault.find("s:Code/s:Subcode/s:Value",
                                   namespaces=NAMESPACES)
            if code_info is not None:
                code = code_info.text
            else:
                code_info = fault.find("s:Code/s:Value",
                                       namespaces=NAMESPACES)
                if code_info is not None:
                    code = code_info.text

            reason_info = fault.find("s:Reason/s:Text",
                                     namespaces=NAMESPACES)
            if reason_info is not None:
                reason = reason_info.text

        wsman_fault = fault.find("s:Detail/wsmanfault:WSManFault",
                                 namespaces=NAMESPACES)
        if wsman_fault is not None:
            code = wsman_fault.attrib.get('Code', code)
            machine = wsman_fault.attrib.get('Machine')

            message_info = wsman_fault.find("wsmanfault:Message",
                                            namespaces=NAMESPACES)
            if message_info is not None:
                # message may still not be set, fall back to the existing
                # reason value from the base soap Fault element
                reason = message_info.text if message_info.text else reason

            provider_info = wsman_fault.find("wsmanfault:Message/"
                                             "wsmanfault:ProviderFault",
                                             namespaces=NAMESPACES)
            if provider_info is not None:
                provider = provider_info.attrib.get('provider')
                provider_path = provider_info.attrib.get('path')
                provider_fault = provider_info.text

        # lastly try and cleanup the value of the parameters
        try:
            code = int(code)
        except (TypeError, ValueError):
            pass

        try:
            reason = reason.strip()
        except AttributeError:
            pass

        try:
            provider_fault = provider_fault.strip()
        except AttributeError:
            pass

        return WSManFaultError(code, machine, reason, provider,
                               provider_path,
                               provider_fault)


class _WSManSet(object):

    def __init__(self, element_name, child_element_name, must_understand):
        self.element_name = element_name
        self.child_element_name = child_element_name
        self.must_understand = must_understand
        self.values = []

    def __str__(self):
        # can't just str({}) as the ordering is important
        entry_values = []
        for value in self.values:
            entry_values.append("'%s': '%s'" % (value[0], value[1]))

        string_value = "{%s}" % ", ".join(entry_values)
        return string_value

    def add_option(self, name, value, attributes=None):
        attributes = attributes if attributes is not None else {}
        self.values.append((name, value, attributes))

    def pack(self):
        s = NAMESPACES['s']
        wsman = NAMESPACES['wsman']
        element = ET.Element("{%s}%s" % (wsman, self.element_name))
        if self.must_understand:
            element.attrib['{%s}mustUnderstand' % s] = "true"

        for key, value, attributes in self.values:
            ET.SubElement(element, "{%s}%s" % (wsman, self.child_element_name),
                          Name=key,
                          attrib=attributes).text = str(value)

        return element


class OptionSet(_WSManSet):

    def __init__(self):
        super(OptionSet, self).__init__("OptionSet", "Option", True)


class SelectorSet(_WSManSet):

    def __init__(self):
        super(SelectorSet, self).__init__("SelectorSet", "Selector", False)


# this should not be used outside of this class
class _TransportHTTP(object):

    def __init__(self, server, port=None, username=None, password=None,
                 ssl=True, path="wsman", auth="negotiate",
                 cert_validation=True, connection_timeout=30,
                 encryption='auto', proxy=None, no_proxy=False,
                 read_timeout=30, reconnection_retries=0,
                 reconnection_backoff=2.0, **kwargs):
        self.server = server
        self.port = port if port is not None else (5986 if ssl else 5985)
        self.username = username
        self.password = password
        self.ssl = ssl
        self.path = path

        if auth not in SUPPORTED_AUTHS:
            raise ValueError("The specified auth '%s' is not supported, "
                             "please select one of '%s'"
                             % (auth, ", ".join(SUPPORTED_AUTHS)))
        self.auth = auth
        self.cert_validation = cert_validation
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.reconnection_retries = reconnection_retries
        self.reconnection_backoff = reconnection_backoff

        # determine the message encryption logic
        if encryption not in ["auto", "always", "never"]:
            raise ValueError("The encryption value '%s' must be auto, "
                             "always, or never" % encryption)
        enc_providers = ["credssp", "kerberos", "negotiate", "ntlm"]
        if ssl:
            # msg's are automatically encrypted with TLS, we only want message
            # encryption if always was specified
            self.wrap_required = encryption == "always"
            if self.wrap_required and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='auto' or use one of the following auth "
                    "providers: %s" % (self.auth, ", ".join(enc_providers))
                )
        else:
            # msg's should always be encrypted when not using SSL, unless the
            # user specifies to never encrypt
            self.wrap_required = not encryption == "never"
            if self.wrap_required and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='never', use ssl=True or use one of the "
                    "following auth providers: %s"
                    % (self.auth, ", ".join(enc_providers))
                )
        self.encryption = None

        self.proxy = proxy
        self.no_proxy = no_proxy

        for kwarg_list in AUTH_KWARGS.values():
            for kwarg in kwarg_list:
                setattr(self, kwarg, kwargs.get(kwarg, None))

        self.endpoint = self._create_endpoint(self.ssl, self.server, self.port,
                                              self.path)
        log.debug("Initialising HTTP transport for endpoint: %s, auth: %s, "
                  "user: %s" % (self.endpoint, self.username, self.auth))
        self.session = None

        # used when building tests, keep commented out
        # self._test_messages = []

    def close(self):
        if self.session:
            self.session.close()

    def send(self, message):
        hostname = get_hostname(self.endpoint)
        if self.session is None:
            self.session = self._build_session()

            # need to send an initial blank message to setup the security
            # context required for encryption
            if self.wrap_required:
                request = requests.Request('POST', self.endpoint, data=None)
                prep_request = self.session.prepare_request(request)
                self._send_request(prep_request)

                protocol = WinRMEncryption.SPNEGO
                if isinstance(self.session.auth, HttpCredSSPAuth):
                    protocol = WinRMEncryption.CREDSSP
                elif self.session.auth.contexts[hostname].response_auth_header == 'kerberos':
                    # When Kerberos (not Negotiate) was used, we need to send a special protocol value and not SPNEGO.
                    protocol = WinRMEncryption.KERBEROS

                self.encryption = WinRMEncryption(self.session.auth.contexts[hostname], protocol)

        log.debug("Sending message: %s" % message)
        # for testing, keep commented out
        # self._test_messages.append({"request": message.decode('utf-8'),
        #                             "response": None})

        headers = self.session.headers
        if self.wrap_required:
            content_type, payload = self.encryption.wrap_message(message)
            type_header = '%s;protocol="%s";boundary="Encrypted Boundary"' \
                          % (content_type, self.encryption.protocol)
            headers.update({
                'Content-Type': type_header,
                'Content-Length': str(len(payload)),
            })
        else:
            payload = message
            headers['Content-Type'] = "application/soap+xml;charset=UTF-8"

        request = requests.Request('POST', self.endpoint, data=payload,
                                   headers=headers)
        prep_request = self.session.prepare_request(request)
        return self._send_request(prep_request)

    def _send_request(self, request):
        response = self.session.send(request, timeout=(
            self.connection_timeout, self.read_timeout
        ))

        content_type = response.headers.get('content-type', "")
        if content_type.startswith("multipart/encrypted;") or content_type.startswith("multipart/x-multi-encrypted;"):
            boundary = re.search('boundary=[''|\\"](.*)[''|\\"]', response.headers['content-type']).group(1)
            response_content = self.encryption.unwrap_message(response.content, to_unicode(boundary))
            response_text = to_string(response_content)
        else:
            response_content = response.content
            response_text = response.text if response_content else ''

        log.debug("Received message: %s" % response_text)
        # for testing, keep commented out
        # self._test_messages[-1]['response'] = response_text
        try:
            response.raise_for_status()
        except requests.HTTPError as err:
            response = err.response
            if response.status_code == 401:
                raise AuthenticationError("Failed to authenticate the user %s "
                                          "with %s"
                                          % (self.username, self.auth))
            else:
                code = response.status_code
                raise WinRMTransportError('http', code, response_text)

        return response_content

    def _build_session(self):
        log.debug("Building requests session with auth %s" % self.auth)
        self._suppress_library_warnings()

        session = requests.Session()
        session.headers['User-Agent'] = "Python PSRP Client"

        # requests defaults to 'Accept-Encoding: gzip, default' which normally doesn't matter on vanila WinRM but for
        # Exchange endpoints hosted on IIS they actually compress it with 1 of the 2 algorithms. By explicitly setting
        # identity we are telling the server not to transform (compress) the data using the HTTP methods which we don't
        # support. https://tools.ietf.org/html/rfc7231#section-5.3.4
        session.headers['Accept-Encoding'] = 'identity'

        # get the env requests settings
        session.trust_env = True
        settings = session.merge_environment_settings(url=self.endpoint,
                                                      proxies={},
                                                      stream=None,
                                                      verify=None,
                                                      cert=None)

        # set the proxy config
        orig_proxy = session.proxies
        session.proxies = settings['proxies']
        if self.proxy is not None:
            proxy_key = 'https' if self.ssl else 'http'
            session.proxies = {
                proxy_key: self.proxy
            }
        elif self.no_proxy:
            session.proxies = orig_proxy

        # Retry on connection errors, with a backoff factor
        retry_kwargs = {
            'total': self.reconnection_retries,
            'connect': self.reconnection_retries,
            'status': self.reconnection_retries,
            'read': 0,
            'backoff_factor': self.reconnection_backoff,
            'status_forcelist': (425, 429, 503),
        }
        try:
            retries = Retry(**retry_kwargs)
        except TypeError:
            # Status was added in urllib3 >= 1.21 (Requests >= 2.14.0), remove
            # the status retry counter and try again. The user should upgrade
            # to a newer version
            log.warning("Using an older requests version that without support "
                        "for status retries, ignoring.", exc_info=True)
            del retry_kwargs['status']
            retries = Retry(**retry_kwargs)

        session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

        # set cert validation config
        session.verify = self.cert_validation

        # if cert_validation is a bool (no path specified), not False and there
        # are env settings for verification, set those env settings
        if isinstance(self.cert_validation, bool) and self.cert_validation \
                and settings['verify'] is not None:
            session.verify = settings['verify']

        build_auth = getattr(self, "_build_auth_%s" % self.auth)
        build_auth(session)
        return session

    def _build_auth_basic(self, session):
        if self.username is None:
            raise ValueError("For basic auth, the username must be specified")
        if self.password is None:
            raise ValueError("For basic auth, the password must be specified")

        session.auth = requests.auth.HTTPBasicAuth(username=self.username,
                                                   password=self.password)

    def _build_auth_certificate(self, session):
        if self.certificate_key_pem is None:
            raise ValueError("For certificate auth, the path to the "
                             "certificate key pem file must be specified with "
                             "certificate_key_pem")
        if self.certificate_pem is None:
            raise ValueError("For certificate auth, the path to the "
                             "certificate pem file must be specified with "
                             "certificate_pem")
        if self.ssl is False:
            raise ValueError("For certificate auth, SSL must be used")

        session.cert = (self.certificate_pem, self.certificate_key_pem)
        session.headers['Authorization'] = "http://schemas.dmtf.org/wbem/" \
                                           "wsman/1/wsman/secprofile/" \
                                           "https/mutual"

    def _build_auth_credssp(self, session):
        if self.username is None:
            raise ValueError("For credssp auth, the username must be "
                             "specified")
        if self.password is None:
            raise ValueError("For credssp auth, the password must be "
                             "specified")

        kwargs = self._get_auth_kwargs('credssp')
        session.auth = HttpCredSSPAuth(username=self.username,
                                       password=self.password,
                                       **kwargs)

    def _build_auth_kerberos(self, session):
        self._build_auth_negotiate(session, "kerberos")

    def _build_auth_negotiate(self, session, auth_provider="negotiate"):
        kwargs = self._get_auth_kwargs('negotiate')

        session.auth = HTTPNegotiateAuth(username=self.username,
                                         password=self.password,
                                         auth_provider=auth_provider,
                                         wrap_required=self.wrap_required,
                                         **kwargs)

    def _build_auth_ntlm(self, session):
        self._build_auth_negotiate(session, "ntlm")

    def _get_auth_kwargs(self, auth_provider):
        kwargs = {}
        for kwarg in AUTH_KWARGS[auth_provider]:
            kwarg_value = getattr(self, kwarg, None)
            if kwarg_value is not None:
                kwarg_key = kwarg[len(auth_provider) + 1:]
                kwargs[kwarg_key] = kwarg_value

        return kwargs

    def _suppress_library_warnings(self):
        # try to suppress known warnings from requests if possible
        try:
            from requests.packages.urllib3.exceptions import \
                InsecurePlatformWarning
            warnings.simplefilter('ignore', category=InsecurePlatformWarning)
        except:  # NOQA: E722; # pragma: no cover
            pass

        try:
            from requests.packages.urllib3.exceptions import SNIMissingWarning
            warnings.simplefilter('ignore', category=SNIMissingWarning)
        except:  # NOQA: E722; # pragma: no cover
            pass

        # if we're explicitly ignoring validation, try to suppress
        # InsecureRequestWarning, since the user opted-in
        if self.cert_validation is False:
            try:
                from requests.packages.urllib3.exceptions import \
                    InsecureRequestWarning
                warnings.simplefilter('ignore',
                                      category=InsecureRequestWarning)
            except:  # NOQA: E722; # pragma: no cover
                pass

    @staticmethod
    def _create_endpoint(ssl, server, port, path):
        scheme = "https" if ssl else "http"

        # Check if the server is an IPv6 Address, enclose in [] if it is
        try:
            address = ipaddress.IPv6Address(to_unicode(server))
        except ipaddress.AddressValueError:
            pass
        else:
            server = "[%s]" % address.compressed

        endpoint = "%s://%s:%s/%s" % (scheme, server, port, path)
        return endpoint
