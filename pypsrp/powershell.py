# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import struct
import sys
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from pypsrp.complex_objects import ApartmentState, Command, \
    CommandParameter, HostInfo, Pipeline, PSInvocationState, PSThreadOptions, \
    RemoteStreamOptions, RunspacePoolState
from pypsrp.exceptions import FragmentError, InvalidPipelineStateError, \
    InvalidPSRPOperation, InvalidRunspacePoolStateError
from pypsrp.messages import ConnectRunspacePool, CreatePipeline, Destination, \
    GetAvailableRunspaces, InitRunspacePool, Message, MessageType, PublicKey, \
    SessionCapability, SetMaxRunspaces, SetMinRunspaces
from pypsrp.serializer import Serializer
from pypsrp.shell import SignalCode, WinRS
from pypsrp.wsman import NAMESPACES, OptionSet, SelectorSet

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2.3"
PS_VERSION = "2.0"
SERIALIZATION_VERSION = "1.1.0.1"


class RunspacePool(object):

    def __init__(self, wsman, apartment_state=ApartmentState.UNKNOWN,
                 thread_options=PSThreadOptions.DEFAULT, host_info=None,
                 min_runspaces=1, max_runspaces=1,
                 session_key_timeout_ms=60000):
        # The below are defined in some way at
        # https://msdn.microsoft.com/en-us/library/ee176015.aspx
        self.id = str(uuid.uuid4()).upper()
        self.state = RunspacePoolState.BEFORE_OPEN
        self.wsman = wsman
        resuri = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
        self.shell = WinRS(wsman, resource_uri=resuri, id=self.id,
                           input_streams='stdin pr', output_streams='stdout')
        self.ci_table = {}
        self.pipelines = {}
        self.session_key_timeout_ms = session_key_timeout_ms

        # Extra properties that are important and can control the RunspacePool
        # behaviour
        self.apartment_state = apartment_state
        self.thread_options = thread_options
        self.host_info = host_info if host_info is not None else HostInfo()

        self._application_private_data = None
        self._min_runspaces = min_runspaces
        self._max_runspaces = max_runspaces
        self._serializer = Serializer()
        self._fragmenter = Fragmenter(self.wsman._max_payload_size,
                                      self._serializer)
        self._exchange_key = None
        self._key_exchanged = False
        self._new_client = False
        self._ci_counter = 0

    @property
    def application_private_data(self):
        """
        Private data to be used by applications built on top of PowerShell.
        Runspace data is gathered when creating the remote runspace pool and
        will be None if the runspace is not connected.
        """
        return self._application_private_data

    @property
    def min_runspaces(self):
        return self._min_runspaces

    @min_runspaces.setter
    def min_runspaces(self, min_runspaces):
        """
        Sets the minimum number of Runspaces that the pool maintains in
        anticipation of new requests.

        :param min_runspaces: The minimum number of runspaces in the pool
        """
        if self.state != RunspacePoolState.OPENED:
            self._min_runspaces = min_runspaces
            return
        elif min_runspaces == self._min_runspaces:
            return

        def response_handler(response):
            if not response:
                raise InvalidPSRPOperation("Failed to set minimum runspaces")
            return response

        ci = self._ci_counter
        self._ci_counter += 1
        self.ci_table[ci] = response_handler

        set_min_runspace = SetMinRunspaces(min_runspaces=min_runspaces, ci=ci)
        data = self._fragmenter.fragment(set_min_runspace, self.id)[0]
        self.shell.send('stdin', data)

        while not isinstance(self.ci_table[ci], bool):
            self._receive()
        self._min_runspaces = min_runspaces
        del self.ci_table[ci]

    @property
    def max_runspaces(self):
        return self._max_runspaces

    @max_runspaces.setter
    def max_runspaces(self, max_runspaces):
        """
        Sets the maximum number of Runspaces that can be active concurrently
        in the pool. All requests above that number remain queued until
        runspaces become available.

        :param max_runspaces: The maximum number of runspaces in the pool
        """
        if self.state != RunspacePoolState.OPENED:
            self._max_runspaces = max_runspaces
            return
        elif max_runspaces == self._max_runspaces:
            return

        def response_handler(response):
            if not response:
                raise InvalidPSRPOperation("Failed to set maximum runspaces")
            return response

        ci = self._ci_counter
        self._ci_counter += 1
        self.ci_table[ci] = response_handler

        set_max_runspace = SetMaxRunspaces(max_runspaces=max_runspaces, ci=ci)
        data = self._fragmenter.fragment(set_max_runspace, self.id)[0]
        self.shell.send('stdin', data)

        while not isinstance(self.ci_table[ci], bool):
            self._receive()
        self._max_runspaces = max_runspaces
        del self.ci_table[ci]

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        """
        Closes the RunspacePool and cleans all the internal resources. This
        will close all the runspaces in the runspacepool and release all the
        operations waiting for a runspace. If the pool is already closed or
        broken or closing, this will just return
        """
        if self.state in [RunspacePoolState.CLOSED, RunspacePoolState.CLOSING,
                          RunspacePoolState.BROKEN]:
            return

        self.shell.close()
        self.state = RunspacePoolState.CLOSED

    def connect(self):
        """
        Connects the runspace pool, Runspace pool must be in a disconnected
        state. This only supports reconnecting to a runspace pool created by
        the same client with the same SessionId value in the WSMan headers.
        """
        if self.state == RunspacePoolState.OPENED:
            return
        elif self.state != RunspacePoolState.DISCONNECTED:
            raise InvalidRunspacePoolStateError(
                self.state, RunspacePoolState.DISCONNECTED,
                "connect to a disconnected Runspace Pool"
            )

        if self._new_client:
            self._connect_new_client()
            self._new_client = False
        else:
            self._connect_existing_client()

    def _connect_existing_client(self):
        selector_set = SelectorSet()
        selector_set.add_option("ShellId", self.shell.id)

        self.wsman.reconnect(self.shell.resource_uri,
                             selector_set=selector_set)
        self.state = RunspacePoolState.OPENED

    def _connect_new_client(self):
        rsp = NAMESPACES['rsp']
        session_capability = SessionCapability(PROTOCOL_VERSION, PS_VERSION,
                                               SERIALIZATION_VERSION)
        connect_runspace = ConnectRunspacePool()
        data = self._fragmenter.fragment(session_capability, self.id)[0]
        data += self._fragmenter.fragment(connect_runspace, self.id)[0]

        connect = ET.Element("{%s}Connect" % rsp)
        selectors = SelectorSet()
        selectors.add_option("ShellId", self.id)

        options = OptionSet()
        options.add_option("protocolversion", PROTOCOL_VERSION,
                           {"MustComply": "true"})

        open_content = ET.SubElement(connect, "connectXml",
                                     xmlns="http://schemas.microsoft.com/"
                                           "powershell")
        open_content.text = base64.b64encode(data).decode('utf-8')

        response = self.wsman.connect(self.shell.resource_uri, connect,
                                      options, selectors)
        response_xml = response.find("rsp:ConnectResponse/"
                                     "pwsh:connectResponseXml",
                                     NAMESPACES).text
        fragments = base64.b64decode(response_xml)

        self._parse_responses(fragments)
        self.shell.id = self.id  # need to sync up the ShellID with the rs ID
        self._receive()

    def create_disconnected_power_shells(self):
        """
        Creates a list of PowerShell objects that are in the Disconnected state
        for all currently disconnected running commands associated with this
        runspace pool.

        :return: List<PowerShell>: List of disconnected PowerShell objects
        """
        return [s for s in self.pipelines.values() if
                s.state == PSInvocationState.DISCONNECTED]

    def disconnect(self):
        """
        Disconnects the runspace pool, must be in the Opened state
        """
        if self.state == RunspacePoolState.DISCONNECTED:
            return
        elif self.state != RunspacePoolState.OPENED:
            raise InvalidRunspacePoolStateError(
                self.state, RunspacePoolState.OPENED,
                "disconnect a Runspace Pool"
            )

        disconnect = ET.Element("{%s}Disconnect" % NAMESPACES['rsp'])
        selector_set = SelectorSet()
        selector_set.add_option("ShellId", self.shell.id)

        self.wsman.disconnect(self.shell.resource_uri, disconnect,
                              selector_set=selector_set)
        self.state = RunspacePoolState.DISCONNECTED
        for pipeline in self.pipelines.values():
            pipeline.state = PSInvocationState.DISCONNECTED

    def get_available_runspaces(self):
        """
        Retrieves the number of runspaces available at the time of calling this
        method.

        :return: The number of available runspaces in the pool
        """
        def response_handler(response):
            self._max_runspaces = response
            return response

        ci = self._ci_counter
        self._ci_counter += 1
        self.ci_table[ci] = response_handler

        get_runspaces = GetAvailableRunspaces(ci=ci)
        data = self._fragmenter.fragment(get_runspaces, self.id)[0]
        self.shell.send('stdin', data)

        avail_runspaces = None
        while avail_runspaces is None:
            self._receive()
            if isinstance(self.ci_table[ci], int):
                avail_runspaces = self.ci_table[ci]

        del self.ci_table[ci]
        return avail_runspaces

    @staticmethod
    def get_runspace_pools(wsman):
        """
        Queries the server for disconnected runspace pools and creates a list
        of runspace pool objects associated with each disconnected runspace
        pool on the server. Each runspace pool object in the returned array is
        in the Disconnected state and can be connected to the server by calling
        the connect() method on the runspace pool.

        :param wsman: The WSMan instance that is used to transport the messages
            to the server
        :return: List<RunspacePool> objects each in the Disconnected state
        """
        wsen = NAMESPACES['wsen']
        wsmn = NAMESPACES['wsman']

        enum_msg = ET.Element("{%s}Enumerate" % wsen)
        ET.SubElement(enum_msg, "{%s}OptimizeEnumeration" % wsmn)
        ET.SubElement(enum_msg, "{%s}MaxElements" % wsmn).text = "32000"

        # TODO: support wsman:EndOfSequence
        response = wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/"
                                   "windows/shell", enum_msg)
        shells = response.findall("wsen:EnumerateResponse/"
                                  "wsman:Items/"
                                  "rsp:Shell", NAMESPACES)

        runspace_pools = []
        for shell in shells:
            shell_id = shell.find("rsp:ShellId", NAMESPACES).text
            pool = RunspacePool(wsman)
            pool.id = shell_id
            pool.shell.shell_id = shell_id
            pool.shell.opened = True
            pool._new_client = True

            # Seems like the server sends all pools not just disconnected but
            # the .NET API always sets the state to Disconnected when callling
            # GetRunspacePools
            pool.state = RunspacePoolState.DISCONNECTED

            enum_msg = ET.Element("{%s}Enumerate" % wsen)
            ET.SubElement(enum_msg, "{%s}OptimizeEnumeration" % wsmn)
            ET.SubElement(enum_msg, "{%s}MaxElements" % wsmn).text = "32000"
            filter = ET.SubElement(enum_msg, "{%s}Filter" % wsmn,
                                   Dialect="http://schemas.dmtf.org/wbem/wsman"
                                           "/1/wsman/SelectorFilter")
            selector_set = SelectorSet()
            selector_set.add_option("ShellId", shell_id)
            filter.append(selector_set.pack())

            response = wsman.enumerate("http://schemas.microsoft.com/wbem/"
                                       "wsman/1/windows/shell/Command",
                                       enum_msg)
            commands = response.findall("wsen:EnumerateResponse/"
                                        "wsman:Items/"
                                        "rsp:Command", NAMESPACES)
            pipelines = {}
            for command in commands:
                command_id = command.find("rsp:CommandId", NAMESPACES).text

                powershell = PowerShell(pool)
                powershell.id = command_id
                powershell.state = PSInvocationState.DISCONNECTED
                pipelines[powershell.id] = powershell

            pool.pipelines = pipelines
            runspace_pools.append(pool)
        return runspace_pools

    def open(self):
        """
        Opens the runspace pool, this step must be called before it can be
        used.
        """
        if self.state == RunspacePoolState.OPENED:
            return
        if self.state != RunspacePoolState.BEFORE_OPEN:
            raise InvalidRunspacePoolStateError(
                self.state, RunspacePoolState.BEFORE_OPEN,
                "open a new Runspace Pool"
            )

        session_capability = SessionCapability(PROTOCOL_VERSION, PS_VERSION,
                                               SERIALIZATION_VERSION)
        init_runspace_pool = InitRunspacePool(
            self.min_runspaces, self.max_runspaces,
            PSThreadOptions(value=self.thread_options),
            ApartmentState(value=self.apartment_state), self.host_info
        )
        data = self._fragmenter.fragment(session_capability, self.id)[0]
        data += self._fragmenter.fragment(init_runspace_pool, self.id)[0]

        open_content = ET.Element(
            "creationXml", xmlns="http://schemas.microsoft.com/powershell"
        )
        open_content.text = base64.b64encode(data).decode('utf-8')

        options = OptionSet()
        options.add_option("protocolversion", PROTOCOL_VERSION,
                           {"MustComply": "true"})
        self.shell.open(options, open_content)
        self.state = RunspacePoolState.NEGOTIATION_SENT

        while self.state == RunspacePoolState.NEGOTIATION_SENT:
            responses = self._receive()

        error_states = [RunspacePoolState.BROKEN, RunspacePoolState.CLOSED]
        if self.state in error_states:
            # TODO: get error_record from RunspacePoolState message
            state_response = None

            raise InvalidRunspacePoolStateError(
                self.state, error_states, "open new Runspace Pool"
            )

    def exchange_keys(self):
        """
        Initiate a key exchange with the server that is required when dealing
        with secure strings. This can only be run once the RunspacePool is
        open and if the key has already been exchanged then nothing will
        happen.
        """
        if self._key_exchanged or self._exchange_key is not None:
            # key is already exchanged or we are still in the processes of
            # exchanging it, no need to run again
            return

        # Generate a unique RSA key pair for use in this Pool only
        self._exchange_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_numbers = self._exchange_key.public_key().public_numbers()
        exponent = struct.pack("<I", public_numbers.e)
        modulus = b""
        for i in range(0, 256):
            byte_value = struct.pack("B", public_numbers.n >> (i * 8) & 0xff)
            modulus += byte_value

        # the public key bytes follow a set structure defined in MS-PSRP
        public_key_bytes = b"\x06\x02\x00\x00\x00\xa4\x00\x00" \
                           b"\x52\x53\x41\x31\x00\x08\x00\x00" + \
                           exponent + modulus
        public_key = base64.b64encode(public_key_bytes)

        msg = PublicKey(public_key=public_key.decode('utf-8'))
        fragments = self._fragmenter.fragment(msg, self.id)
        for fragment in fragments:
            self.shell.send('stdin', fragment)

        start = time.time()
        while not self._key_exchanged:
            elapsed = int((time.time() - start) * 1000)
            if elapsed > self.session_key_timeout_ms:
                raise InvalidPSRPOperation("Timeout while waiting for key "
                                           "exchange")
            self._receive()

    def serialize(self, obj, metadata=None):
        """
        Serialize a Python object to PSRP object. This can try to automatically
        serialize based on the Python type to the closest PSRP object but
        manual coercion can be done with the metadata parameter.

        :param obj: The Python object to serialize
        :param metadata: complex_objects.ObjectMeta that defines the type of
            object to serialize to, if omitted the obj will be serialized based
            on the Python type
        :return: An XML element that can be used as part of the PSRP input
            elements like cmdlet parameters
        """
        # TODO: should I clear before or after?
        return self._serializer.serialize(obj, metadata=metadata)

    def _receive(self, id=None, timeout=None):
        """
        Sends a Receive WSMV request to the host and processes the messages
        that are received from the host (if there are any).

        :param id: If the receive is targeted to a Pipeline then this should be
            the ID of that pipeline, if None then the receive is targeted to
            the RunspacePool
        :param timeout: An override that specifies the operation timeout for
            the receive command
        :return: List of tuples where each tuple is a tuple of
            MessageType: The Message ID of the response
            Response: The return object of the response handler function for
                the message type
        """
        response = self.shell.receive("stdout", command_id=id,
                                      timeout=timeout)[2]['stdout']
        return self._parse_responses(response, id)

    def _parse_responses(self, responses, id=None):
        messages = self._fragmenter.defragment(responses)
        pipeline = self.pipelines.get(id)

        response_functions = {
            # While the docs say we should verify, they are out of date with
            # the possible responses and so we will just ignore for now
            MessageType.SESSION_CAPABILITY: None,
            MessageType.ENCRYPTED_SESSION_KEY:
                self._process_encrypted_session_key,
            MessageType.PUBLIC_KEY_REQUEST: self.exchange_keys,
            MessageType.RUNSPACEPOOL_INIT_DATA:
                self._process_runspacepool_init_data,
            MessageType.RUNSPACE_AVAILABILITY:
                self._process_runspacepool_availability,
            MessageType.RUNSPACEPOOL_STATE: self._process_runspacepool_state,
            MessageType.USER_EVENT: None,
            MessageType.APPLICATION_PRIVATE_DATA:
                self._process_application_private_data,
            MessageType.RUNSPACEPOOL_HOST_CALL: None,
        }

        if pipeline is not None:
            pipeline_response_functions = {
                # The Pipeline Output isn't processes and just returned back to
                # the receive caller
                MessageType.PIPELINE_OUTPUT: None,
                MessageType.ERROR_RECORD: pipeline._process_error_record,
                MessageType.PIPELINE_STATE: pipeline._process_pipeline_state,
                MessageType.DEBUG_RECORD: pipeline._process_debug_record,
                MessageType.VERBOSE_RECORD: pipeline._process_verbose_record,
                MessageType.WARNING_RECORD: pipeline._process_warning_record,
                MessageType.PROGRESS_RECORD: pipeline._process_progress_record,
                MessageType.INFORMATION_RECORD:
                    pipeline._process_information_record,
                MessageType.PIPELINE_HOST_CALL: None
            }
            response_functions.update(pipeline_response_functions)

        return_values = []
        for message in messages:
            response_function = response_functions[message.message_type]
            if response_function is not None:
                return_value = response_function(message)
                return_values.append((message.message_type, return_value))
            else:
                return_values.append((message.message_type, message))

        return return_values

    def _process_runspacepool_init_data(self, message):
        self._min_runspaces = message.data.min_runspaces
        self._max_runspaces = message.data.max_runspaces

    def _process_runspacepool_availability(self, message):
        ci = message.data.ci
        response = message.data.response
        ci_handler = self.ci_table[ci]
        response = ci_handler(response)
        self.ci_table[ci] = response
        return response

    def _process_runspacepool_state(self, message):
        self.state = message.data.state
        return message.data

    def _process_application_private_data(self, message):
        self._application_private_data = message.data

    def _process_encrypted_session_key(self, message):
        enc_sess_key = base64.b64decode(message.data.session_key)

        # strip off Win32 Crypto Blob Header and reverse the bytes
        encrypted_key = enc_sess_key[12:][::-1]
        pad_method = padding.PKCS1v15()
        decrypted_key = self._exchange_key.decrypt(encrypted_key, pad_method)

        iv = b"\x00" * 16  # PSRP doesn't use an IV
        algorithm = algorithms.AES(decrypted_key)
        mode = modes.CBC(iv)
        cipher = Cipher(algorithm, mode, default_backend())

        self._serializer.cipher = cipher
        self._key_exchanged = True
        self._exchange_key = None


class PowerShell(object):

    def __init__(self, runspace_pool):
        """
        Represents a PowerShell command or script to execute against a
        RunspacePool.

        This is meant to be a near representation of the
        System.Management.Automation.PowerShell .NET class

        :param runspace_pool: The RunspacePool that the PowerShell instance
            will run over
        """
        self.runspace_pool = runspace_pool
        self.state = PSInvocationState.NOT_STARTED

        self.commands = PSCommand()
        self.had_errors = False
        self.history_string = None
        self.id = str(uuid.uuid4()).upper()
        self.is_nested = False
        self.streams = PSDataStreams()
        self.output = []
        self._from_disconnect = False

        runspace_pool.pipelines[self.id] = self

    def add_argument(self, value):
        """
        Adds an argument to the last added command.

        :param value: The argument to add. If the value is a native Python
            type then it will be automatically serialized, otherwise if it is
            an already serialized object then that value will be used instead
        :return: The current PowerShell object with the argument added to the
            last added Command
        """
        self.commands.add_argument(value)
        return self

    def add_command(self, command):
        """
        Add a Command object to the current command pipeline.

        :param command: Command to add
        :return: The current PowerShell object with the Command added
        """
        self.commands.add_command(command)
        return self

    def add_cmdlet(self, cmdlet, use_local_scope=None):
        """
        Add a cmdlet/command to the current command pipeline. This is similar
        to add_command but it takes in a string and constructs the Command
        object for you. For example to construct "Get-Process | Sort-Object"

        .add_cmdlet("Get-Process").add_cmdlet("Sort-Object")

        :param cmdlet: A string representing the cmdlet to add
        :param use_local_scope: Run the cmdlet under the local scope
        :return: The current PowerShell object with the cmdlet added
        """
        self.commands.add_cmdlet(cmdlet, use_local_scope)
        return self

    def add_parameter(self, parameter_name, value=None):
        """
        Add a parameter to the last added command. For example to construct a
        command string "get-service -name service-name"

        .add_command("get-service").add_parameter("name", "service-name")

        :param parameter_name: The name of the parameter
        :param value: The value for the parameter, None means no value is set.
            If the value is a native Python type then it will be automatically
            serialized, otherwise if it is an already serialized object then
            that value will be used instead
        :return: the current PowerShell instance with the parameter added
        """
        self.commands.add_parameter(parameter_name, value)
        return self

    def add_parameters(self, parameters):
        """
        Adds a set of parameters to the last added command.

        :param parameters: A dictionary of parameters where the key is the
            parameter name and the value is the parameter value. A value of
            None means no value is set and the parameter is a switch
        :return: the current PowerShell instance with the parameters added
        """
        for parameter_name, value in parameters.items():
            self.commands.add_parameter(parameter_name, value)
        return self

    def add_script(self, script, use_local_scope=None):
        """
        Add a piece of script to construct a command pipeline.

        :param script: A string representing a script
        :param use_local_scope: Run the script under the local scope
        :return: the current PowerShell instance with the command added
        """
        self.commands.add_script(script, use_local_scope)
        return self

    def add_statement(self):
        """
        Set's the last command in the pipeline to be the last in that
        statement/pipeline so the next command is in a new statement.

        :return: The current PowerShell instance with the last command set
            as the last one in that statement
        """
        self.commands.add_statement()
        return self

    def connect(self):
        """
        Connects to a running command on a remote server, waits until the
        command is finished and returns the output objects.

        :return: Command output as a PSDataCollection
        """
        self.connect_async()
        return self.end_invoke()

    def connect_async(self):
        """
        Connects to a running command on a remote server, this method will
        connect to the host but will not wait until the command is finished.
        Call end_invoke() to wait until the process is complete.
        """
        if self.state != PSInvocationState.DISCONNECTED:
            raise InvalidPipelineStateError(
                self.state, PSInvocationState.DISCONNECTED,
                "connect to a disconnect async pipeline"
            )
        rsp = NAMESPACES['rsp']

        connect = ET.Element("{%s}Connect" % rsp, CommandId=self.id)
        selectors = SelectorSet()
        selectors.add_option("ShellId", self.runspace_pool.id)

        self.runspace_pool.wsman.connect(self.runspace_pool.shell.resource_uri,
                                         connect,
                                         selector_set=selectors)
        self.state = PSInvocationState.RUNNING
        self._from_disconnect = True

    def create_nested_power_shell(self):
        """
        Creates a nested PowerShell within the current instance. Nested
        PowerShell is used to do simple operations like checking state of a
        variable while another command is using the runspace.

        Nested PowerShell should be invoked from the same thread as the parent
        PowerShell invocation thread. So effectively the parent PowerShell
        invocation thread is blocked until the nested invoke() operation is
        complete.

        :return: The new nested PowerShell object
        """
        if self.state != PSInvocationState.RUNNING:
            raise InvalidPipelineStateError(
                self.state, PSInvocationState.RUNNING,
                "create a nested PowerShell pipeline"
            )
        elif self._from_disconnect:
            raise InvalidPSRPOperation("Cannot created a nested PowerShell "
                                       "pipeline from an existing pipeline "
                                       "that was connected to remotely")

        ps = PowerShell(self.runspace_pool)
        ps.is_nested = True
        return ps

    def begin_invoke(
            self, input=None, add_to_history=False, apartment_state=None,
            host=None, redirect_shell_error_to_out=False,
            remote_stream_options=RemoteStreamOptions.ADD_INVOCATION_INFO):
        """
        Invoke the command asynchronously, use end_invoke to get the output
        collection of return objects.

        :param input: List of inputs to the command
        :param add_to_history:
        :param apartment_state:
        :param host:
        :param redirect_shell_error_to_out: Whether to redirect the global
            error output pipe to the commands error output pipe.
        :param remote_stream_options: Whether to return the invocation info on
            the various steams, see complex_objects.RemoteStreamOptions for the
            values. Will default to returning the invocation info on all
        :return:
        """
        if self.state != PSInvocationState.NOT_STARTED:
            raise InvalidPipelineStateError(
                self.state, PSInvocationState.NOT_STARTED,
                "start a PowerShell pipeline"
            )

        if len(self.commands.commands) == 0:
            raise InvalidPSRPOperation("Cannot invoke PowerShell without any "
                                       "commands being set")

        no_input = input is None or not input
        apartment_state = apartment_state or self.runspace_pool.apartment_state
        host_info = host or self.runspace_pool.host_info

        pipeline = Pipeline(
            is_nested=self.is_nested,
            cmds=self.commands.commands,
            history=self.history_string,
            redirect_err_to_out=redirect_shell_error_to_out
        )
        create_pipeline = CreatePipeline(
            no_input, ApartmentState(value=apartment_state),
            RemoteStreamOptions(value=remote_stream_options), add_to_history,
            host_info, pipeline, self.is_nested
        )

        fragments = self.runspace_pool._fragmenter.fragment(
            create_pipeline, self.runspace_pool.id, self.id
        )

        first_frag = base64.b64encode(fragments.pop(0)).decode('utf-8')
        self.runspace_pool.shell.command('', arguments=[first_frag],
                                         command_id=self.id)
        self.state = PSInvocationState.RUNNING

        # now send the remaining fragments with the send message
        for fragment in fragments:
            self.runspace_pool.shell.send('stdin', fragment,
                                          command_id=self.id)

    def end_invoke(self):
        """
        Wait until the asynchronous command has finished executing and return
        the output collection of return objects.

        :return: A list of output objects
        """
        while self.state == PSInvocationState.RUNNING:
            responses = self.runspace_pool._receive(self.id)
            for response in responses:
                if response[0] == MessageType.PIPELINE_OUTPUT:
                    self.output.append(response[1].data.data)

        return self.output

    def invoke(self, input=None, add_to_history=False, apartment_state=None,
               host=None, redirect_shell_error_to_out=False,
               remote_stream_options=RemoteStreamOptions.ADD_INVOCATION_INFO):
        """
        Invoke the command and return the output collection of return objects.

        :param input: List of inputs to the command
        :param add_to_history:
        :param apartment_state:
        :param host:
        :param remote_stream_options:
        :return: A list of output objects
        """
        self.begin_invoke(input, add_to_history, apartment_state, host,
                          redirect_shell_error_to_out, remote_stream_options)
        return self.end_invoke()

    def stop(self):
        """
        Stop the currently running command.
        """
        if self.state in [PSInvocationState.STOPPING,
                          PSInvocationState.STOPPED]:
            return
        elif self.state != PSInvocationState.RUNNING:
            raise InvalidPipelineStateError(
                self.state, PSInvocationState.RUNNING,
                "stop a running pipeline"
            )

        self.state = PSInvocationState.STOPPING
        self.runspace_pool.shell.signal(SignalCode.PS_CTRL_C,
                                        str(self.id).upper())
        self.state = PSInvocationState.STOPPED
        del self.runspace_pool.pipelines[self.id]

    def _process_error_record(self, message):
        self.streams.error.append(message.data)

    def _process_pipeline_state(self, message):
        self.state = message.data.state
        if message.data.error_record is not None:
            self.streams.error.append(message.data.error_record)

        if self.state == PSInvocationState.FAILED:
            self.had_errors = True

    def _process_debug_record(self, message):
        self.streams.debug.append(message.data)

    def _process_verbose_record(self, message):
        self.streams.verbose.append(message.data)

    def _process_warning_record(self, message):
        self.streams.warning.append(message.data)

    def _process_progress_record(self, message):
        self.streams.progress.append(message.data)

    def _process_information_record(self, message):
        self.streams.information.append(message.data)


class PSCommand(object):

    def __init__(self):
        self.commands = []
        self._current_command = None

    def add_argument(self, value):
        """
        Adds an argument to the last added command.

        :param value: The argument to add. If the value is a native Python
            type then it will be automatically serialized, otherwise if it is
            an already serialized object then that value will be used instead
        :return: The current PSCommand object with the argument added to the
            last added Command
        """
        command_parameter = CommandParameter(value=value)
        self._current_command.args.append(command_parameter)
        return self

    def add_command(self, command):
        """
        Add a Command object to the current command pipeline.

        :param command: Command to add
        :return: The current PSCommand object with the Command added
        """
        self.commands.append(command)
        self._current_command = command
        return self

    def add_cmdlet(self, cmdlet, use_local_scope=None):
        """
        Add a cmdlet/command to the current command pipeline. This is similar
        to add_command but it takes in a string and constructs the Command
        object for you. For example to construct "Get-Process | Sort-Object"

        .add_cmdlet("Get-Process").add_cmdlet("Sort-Object")

        :param cmdlet: A string representing the cmdlet to add
        :param use_local_scope: Run the cmdlet under the local scope
        :return: The current PSCommand object with the cmdlet added
        """
        command = Command(cmd=cmdlet, is_script=False,
                          use_local_scope=use_local_scope)
        self.commands.append(command)
        self._current_command = command
        return self

    def add_parameter(self, parameter_name, value=None):
        """
        Add a parameter to the last added command. For example to construct
        "Get-Process -Name powershell"

        .add_cmdlet("Get-Process").add_parameter("Name", "powershell")

        :param parameter_name: The name of the parameter
        :param value: The value for the parameter, None means no value is set.
            If the value is a native Python type then it will be automatically
            serialized, otherwise if it is an already serialized object then
            that value will be used instead
        :return: The current PSCommand object with the parameter added to the
            last command's parameter list
        """
        command_parameter = CommandParameter(name=parameter_name, value=value)
        self._current_command.args.append(command_parameter)
        return self

    def add_script(self, script, use_local_scope=None):
        """
        Add a piece of script to construct a command pipeline.

        :param script: A string representing the script
        :param use_local_scope: Run the script under the local scope
        :return: the current PSCommand object with the script added
        """
        command = Command(cmd=script, is_script=True,
                          use_local_scope=use_local_scope)
        self.commands.append(command)
        self._current_command = command
        return self

    def add_statement(self):
        """
        Set's the last command in the pipeline to be the last in that
        statement/pipeline so the next command is in a new statement.

        :return: The current PSCommand instance with the last command set
            as the last one in that statement
        """
        self._current_command.end_of_statement = True
        self._current_command = None
        return self

    def clear(self):
        """
        Clears the commands.
        """
        self._current_command = None
        self.commands = []


class PSDataStreams(object):

    def __init__(self):
        """
        Streams generated by PowerShell invocations

        System.Management.Automation.PSDataStreams
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.psdatastreams?view=powershellsdk-1.1.0
        """
        self.debug = []
        self.error = []
        self.information = []
        self.progress = []
        self.verbose = []
        self.warning = []


class Fragmenter(object):

    def __init__(self, max_size, serializer):
        self.incoming_buffer = {}
        self.outgoing_counter = 1
        self.max_size = max_size
        self.serializer = serializer

    def fragment(self, data, rpid, pid=None):
        msg = Message(Destination.SERVER, rpid, pid, data, self.serializer)
        msg_data = msg.pack()
        fragments = []

        fragment_id = 0
        start = True
        max_size = self.max_size
        for msg_fragment, end in self._byte_iterator(msg_data, max_size):
            fragment = Fragment(self.outgoing_counter, fragment_id,
                                msg_fragment, start, end)
            fragments.append(fragment.pack())
            fragment_id += 1
            start = False

        self.outgoing_counter += 1
        return fragments

    def defragment(self, data):
        fragments = []
        while data != b"":
            frag, data = Fragment.unpack(data)
            incoming_buffer = self.incoming_buffer.get(frag.object_id)
            if incoming_buffer is None:
                incoming_buffer = {"data": b"", "id": 0}
                self.incoming_buffer[frag.object_id] = incoming_buffer

            if frag.fragment_id != incoming_buffer['id']:
                raise FragmentError(
                    "Fragment Fragment Id: %d != Expected Fragment Id: %d"
                    % (frag.fragment_id, incoming_buffer['id'])
                )

            if frag.start and frag.end:
                fragments.append(frag.data)
                del self.incoming_buffer[frag.object_id]
            elif frag.start:
                incoming_buffer['data'] = frag.data
                incoming_buffer['id'] += 1
            elif frag.end:
                fragments.append(incoming_buffer['data'] + frag.data)
                del self.incoming_buffer[frag.object_id]
            else:
                incoming_buffer['data'] += frag.data
                incoming_buffer['id'] += 1

        messages = [Message.unpack(fragment, self.serializer)
                    for fragment in fragments]
        return messages

    def _byte_iterator(self, data, buffer_size):
        byte_count = len(data)
        for i in range(0, byte_count, buffer_size):
            yield data[i:i + buffer_size], i + buffer_size >= byte_count


class Fragment(object):

    def __init__(self, object_id, fragment_id, data, start=False, end=False):
        self.object_id = object_id
        self.fragment_id = fragment_id
        self.start = start
        self.end = end
        self.data = data

    def pack(self):
        start_end_byte = 0
        if self.start:
            start_end_byte |= 0x1
        if self.end:
            start_end_byte |= 0x2

        data = struct.pack(">Q", self.object_id)
        data += struct.pack(">Q", self.fragment_id)
        data += struct.pack("B", start_end_byte)
        data += struct.pack(">I", len(self.data))
        data += self.data

        return data

    @staticmethod
    def unpack(data):
        object_id = struct.unpack(">Q", data[0:8])[0]
        fragment_id = struct.unpack(">Q", data[8:16])[0]

        start_end_byte = struct.unpack("B", data[16:17])[0]
        start = start_end_byte & 0x1 == 0x1
        end = start_end_byte & 0x2 == 0x2

        length = struct.unpack(">I", data[17:21])[0]
        fragment_data = data[21:length + 21]

        fragment = Fragment(object_id, fragment_id, fragment_data, start, end)
        return fragment, data[21 + length:]
