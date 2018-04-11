# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import struct
import sys
import uuid

from random import randint

from pypsrp.complex_objects import ApartmentState, Command, \
    CommandParameter, HostInfo, Pipeline, PSThreadOptions, RemoteStreamOptions
from pypsrp.exceptions import WinRMError
from pypsrp.messages import CreatePipeline, Destination, \
    GetAvailableRunspaces, InitRunspacePool, Message, MessageType, PublicKey, \
    SessionCapability, SetMaxRunspaces, SetMinRunspaces
from pypsrp.serializer import Serializer
from pypsrp.shell import SignalCode, WinRS
from pypsrp.wsman import NAMESPACES, OptionSet, SelectorSet

HAS_CRYPTO = False
CRYPTO_IMP_ERR = None
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, \
        modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError as ie:
    CRYPTO_IMP_ERR = ie

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)


class RunspacePoolState(object):
    """
    [MS-PSRP] 2.2.3.4 RunspacePoolState
    https://msdn.microsoft.com/en-us/library/dd341723.aspx

    Represents the state of the RunspacePool.
    """
    BEFORE_OPEN = 0
    OPENING = 1
    OPENED = 2
    CLOSED = 3
    CLOSING = 4
    BROKEN = 5
    NEGOTIATION_SENT = 6
    NEGOTIATION_SUCCEEDED = 7
    CONNECTING = 8
    DISCONNECTED = 9


class PSInvocationState(object):
    """
    [MS-PSRP] 2.2.3.5 PSInvocationState
    https://msdn.microsoft.com/en-us/library/dd341651.aspx

    Represents the state of a pipeline invocation.
    """
    NOT_STARTED = 0
    RUNNING = 1
    STOPPING = 2
    STOPPED = 3
    COMPLETED = 4
    FAILED = 5
    DISCONNECTED = 6


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
        self.shell = WinRS(wsman)
        self.shell.resource_uri = "http://schemas.microsoft.com/powershell/" \
                                  "Microsoft.PowerShell"
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
            self._min_runspaces = response
            return response

        ci = randint(1, 9223372036854775807)
        self.ci_table[ci] = response_handler

        set_min_runspace = SetMinRunspaces(min_runspaces=min_runspaces, ci=ci)
        data = self._fragmenter.fragment(set_min_runspace, self.id)[0]
        self.shell._send(data, name='stdin')

        while not isinstance(self.ci_table[ci], bool):
            self._receive()
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
            self._max_runspaces = response
            return response

        ci = randint(1, 9223372036854775807)
        self.ci_table[ci] = response_handler

        set_max_runspace = SetMaxRunspaces(max_runspaces=max_runspaces, ci=ci)
        data = self._fragmenter.fragment(set_max_runspace, self.id)[0]
        self.shell._send(data, name='stdin')

        while not isinstance(self.ci_table[ci], bool):
            self._receive()
        del self.ci_table[ci]

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
        Connects the runspaace pool, Runspace pool must be in a disconnected
        state. This only supports reconnecting to a runspace pool created by
        the same client with the same SessionId value in the WSMan headers.
        """
        if self.state == RunspacePoolState.OPENED:
            return
        elif self.state != RunspacePoolState.DISCONNECTED:
            raise WinRMError("Cannot connect to a runspace pool that is not "
                             "in a disconnected state")

        selector_set = SelectorSet()
        selector_set.add_option("ShellId", self.shell.shell_id)

        self.wsman.reconnect(self.shell.resource_uri,
                             selector_set=selector_set)
        self.state = RunspacePoolState.OPENED

    def create_disconnected_power_shells(self):
        """
        Creates a list of PowerShell objects that are in the Disconnected state
        for all currently disconnected running commands associated with this
        runspace pool.

        :return: List<PowerShell>: List of disconnected PowerShell objects
        """
        raise NotImplementedError()

    def disconnect(self):
        """
        Disconnects the runspace pool, must be in the Opened state
        """
        if self.state == RunspacePoolState.DISCONNECTED:
            return
        elif self.state != RunspacePoolState.OPENED:
            raise WinRMError("Cannot disconnect a runspace pool that is not in"
                             " an opened state")

        disconnect = ET.Element("{%s}Disconnect" % NAMESPACES['rsp'])
        selector_set = SelectorSet()
        selector_set.add_option("ShellId", self.shell.shell_id)

        self.wsman.disconnect(self.shell.resource_uri, disconnect,
                              selector_set=selector_set)
        self.state = RunspacePoolState.DISCONNECTED

    def get_available_runspaces(self):
        """
        Retrieves the number of runspaces available at the time of calling this
        method.

        :return: The number of available runspaces in the pool
        """
        def response_handler(response):
            self._max_runspaces = response
            return response

        ci = randint(1, 9223372036854775807)
        self.ci_table[ci] = response_handler

        get_runspaces = GetAvailableRunspaces(ci=ci)
        data = self._fragmenter.fragment(get_runspaces, self.id)[0]
        self.shell._send(data, name='stdin')

        avail_runspaces = None
        while avail_runspaces is None:
            self._receive()
            if isinstance(self.ci_table[ci], int):
                avail_runspaces = self.ci_table[ci]

        del self.ci_table[ci]
        return avail_runspaces

    @staticmethod
    def get_runspace_pools(connection_info, host, type_table):
        """
        Queries the server for disconnected runspace pools and creates a list
        of runspace pool objects associated with each disconnected runspace
        pool on the server. Each runspace pool object in the returned array is
        in the Disconnected state and can be connected to the server by calling
        the connect() method on the runspace pool.

        :param connection_info: Connection object for the target server
        :param host: Client host object
        :param type_table: TypeTable object
        :return: List<RunspacePool> objects each in the Disconnected state
        """
        raise NotImplementedError()

    def open(self):
        """
        Opens the runspace pool, this step must be called before it can be
        used.
        """
        if self.state != RunspacePoolState.BEFORE_OPEN:
            raise WinRMError("Cannot open runspace pool when not in the "
                             "Before Open state")

        session_capability = SessionCapability("2.3", "2.0", "1.1.0.1")

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
        options.add_option("protocolversion", "2.3", {"MustComply": "true"})
        self.shell.open(input_streams='stdin pr', output_streams='stdout',
                        shell_id=self.id, open_content=open_content,
                        base_options=options)
        self.state = RunspacePoolState.NEGOTIATION_SENT

        while self.state != RunspacePoolState.OPENED:
            self._receive()

    def exchange_keys(self):
        """
        Initiate a key exchange with the server that is required when dealing
        with secure strings. This can only be run once the RunspacePool is
        open and if the key has already been exchanged then nothing will
        happen.
        """
        if not HAS_CRYPTO:
            raise Exception("Failed to import cryptography, cannot generate "
                            "RSA key: %s" % str(CRYPTO_IMP_ERR))
        elif self._key_exchanged or self._exchange_key is not None:
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
            self.shell._send(fragment)

        # TODO: set timer on this
        while not self._key_exchanged:
            self._receive()

    def _receive(self, id=None):
        """
        Sends a Receive WSMV request to the host and processes the messages
        that are received from the host (if there are any).

        :param id: If the receive is targeted to a Pipeline then this should be
            the ID of that pipeline, if None then the receive is targeted to
            the RunspacePool
        :return: List of tuples where each tuple is a tuple of
            MessageType: The Message ID of the response
            Response: The return object of the response handler function for
                the message type
        """
        responses = self.shell._receive("stdout", command_id=id)[2]['stdout']
        messages = self._fragmenter.defragment(responses)
        pipeline = self.pipelines.get(id)

        response_functions = {
            # While the docs say we should verify, they are out of date with
            # the possible responses and so we will just ignore for now
            MessageType.SESSION_CAPABILITY: None,
            MessageType.ENCRYPTED_SESSION_KEY:
                self._process_encrypted_session_key,
            MessageType.PUBLIC_KEY_REQUEST: self.exchange_keys,
            MessageType.RUNSPACEPOOL_INIT_DATA: None,
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

    def _process_runspacepool_availability(self, message):
        ci = message.ci
        response = message.response
        ci_handler = self.ci_table[ci]
        response = ci_handler(response)
        self.ci_table[ci] = response
        return response

    def _process_runspacepool_state(self, message):
        self.state = message.data.state
        if self.state in [RunspacePoolState.BROKEN, RunspacePoolState.CLOSED]:
            raise Exception("Failed to initialise RunspacePool")

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
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.powershell?view=powershellsdk-1.1.0
        https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/hostifaces/PowerShell.cs

        :param runspace_pool: The RunspacePool that the PowerShell instance
            will run over
        """
        self.runspace_pool = runspace_pool
        self.state = PSInvocationState.NOT_STARTED

        self.commands = PSCommand()
        self.had_errors = None
        self.history_string = None
        self.id = str(uuid.uuid4()).upper()
        self.is_nested = False
        self.streams = PSDataStreams()

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
        Connects to a running command on a remote server
        :return: Command output as a PSDataCollection
        """
        raise NotImplementedError()

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
        raise NotImplementedError()

    def invoke(self, input=None, add_to_history=False, apartment_state=None,
               host=None,
               remote_stream_options=RemoteStreamOptions.ADD_INVOCATION_INFO,
               raw_output=False):
        """
        Invoke the command and return the output collection of return objects.

        :param input: List of inputs to the command
        :param add_to_history:
        :param apartment_state:
        :param host:
        :param remote_stream_options:
        :param raw_output: Controls whether the output objects will be a raw
            CLIXML representation or whether Python will attempt to convert
            them to a Python type. The object can still be a complex object
            if it is a type not known to pypsrp
        :return: A list of output objects, the type is controlled by raw_output
        """
        if len(self.commands.commands) == 0:
            raise WinRMError("Cannot invoke PowerShell without any commands "
                             "being set")

        no_input = input is None or not input
        apartment_state = apartment_state or self.runspace_pool.apartment_state
        host_info = host or self.runspace_pool.host_info

        pipeline = Pipeline(
            is_nested=self.is_nested,
            cmds=self.commands.commands,
            history=self.history_string,
            # TODO: calc this
            redirect_err_to_out=False
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
        self.runspace_pool.shell._command('',
                                          arguments=[first_frag],
                                          command_id=self.id)
        self.state = PSInvocationState.RUNNING

        # now send the remaining fragments with the send message
        for fragment in fragments:
            self.runspace_pool.shell._send(fragment, command_id=self.id)

        output = []
        while self.state == PSInvocationState.RUNNING:
            responses = self.runspace_pool._receive(self.id)
            for response in responses:
                if response[0] == MessageType.PIPELINE_OUTPUT:
                    output.append(response[1].data.data)

        return output

    def stop(self):
        """
        Stop the currently running command.
        """
        if self.state in [PSInvocationState.STOPPING,
                          PSInvocationState.STOPPED]:
            return

        self.state = PSInvocationState.STOPPING
        self.runspace_pool.shell.signal(SignalCode.TERMINATE,
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
            self.has_errors = True

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
        self.outgoing_object_id = 1
        self.outgoing_buffer = b""
        self.incoming_object_id = 1
        self.incoming_fragment_id = 0
        self.incoming_buffer = b""
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
            fragment = Fragment(self.outgoing_object_id, fragment_id,
                                msg_fragment, start, end)
            fragments.append(fragment.pack())
            fragment_id += 1
            start = False

        self.outgoing_object_id += 1
        return fragments

    def defragment(self, data):
        fragments = []
        while data != b"":
            fragment, data = Fragment.unpack(data)
            if fragment.object_id != self.incoming_object_id:
                raise WinRMError("Fragment Object Id: %d != Expected Object "
                                 "Id: %d" % (fragment.object_id,
                                             self.incoming_object_id))

            if fragment.fragment_id != self.incoming_fragment_id:
                raise WinRMError("Fragment Fragment Id: %d != Expected "
                                 "Fragment Id: %d"
                                 % (fragment.fragment_id,
                                    self.incoming_fragment_id))

            if fragment.start and fragment.end:
                fragments.append(fragment.data)
                self.incoming_object_id += 1
                self.incoming_fragment_id = 0
            elif fragment.start:
                self.incoming_buffer = fragment.data
                self.incoming_fragment_id += 1
            elif fragment.end:
                fragments.append(self.incoming_buffer + fragment.data)
                self.incoming_buffer = b""
                self.incoming_object_id += 1
                self.incoming_fragment_id = 0
            else:
                self.incoming_buffer += fragment.data
                self.incoming_fragment_id += 1

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
