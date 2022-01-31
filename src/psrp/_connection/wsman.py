# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import contextlib
import logging
import ssl
import threading
import typing as t
import uuid
import xml.etree.ElementTree as ElementTree

from psrpcore import ClientRunspacePool, PSRPEvent, PSRPPayload, StreamType
from psrpcore.types import (
    ErrorCategoryInfo,
    ErrorRecord,
    NETException,
    PipelineState,
    PSInvocationState,
    PSRPMessageType,
    PSVersion,
    RunspacePoolState,
    RunspacePoolStateMsg,
)

from psrp._compat import Literal, asyncio_create_task
from psrp._connection.connection import (
    AsyncConnection,
    AsyncEventCallable,
    ConnectionInfo,
    EnumerationPipelineResult,
    EnumerationRunspaceResult,
    OutputBufferingMode,
    SyncConnection,
    SyncEventCallable,
)
from psrp._exceptions import (
    ErrorCancelled,
    OperationAborted,
    OperationTimedOut,
    ServiceStreamDisconnected,
    ShellDisconnected,
    UnexpectedSelectors,
)
from psrp._io.wsman import AsyncWSManHTTP, SyncWSManHTTP, WSManConnectionData
from psrp._winrs import WinRS, enumerate_winrs, receive_winrs_enumeration
from psrp._wsman import (
    NAMESPACES,
    CommandResponseEvent,
    CommandState,
    OptionSet,
    ReceiveResponseEvent,
    SignalCode,
    WSMan,
)

log = logging.getLogger(__name__)

PS_RESOURCE_PREFIX = "http://schemas.microsoft.com/powershell"


def _process_enumeration_response(
    connection_info: "WSManInfo",
    shell: WinRS,
    data: bytes,
) -> EnumerationRunspaceResult:
    shell.wsman
    cmd_enumeration = shell.wsman.receive_data(data)
    pipelines = [
        EnumerationPipelineResult(pid=c.command_id, state=c.state)
        for c in receive_winrs_enumeration(shell.wsman, cmd_enumeration)[1]
    ]

    shell_id = shell.shell_id
    config_name = shell.resource_uri[len(PS_RESOURCE_PREFIX) + 1 :]

    new_connection_info = WSManInfo(
        connection_info.connection_info.connection_uri,
        encryption=connection_info.connection_info.encryption,
        ssl_context=connection_info.connection_info.tls,
        connection_timeout=connection_info.connection_info.connection_timeout,
        read_timeout=connection_info.connection_info.read_timeout,
        auth=connection_info.connection_info.auth,
        username=connection_info.connection_info.username,
        password=connection_info.connection_info.password,
        certificate_pem=connection_info.connection_info.certificate_pem,
        certificate_key_pem=connection_info.connection_info.certificate_key_pem,
        certificate_key_password=connection_info.connection_info.certificate_key_password,
        negotiate_service=connection_info.connection_info.negotiate_service,
        negotiate_hostname=connection_info.connection_info.negotiate_hostname,
        negotiate_send_cbt=connection_info.connection_info.negotiate_send_cbt,
        credssp_ssl_context=connection_info.connection_info.credssp_ssl_context,
        credssp_auth_mechanism=connection_info.connection_info.credssp_auth_mechanism,
        credssp_minimum_version=connection_info.connection_info.credssp_minimum_version,
        max_envelope_size=connection_info.max_envelope_size,
        operation_timeout=connection_info.operation_timeout,
        locale=connection_info.locale,
        data_locale=connection_info.data_locale,
        configuration_name=config_name,
        # TODO: Get these values from rsp:IdletimeOut and rsp:BufferMode
        buffer_mode=connection_info.buffer_mode,
        idle_timeout=connection_info.idle_timeout,
    )
    new_connection_info._shell = shell
    return EnumerationRunspaceResult(
        connection_info=new_connection_info,
        rpid=shell_id,
        state=shell.state,
        pipelines=pipelines,
    )


def _get_fragment_size(
    pool: ClientRunspacePool,
) -> t.Optional[int]:
    """Calculates the fragment size based on the protocol version defaults."""
    if not pool.their_capability:
        return None

    protocol_version = pool.their_capability.protocolversion
    if protocol_version >= PSVersion("2.2"):
        max_envelope_size = 512000
    else:  # pragma: no cover
        max_envelope_size = 153600

    # The fragment size also needs to include the WSMan envelope itself. This
    # is the rough size with some padding.
    max_byte_size = max_envelope_size - 2048

    # Data is sent as Base64 encoded which inflates the size, we need to
    # calculate how large that can be
    base64_size = int(max_byte_size / 4 * 3)
    return base64_size


class WSManInfo(ConnectionInfo):
    """WSMan Connection Info.

    This is a connection info class used to describe how a Runspace Pool will
    connect to the server using the WSMan/WinRM connection type.

    The default TLS context used for HTTPS connections is based on the result
    of:

        >>> httpx.create_ssl_context(verify=verify)

    The `verify` value is based on the `verify` kwarg and can either be a bool
    to turn CA/CN verification on or off or a string for the CA bundle to use
    as a verification source. HTTPX may be configured to load the certifi
    bundle or some other system defined location depending on how it was
    packaged or installed. An explicit SSLContext with custom settings can also
    be passed in with the `ssl_context` keyword argument.

    The `encryption` kwarg controls whether message encryption is applied by
    the authentication context. It can be set to one of these 3 values:

        auto: The default and will apply message encryption when running on
            http only and with the credssp, kerberos, negotiate, or ntlm
            authentication protocol.
        always: Always use message encryption, even if running over https. This
            cannot be used with auth=basic and auth=certificate. This option is
            redundant when connection over https and is useful for ensuring
            message encryption is available over http rather than the implicit
            of no encryption.
        never: Never use message encryption regardless of the scheme and
            authentication protocol use.

    The `message_encryption` attribute can be checked after the dataclass has
    been created to determine if message encryption will be used on this
    connection or not.

    The `auth` kwarg controls the authentication protocols that is used in the
    connection. It can be set to one of the following:

        basic: Uses basic authentication. This should only be used over https
            and only work with local accounts on Windows.
        certificate: Uses X.509 client certificate authentication. This only
            works over https and is mapped to local accounts on Windows.
        credssp: Uses CredSSP auth, username and password must be set.
        kerberos: Uses Kerberos auth.
        negotiate: Attempts to use Kerberos auth with a fallback to NTLM if it
            is unavailable.
        ntlm: Uses NTLM auth.

    The CredSSP TLS context is based on the default of:

        >>> spnego.tls.default_tls_context()

    The default context is set to only allow TLSv1.2 or newer with no CA or CN
    verification. The allowed cipher suites are governed by Python and what it
    allows. To make any changes to these settings it is recommended to first
    create the initial SSLContext using that method and make the required
    changes on that instead of starting from scratch.

    Asyncio on Windows can have problems with closing the vent loop. Using the
    ``ProactorEventLoop`` event loop may solve some of those issues.

    Example:
        To set the ``ProactorEventLoop`` event loop on Windows do::

            asycnio.set_event_loop_policy(asyncio.ProactorEventLoop())

    Args:
        server: The server/hostname/IP/URI to use for connecting to the target.
            The full URI can be passed in here or just the hostname portion. If
            the URI is passed in then scheme, port, path are ignored.
        scheme: Used to designate the connection scheme, `http` or `https`,
            defaults to `http` if `port` is undefined or set to 80 or 5985.
        port: The port used in the connection, defaults to `5985` if no scheme
            is defined otherwise `5985` for `http` and `5986` for `https`.
        path: The URI path used in the connection, defaults to `wsman`.
        encryption: Controls the behaviour of message encryption. This is the
            encryption applied by the authentication protocol and not related
            to TLS/HTTPS encryption.
        ssl_context: The SSL context used as part of the TLS handshake with the
            peer. If not set the default is based on `httpx.create_ssl_context`.
        verify: A simpler method to control the SSL verification options rather
            than providing a custom SSLConect to ssl_context. Set to a boolean
            to enable or disable certificate or a string to the CA path to use
            when verifying the endpoint certificate.
        connection_timeout: The max time, in seconds, to wait for the initial
            connection to the server to complete.
        read_timeout: The max time, in seconds, to wait for each request to
            complete.
        auth: The authentication protocol to use.
        username: The username to authenticate with.
        password: The password to authenticate with.
        certificate_pem: The path to the client authentication certificate. Can
            be set with `certificate_key_pem` to define the cert and key
            separately.
        certificate_key_pem: The path to a client authentication certificate
            key to use with certificate authentication.
        certificate_key_password: The password used to decrypt the client
            certificate key. If not set the key must not be encrypted.
        negotiate_service: Override the service used for Kerberos
            authentication. Defaults to `http`.
        negotiate_hostname: Override the hostname used in the Kerberos SPN.
            Defaults to `None` which uses the HTTP request hostname.
        negotiate_delegate: Delegate the Kerberos ticket to the peer.
        negotiate_send_cbt: Bind the channel binding token to the NTLM or
            Kerberos auth token. Defaults to `True` but can be set to `False`
            to disable CBT.
        credssp_ssl_context: Control the TLS context and settings that are used
            when negotiating CredSSP. By default only TLS 1.2+ is allowed with
            no server certificate verification.
        credssp_auth_mechanism: The sub authentication protocol to use within
            CredSSP. Can be set to kerberos, negotiate, or ntlm. Defaults to
            negotiate. Note the `negotiate_service` and `negotiate_hostname`
            values also apply to the sub authentication protocol in CredSSP.
        credssp_minimum_version: The minimuim CredSSP protocol of the peer that
            the client will connect to.
        max_envelope_size: Override the maximum envelope size used to fragment
            each PSRP packet. The default will be set based on the OS defaults
            of the target protocol version.
        operation_timeout: The timeout to set on a WSMan operation. This should
            be less than read_timeout. This option typically doesn't need to be
            set.
        locale: The locale value to set on the WSMan connection. This specifies
            the language in which the client wants response text to be
            translated. The value should be in the format described by RFC 3066,
            with the default being `en-US`.
        data_locale: The data locale value to set on each WSMan request. This
            specifies the format in which numerical data is presented in the
            response text. The value should be in the format described by RFC
            3066, which the default being the value of locale.
        configuration_name: The PSRP configuration name to use for the
            connection.
        buffer_mode: The buffering mode to use when the session is disconnected.
            If undefined the default is based on the session configuration set
            on the server.
        idle_timeout: The disconnection idle time out value to use. If
            undefined the default is based on the session configuration set on
            the server.

    Attributes:
        connection_info: The WSMan connection settings.
        max_envelope_size: The maximum envelope size used to fragment each PSRP
            packet.
        operation_timeout: The timeout to set on a WSMan operation. This should
            be less than read_timeout.
        locale: The configured locale culture.
        data_locale: The configured data locale culture
        configuration_name: The PSRP configuration name to use for the
            connection.
        buffer_mode: The buffering mode to use when the session is disconnected.
            If undefined the default is based on the session configuration set
            on the server.
        idle_timeout: The disconnection idle time out value to use. If
            undefined the default is based on the session configuration set on
            the server.
    """

    def __init__(
        self,
        server: str,
        *,
        scheme: t.Optional[Literal["http", "https"]] = None,
        port: int = -1,  # Depends on the scheme (5985 if http else 5096)
        path: str = "wsman",
        encryption: Literal["always", "auto", "never"] = "auto",
        ssl_context: t.Optional[ssl.SSLContext] = None,
        verify: t.Union[str, bool] = True,
        connection_timeout: float = 30.0,
        read_timeout: float = 30.0,
        # Authentication
        auth: Literal["basic", "certificate", "credssp", "kerberos", "negotiate", "ntlm"] = "negotiate",
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        # Cert auth
        certificate_pem: t.Optional[str] = None,
        certificate_key_pem: t.Optional[str] = None,
        certificate_key_password: t.Optional[str] = None,
        # SPNEGO
        negotiate_service: str = "http",
        negotiate_hostname: t.Optional[str] = None,
        negotiate_delegate: bool = False,
        negotiate_send_cbt: bool = True,
        # CredSSP
        credssp_ssl_context: t.Optional[ssl.SSLContext] = None,
        credssp_auth_mechanism: Literal["kerberos", "negotiate", "ntlm"] = "negotiate",
        credssp_minimum_version: t.Optional[int] = None,
        # PSRP/WinRM Protocol
        max_envelope_size: t.Optional[int] = None,
        operation_timeout: int = 20,
        locale: str = "en-US",
        data_locale: t.Optional[str] = None,
        configuration_name: str = "Microsoft.PowerShell",
        buffer_mode: OutputBufferingMode = OutputBufferingMode.NONE,
        idle_timeout: t.Optional[int] = None,
    ) -> None:
        self.connection_info = WSManConnectionData(
            server,
            scheme=scheme,
            port=port,
            path=path,
            encryption=encryption,
            ssl_context=ssl_context,
            verify=verify,
            connection_timeout=connection_timeout,
            read_timeout=read_timeout,
            auth=auth,
            username=username,
            password=password,
            certificate_pem=certificate_pem,
            certificate_key_pem=certificate_key_pem,
            certificate_key_password=certificate_key_password,
            negotiate_service=negotiate_service,
            negotiate_hostname=negotiate_hostname,
            negotiate_delegate=negotiate_delegate,
            negotiate_send_cbt=negotiate_send_cbt,
            credssp_ssl_context=credssp_ssl_context,
            credssp_auth_mechanism=credssp_auth_mechanism,
            credssp_minimum_version=credssp_minimum_version,
        )
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout
        self.locale = locale
        self.data_locale = data_locale
        self.configuration_name = configuration_name
        self.buffer_mode = buffer_mode
        self.idle_timeout = idle_timeout

        # Used by enumerate as it contains the required selectors.
        self._shell: t.Optional[WinRS] = None

    def create_sync(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
    ) -> "SyncConnection":
        return SyncWSManConnection(pool, callback, self, self._new_winrs_shell(pool))

    async def create_async(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> "AsyncConnection":
        return AsyncWSManConnection(pool, callback, self, self._new_winrs_shell(pool))

    def enumerate_sync(self) -> t.Iterator["EnumerationRunspaceResult"]:
        connection = SyncWSManHTTP(self.connection_info)
        wsman = WSMan(self.connection_info.connection_uri)

        enumerate_winrs(wsman)
        resp = connection.post(wsman.data_to_send())
        shell_enumeration = wsman.receive_data(resp)

        shells = receive_winrs_enumeration(wsman, shell_enumeration)[0]
        for shell in shells:
            if not shell.resource_uri.startswith(f"{PS_RESOURCE_PREFIX}/"):
                continue

            enumerate_winrs(
                wsman,
                resource_uri="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                selector_filter=shell.selector_set,
            )
            resp = connection.post(wsman.data_to_send())
            yield _process_enumeration_response(self, shell, resp)

    async def enumerate_async(self) -> t.AsyncIterator["EnumerationRunspaceResult"]:
        connection = AsyncWSManHTTP(self.connection_info)
        wsman = WSMan(self.connection_info.connection_uri)

        enumerate_winrs(wsman)
        resp = await connection.post(wsman.data_to_send())
        shell_enumeration = wsman.receive_data(resp)

        shells = receive_winrs_enumeration(wsman, shell_enumeration)[0]
        for shell in shells:
            if not shell.resource_uri.startswith(f"{PS_RESOURCE_PREFIX}/"):
                continue

            enumerate_winrs(
                wsman,
                resource_uri="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                selector_filter=shell.selector_set,
            )
            resp = await connection.post(wsman.data_to_send())
            yield _process_enumeration_response(self, shell, resp)

    def _new_winrs_shell(
        self,
        pool: ClientRunspacePool,
    ) -> WinRS:
        wsman = WSMan(
            self.connection_info.connection_uri,
            operation_timeout=self.operation_timeout,
            locale=self.locale,
            data_locale=self.data_locale,
        )
        return self._shell or WinRS(
            wsman,
            f"{PS_RESOURCE_PREFIX}/{self.configuration_name}",
            shell_id=str(pool.runspace_pool_id).upper(),
            input_streams="stdin pr",
            output_streams="stdout",
        )


class SyncWSManConnection(SyncConnection):
    """Sync Connection for WSMan."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
        info: WSManInfo,
        shell: WinRS,
    ) -> None:
        super().__init__(pool, callback)

        self._info = info
        self._connection = SyncWSManHTTP(self._info.connection_info)

        self._listener_tasks: t.Dict[t.Optional[uuid.UUID], threading.Thread] = {}
        self._stopped_pipelines: t.List[uuid.UUID] = []
        self._shell = shell
        self._pipeline_lookup: t.Dict[uuid.UUID, uuid.UUID] = {}

    def get_fragment_size(self) -> int:
        if not self._info.max_envelope_size:
            self._info.max_envelope_size = _get_fragment_size(self.get_runspace_pool())

        if self._info.max_envelope_size:
            return self._info.max_envelope_size
        else:
            # Pre Win 8/2012 the default was 153600. This is the allowed base64
            # size based on that default.
            return 113664

    def close(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        if pipeline_id and pipeline_id in self._listener_tasks:
            self.signal(pipeline_id, signal_code=SignalCode.TERMINATE)
            pipeline_task = self._listener_tasks.pop(pipeline_id)
            pipeline_task.join()
            del self._pipeline_lookup[pipeline_id]

        elif not pipeline_id:
            # Closing the shell will implicitly stop the pipelines, mark them
            # as stopped so the listener updates the client correctly if needed.
            listener_tasks: t.List[threading.Thread] = []
            for pid in list(self._listener_tasks.keys()):
                listener_tasks.append(self._listener_tasks.pop(pid))

                if not pid:
                    continue

                self._stopped_pipelines.append(pid)

            self._shell.close()
            resp = self._connection.post(self._shell.data_to_send())
            self._shell.receive_data(resp)

            # Ugly hack but WSMan does not send a RnuspacePool state change response on our receive listener so this
            # does it manually to align with the other connection types.
            pool = self.get_runspace_pool()
            if pool.state != RunspacePoolState.Broken:
                pool.state = RunspacePoolState.Closed
                closed_event = PSRPEvent.create(
                    PSRPMessageType.RunspacePoolState,
                    RunspacePoolStateMsg(RunspaceState=pool.state),
                    pool.runspace_pool_id,
                )
                self.process_response(closed_event)

            # Wait for the listener task(s) to complete and remove the RunspacePool from our internal table.
            for task in listener_tasks:
                task.join()

            self._connection.close()

    def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        payload = t.cast(PSRPPayload, self.next_payload())
        self._shell.command("", args=[base64.b64encode(payload.data).decode()], command_id=pipeline_id)
        resp = self._connection.post(self._shell.data_to_send())
        command_resp = t.cast(CommandResponseEvent, self._shell.receive_data(resp))

        # On older Windows hosts (Win 7) the pipeline id specified in the request isn't actually used. Will need to
        # create a mapping table to ensure that the returned command id is used if our pipeline_id is requested.
        self._pipeline_lookup[pipeline_id] = command_resp.command_id

        self._create_listener(pipeline_id)

    def create(self) -> None:
        pool = self.get_runspace_pool()
        payload = t.cast(PSRPPayload, self.next_payload())

        open_content = ElementTree.Element("creationXml", xmlns=PS_RESOURCE_PREFIX)
        open_content.text = base64.b64encode(payload.data).decode()
        options = OptionSet()
        options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})
        self._shell.open(options, open_content)

        resp = self._connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        self._create_listener()

    def send(
        self,
        buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        self._listener_send(payload, self._connection)

        return True

    def _listener_send(
        self,
        payload: PSRPPayload,
        connection: SyncWSManHTTP,
    ) -> None:
        stream = "stdin" if payload.stream_type == StreamType.default else "pr"
        command_id: t.Optional[uuid.UUID] = None
        if payload.pipeline_id:
            command_id = self._pipeline_lookup[payload.pipeline_id]

        self._shell.send(stream, payload.data, command_id=command_id)
        resp = connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

    def signal(
        self,
        pipeline_id: uuid.UUID,
        signal_code: SignalCode = SignalCode.PS_CRTL_C,
    ) -> None:
        self._stopped_pipelines.append(pipeline_id)

        self._shell.signal(signal_code, self._pipeline_lookup[pipeline_id])
        resp = self._connection.post(self._shell.data_to_send())

        # Older Win hosts raise this error when terminating a pipeline, just ignore it.
        with contextlib.suppress(OperationAborted):
            self._shell.receive_data(resp)

    def connect(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        rsp = NAMESPACES["rsp"]
        connect = ElementTree.Element("{%s}Connect" % rsp)
        if pipeline_id:
            connect.attrib["CommandId"] = str(pipeline_id).upper()
            options = None

        else:
            pool = self.get_runspace_pool()
            payload = t.cast(PSRPPayload, self.next_payload())

            options = OptionSet()
            options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})

            open_content = ElementTree.SubElement(connect, "connectXml", xmlns=PS_RESOURCE_PREFIX)
            open_content.text = base64.b64encode(payload.data).decode()

        self._shell.wsman.connect(
            self._shell.resource_uri, connect, option_set=options, selector_set=self._shell.selector_set
        )
        resp = self._connection.post(self._shell.data_to_send())
        event = self._shell.wsman.receive_data(resp)

        if pipeline_id:
            self._pipeline_lookup[pipeline_id] = pipeline_id
        else:
            response_xml = t.cast(
                ElementTree.Element, event.body.find("rsp:ConnectResponse/pwsh:connectResponseXml", NAMESPACES)
            )

            psrp_resp = PSRPPayload(base64.b64decode(response_xml.text or ""), StreamType.default, None)
            pool.receive_data(psrp_resp)

        self._create_listener(pipeline_id=pipeline_id)

    def disconnect(self) -> None:
        rsp = NAMESPACES["rsp"]

        disconnect = ElementTree.Element("{%s}Disconnect" % rsp)
        if self._info.buffer_mode != OutputBufferingMode.NONE:
            buffer_mode_str = "Block" if self._info.buffer_mode == OutputBufferingMode.BLOCK else "Drop"
            ElementTree.SubElement(disconnect, "{%s}BufferMode" % rsp).text = buffer_mode_str

        if self._info.idle_timeout:
            idle_str = f"PT{self._info.idle_timeout}S"
            ElementTree.SubElement(disconnect, "{%s}IdleTimeout" % rsp).text = idle_str

        self._shell.wsman.disconnect(self._shell.resource_uri, disconnect, selector_set=self._shell.selector_set)
        resp = self._connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        pool = self.get_runspace_pool()
        for pipeline_id, pipe in pool.pipeline_table.items():
            if pipe.state in [PSInvocationState.Completed, PSInvocationState.Failed]:
                continue

            pipe.state = PSInvocationState.Disconnected
            disconnected_event = PSRPEvent.create(
                PSRPMessageType.PipelineState,
                PipelineState(
                    PipelineState=pipe.state,
                ),
                runspace_pool_id=pool.runspace_pool_id,
                pipeline_id=pipeline_id,
            )
            self.process_response(disconnected_event)

        for pid in list(self._listener_tasks.keys()):
            self._listener_tasks.pop(pid).join()

    def reconnect(self) -> None:
        self._shell.wsman.reconnect(self._shell.resource_uri, selector_set=self._shell.selector_set)
        resp = self._connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        self._create_listener()

    def _create_listener(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        started = threading.Event()
        task = threading.Thread(target=self._listen, args=(started, pipeline_id))
        self._listener_tasks[pipeline_id] = task
        task.start()
        started.wait()

    def _listen(
        self,
        started: threading.Event,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        command_id: t.Optional[uuid.UUID] = None
        if pipeline_id:
            command_id = self._pipeline_lookup[pipeline_id]

        with SyncWSManHTTP(self._info.connection_info) as conn:
            try:
                while True:
                    self._shell.receive("stdout", command_id=command_id)
                    resp = conn.post(self._shell.data_to_send(), data_sent=None if started.is_set() else started)

                    try:
                        event = t.cast(ReceiveResponseEvent, self._shell.receive_data(resp))

                    except OperationTimedOut:
                        # Occurs when there has been no output after the OperationTimeout set, just repeat the request
                        continue

                    except (
                        ErrorCancelled,
                        OperationAborted,
                        UnexpectedSelectors,
                        ServiceStreamDisconnected,
                        ShellDisconnected,
                    ):
                        # Received when the shell or pipeline has been closed
                        break

                    stream_data = event.streams.get("stdout", [])
                    for psrp_data in stream_data:
                        msg = PSRPPayload(psrp_data, StreamType.default, pipeline_id)

                        payload: t.Optional[PSRPPayload] = None
                        data_available = self.process_response(msg)
                        if data_available:
                            payload = self.next_payload()

                        if payload:
                            self._listener_send(payload, self._connection)

                    # If the command is done then we've got nothing left to do here.
                    if event.command_state == CommandState.DONE:
                        break

            except Exception as e:
                log.exception("WSMan listener encountered unhandled exception")
                started.set()

                if pipeline_id:
                    self._stop_pipeline(pipeline_id, exception=e)

                else:
                    self._break_runspace(exception=e)

            finally:
                # If the shell was closed before the pipelines or due to a rare
                # race condition when a stop signal is sent before the pipeline
                # is fully running the listener may need to notify the the
                # pool that the pipeline has been stopped so the task continues
                # on without blocking.
                if pipeline_id in self._stopped_pipelines:
                    self._stopped_pipelines.remove(pipeline_id)

                    pool = self.get_runspace_pool()
                    pipe = pool.pipeline_table[pipeline_id]
                    if pipe.state != PSInvocationState.Running:
                        return

                    self._stop_pipeline(pipeline_id)

    def _stop_pipeline(
        self,
        pipeline_id: uuid.UUID,
        exception: t.Optional[Exception] = None,
    ) -> None:
        pool = self.get_runspace_pool()
        pipe = pool.pipeline_table[pipeline_id]

        pipe.state = PSInvocationState.Stopped
        error_record: t.Optional[ErrorRecord] = None
        if exception:
            error_record = ErrorRecord(
                Exception=NETException(Message=str(exception)),
                CategoryInfo=ErrorCategoryInfo(),
                TargetObject=exception.__traceback__,
            )

        stopped_event = PSRPEvent.create(
            PSRPMessageType.PipelineState,
            PipelineState(
                PipelineState=pipe.state,
                ExceptionAsErrorRecord=error_record,
            ),
            runspace_pool_id=pool.runspace_pool_id,
            pipeline_id=pipeline_id,
        )
        self.process_response(stopped_event)

    def _break_runspace(
        self,
        exception: t.Optional[Exception] = None,
    ) -> None:
        pool = self.get_runspace_pool()

        pool.state = RunspacePoolState.Broken
        error_record: t.Optional[ErrorRecord] = None
        if exception:
            error_record = ErrorRecord(
                Exception=NETException(Message=str(exception)),
                CategoryInfo=ErrorCategoryInfo(),
                TargetObject=exception.__traceback__,
            )

        broken_event = PSRPEvent.create(
            PSRPMessageType.RunspacePoolState,
            RunspacePoolStateMsg(
                RunspaceState=pool.state,
                ExceptionAsErrorRecord=error_record,
            ),
            runspace_pool_id=pool.runspace_pool_id,
        )
        self.process_response(broken_event)


class AsyncWSManConnection(AsyncConnection):
    """Async Connection for WSMan."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
        info: WSManInfo,
        shell: WinRS,
    ) -> None:
        super().__init__(pool, callback)

        self._info = info
        self._connection = AsyncWSManHTTP(info.connection_info)

        self._listener_tasks: t.Dict[t.Optional[uuid.UUID], asyncio.Task] = {}
        self._stopped_pipelines: t.List[uuid.UUID] = []
        self._shell = shell
        self._pipeline_lookup: t.Dict[uuid.UUID, uuid.UUID] = {}

    def get_fragment_size(self) -> int:
        if not self._info.max_envelope_size:
            self._info.max_envelope_size = _get_fragment_size(self.get_runspace_pool())

        if self._info.max_envelope_size:
            return self._info.max_envelope_size
        else:
            # Pre Win 8/2012 the default was 153600. This is the allowed base64
            # size based on that default.
            return 113664

    async def close(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        if pipeline_id and pipeline_id in self._listener_tasks:
            await self.signal(pipeline_id, signal_code=SignalCode.TERMINATE)
            pipeline_task = self._listener_tasks.pop(pipeline_id)
            await pipeline_task
            del self._pipeline_lookup[pipeline_id]

        elif not pipeline_id:
            # Closing the shell will implicitly stop the pipelines, mark them
            # as stopped so the listener updates the client correctly if needed.
            listener_tasks: t.List[asyncio.Task] = []
            for pid in list(self._listener_tasks.keys()):
                listener_tasks.append(self._listener_tasks.pop(pid))

                if not pid:
                    continue

                self._stopped_pipelines.append(pid)

            self._shell.close()
            resp = await self._connection.post(self._shell.data_to_send())
            self._shell.receive_data(resp)

            # Ugly hack but WSMan does not send a RnuspacePool state change response on our receive listener so this
            # does it manually to align with the other connection types.
            pool = self.get_runspace_pool()
            pool.state = RunspacePoolState.Closed
            closed_event = PSRPEvent.create(
                PSRPMessageType.RunspacePoolState,
                RunspacePoolStateMsg(RunspaceState=pool.state),
                pool.runspace_pool_id,
            )
            await self.process_response(closed_event)

            # Wait for the listener task(s) to complete and remove the RunspacePool from our internal table.
            await asyncio.gather(*listener_tasks)
            await self._connection.close()

    async def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        payload = t.cast(PSRPPayload, self.next_payload())
        self._shell.command("", args=[base64.b64encode(payload.data).decode()], command_id=pipeline_id)
        resp = await self._connection.post(self._shell.data_to_send())
        command_resp = t.cast(CommandResponseEvent, self._shell.receive_data(resp))

        # On older Windows hosts (Win 7) the pipeline id specified in the request isn't actually used. Will need to
        # create a mapping table to ensure that the returned command id is used if our pipeline_id is requested.
        self._pipeline_lookup[pipeline_id] = command_resp.command_id

        await self._create_listener(pipeline_id)

    async def create(self) -> None:
        pool = self.get_runspace_pool()
        payload = t.cast(PSRPPayload, self.next_payload())

        open_content = ElementTree.Element("creationXml", xmlns=PS_RESOURCE_PREFIX)
        open_content.text = base64.b64encode(payload.data).decode()
        options = OptionSet()
        options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})
        self._shell.open(options, open_content)

        resp = await self._connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        await self._create_listener()

    async def send(
        self,
        buffer: bool = False,
    ) -> bool:
        payload = self.next_payload(buffer=buffer)
        if not payload:
            return False

        await self._listener_send(payload, self._connection)
        return True

    async def _listener_send(
        self,
        payload: PSRPPayload,
        connection: AsyncWSManHTTP,
    ) -> None:
        stream = "stdin" if payload.stream_type == StreamType.default else "pr"
        command_id: t.Optional[uuid.UUID] = None
        if payload.pipeline_id:
            command_id = self._pipeline_lookup[payload.pipeline_id]

        self._shell.send(stream, payload.data, command_id=command_id)
        resp = await connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

    async def signal(
        self,
        pipeline_id: uuid.UUID,
        signal_code: SignalCode = SignalCode.PS_CRTL_C,
    ) -> None:
        self._stopped_pipelines.append(pipeline_id)

        self._shell.signal(signal_code, self._pipeline_lookup[pipeline_id])
        resp = await self._connection.post(self._shell.data_to_send())

        # Older Win hosts raise this error when terminating a pipeline, just ignore it.
        with contextlib.suppress(OperationAborted):
            self._shell.receive_data(resp)

    async def connect(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        rsp = NAMESPACES["rsp"]
        connect = ElementTree.Element("{%s}Connect" % rsp)
        if pipeline_id:
            connect.attrib["CommandId"] = str(pipeline_id).upper()
            options = None

        else:
            pool = self.get_runspace_pool()
            payload = t.cast(PSRPPayload, self.next_payload())

            options = OptionSet()
            options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})

            open_content = ElementTree.SubElement(connect, "connectXml", xmlns=PS_RESOURCE_PREFIX)
            open_content.text = base64.b64encode(payload.data).decode()

        self._shell.wsman.connect(
            self._shell.resource_uri, connect, option_set=options, selector_set=self._shell.selector_set
        )
        resp = await self._connection.post(self._shell.data_to_send())
        event = self._shell.wsman.receive_data(resp)

        if pipeline_id:
            self._pipeline_lookup[pipeline_id] = pipeline_id
        else:
            response_xml = t.cast(
                ElementTree.Element, event.body.find("rsp:ConnectResponse/pwsh:connectResponseXml", NAMESPACES)
            )

            psrp_resp = PSRPPayload(base64.b64decode(response_xml.text or ""), StreamType.default, None)
            pool.receive_data(psrp_resp)

        await self._create_listener(pipeline_id=pipeline_id)

    async def disconnect(self) -> None:
        rsp = NAMESPACES["rsp"]

        disconnect = ElementTree.Element("{%s}Disconnect" % rsp)
        if self._info.buffer_mode != OutputBufferingMode.NONE:
            buffer_mode_str = "Block" if self._info.buffer_mode == OutputBufferingMode.BLOCK else "Drop"
            ElementTree.SubElement(disconnect, "{%s}BufferMode" % rsp).text = buffer_mode_str

        if self._info.idle_timeout:
            idle_str = f"PT{self._info.idle_timeout}S"
            ElementTree.SubElement(disconnect, "{%s}IdleTimeout" % rsp).text = idle_str

        self._shell.wsman.disconnect(self._shell.resource_uri, disconnect, selector_set=self._shell.selector_set)
        resp = await self._connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        pool = self.get_runspace_pool()
        for pipeline_id, pipe in pool.pipeline_table.items():
            if pipe.state in [PSInvocationState.Completed, PSInvocationState.Failed]:
                continue

            pipe.state = PSInvocationState.Disconnected
            disconnected_event = PSRPEvent.create(
                PSRPMessageType.PipelineState,
                PipelineState(
                    PipelineState=pipe.state,
                ),
                runspace_pool_id=pool.runspace_pool_id,
                pipeline_id=pipeline_id,
            )
            await self.process_response(disconnected_event)

        await asyncio.gather(*self._listener_tasks.values())
        self._listener_tasks = {}

    async def reconnect(self) -> None:
        self._shell.wsman.reconnect(self._shell.resource_uri, selector_set=self._shell.selector_set)
        resp = await self._connection.post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        await self._create_listener()

    async def _create_listener(
        self,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        started = asyncio.Event()
        task = asyncio_create_task(self._listen(started, pipeline_id))
        self._listener_tasks[pipeline_id] = task
        await started.wait()

    async def _listen(
        self,
        started: asyncio.Event,
        pipeline_id: t.Optional[uuid.UUID] = None,
    ) -> None:
        command_id: t.Optional[uuid.UUID] = None
        if pipeline_id:
            command_id = self._pipeline_lookup[pipeline_id]

        async with AsyncWSManHTTP(self._info.connection_info) as conn:
            try:
                while True:
                    self._shell.receive("stdout", command_id=command_id)
                    resp = await conn.post(self._shell.data_to_send(), data_sent=None if started.is_set() else started)

                    try:
                        event = t.cast(ReceiveResponseEvent, self._shell.receive_data(resp))

                    except OperationTimedOut:
                        # Occurs when there has been no output after the OperationTimeout set, just repeat the request
                        continue

                    except (
                        ErrorCancelled,
                        OperationAborted,
                        UnexpectedSelectors,
                        ServiceStreamDisconnected,
                        ShellDisconnected,
                    ) as e:
                        # Received when the shell or pipeline has been closed
                        break

                    stream_data = event.streams.get("stdout", [])
                    for psrp_data in stream_data:
                        msg = PSRPPayload(psrp_data, StreamType.default, pipeline_id)

                        payload: t.Optional[PSRPPayload] = None
                        data_available = await self.process_response(msg)
                        if data_available:
                            payload = self.next_payload()

                        if payload:
                            await self._listener_send(payload, self._connection)

                    # If the command is done then we've got nothing left to do here.
                    if pipeline_id and event.command_state == CommandState.DONE:
                        break

            except Exception as e:
                log.exception("WSMan listener encountered unhandled exception")
                started.set()

                if pipeline_id:
                    await self._stop_pipeline(pipeline_id, exception=e)

                else:
                    await self._break_runspace(exception=e)

            finally:
                # If the shell was closed before the pipelines or due to a rare
                # race condition when a stop signal is sent before the pipeline
                # is fully running the listener may need to notify the the
                # pool that the pipeline has been stopped so the task continues
                # on without blocking.
                if pipeline_id in self._stopped_pipelines:
                    self._stopped_pipelines.remove(pipeline_id)

                    pool = self.get_runspace_pool()
                    pipe = pool.pipeline_table[pipeline_id]
                    if pipe.state != PSInvocationState.Running:
                        return

                    await self._stop_pipeline(pipeline_id)

    async def _stop_pipeline(
        self,
        pipeline_id: uuid.UUID,
        exception: t.Optional[Exception] = None,
    ) -> None:
        pool = self.get_runspace_pool()
        pipe = pool.pipeline_table[pipeline_id]

        pipe.state = PSInvocationState.Stopped
        error_record: t.Optional[ErrorRecord] = None
        if exception:
            error_record = ErrorRecord(
                Exception=NETException(Message=str(exception)),
                CategoryInfo=ErrorCategoryInfo(),
                TargetObject=exception.__traceback__,
            )

        stopped_event = PSRPEvent.create(
            PSRPMessageType.PipelineState,
            PipelineState(
                PipelineState=pipe.state,
                ExceptionAsErrorRecord=error_record,
            ),
            runspace_pool_id=pool.runspace_pool_id,
            pipeline_id=pipeline_id,
        )
        await self.process_response(stopped_event)

    async def _break_runspace(
        self,
        exception: t.Optional[Exception] = None,
    ) -> None:
        pool = self.get_runspace_pool()

        pool.state = RunspacePoolState.Broken
        error_record: t.Optional[ErrorRecord] = None
        if exception:
            error_record = ErrorRecord(
                Exception=NETException(Message=str(exception)),
                CategoryInfo=ErrorCategoryInfo(),
                TargetObject=exception.__traceback__,
            )

        broken_event = PSRPEvent.create(
            PSRPMessageType.RunspacePoolState,
            RunspacePoolStateMsg(
                RunspaceState=pool.state,
                ExceptionAsErrorRecord=error_record,
            ),
            runspace_pool_id=pool.runspace_pool_id,
        )
        await self.process_response(broken_event)
