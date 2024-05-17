# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import base64
import collections.abc
import contextlib
import ipaddress
import logging
import ssl
import threading
import typing as t
import urllib.parse
import uuid
import xml.etree.ElementTree as ElementTree

import httpcore
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

from .. import _wsman as wsman
from .._exceptions import PSRPAuthenticationError, PSRPConnectionError
from .connection import (
    AsyncConnection,
    AsyncEventCallable,
    ConnectionInfo,
    EnumerationPipelineResult,
    EnumerationRunspaceResult,
    OutputBufferingMode,
    SyncConnection,
    SyncEventCallable,
)

log = logging.getLogger(__name__)

PS_RESOURCE_PREFIX = "http://schemas.microsoft.com/powershell"


def _build_url(
    server: str,
    *,
    scheme: str | None = None,
    port: int | None = None,
    path: str | None = None,
    default_ports: tuple[int, int] = (5985, 5986),
) -> tuple[str, bool, str]:
    url_split = urllib.parse.urlsplit(server)

    if url_split.scheme and url_split.netloc:
        return server, url_split.scheme == "https", url_split.netloc.split(":")[0]

    else:
        # Wrap IPv6 server inside [].
        try:
            address = ipaddress.IPv6Address(server)
        except ipaddress.AddressValueError:
            pass
        else:
            server = f"[{address.compressed}]"

        if not scheme:
            scheme = "https" if port in [443, 5986] else "http"

        if port is None:
            port = default_ports[0] if scheme == "http" else default_ports[1]

        if path is None:
            path = "wsman" if port in [5985, 5986] else ""

        return f"{scheme}://{server}:{port}/{path}", scheme == "https", server


@contextlib.contextmanager
def _map_wsman_exceptions() -> collections.abc.Iterator[None]:
    """Maps any of the wsman connection exceptions to public ones exposed by this library."""
    try:
        yield
    except wsman.WSManAuthenticationError as e:
        # Authentication problems
        raise PSRPAuthenticationError(str(e)) from e

    except wsman.WSManHTTPError as e:
        # HTTP status that wasn't 2xx
        raise PSRPConnectionError(str(e)) from e

    except wsman.WSManFault as e:
        # WSMan fault under HTTP Status 5xx
        raise

    except httpcore.TimeoutException as e:
        raise PSRPConnectionError(str(e)) from e

    except httpcore.NetworkError as e:
        raise PSRPConnectionError(str(e)) from e


def _process_enumeration_response(
    connection_info: WSManInfo,
    shell: wsman.WinRS,
    data: bytes,
) -> EnumerationRunspaceResult:
    pipelines = [
        EnumerationPipelineResult(pid=c.command_id, state=c.state)
        for c in wsman.WinRS.receive_winrs_enumeration(shell.wsman, data)[1]
    ]

    return EnumerationRunspaceResult(
        connection_info=connection_info._copy_with_shell(shell),
        rpid=shell.shell_id,
        state=shell.state,
        pipelines=pipelines,
    )


def _get_fragment_size(
    pool: ClientRunspacePool,
) -> int | None:
    """Calculates the fragment size based on the protocol version defaults."""
    if not pool.their_capability:
        return None

    protocol_version = pool.their_capability.protocolversion
    if protocol_version >= PSVersion("2.2"):
        max_envelope_size = 512000
    else:  # pragma: no cover
        max_envelope_size = 153600

    # The fragment size also needs to include the WSManClient envelope itself. This
    # is the rough size with some padding.
    max_byte_size = max_envelope_size - 2048

    # Data is sent as Base64 encoded which inflates the size, we need to
    # calculate how large that can be
    base64_size = int(max_byte_size / 4 * 3)
    return base64_size


class WSManInfo(ConnectionInfo):
    """WSManClient Connection Info.

    This is a connection info class used to describe how a Runspace Pool will
    connect to the server using the WSManClient/WinRM connection type.

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
        operation_timeout: The timeout to set on a WSManClient operation. This should
            be less than read_timeout. This option typically doesn't need to be
            set.
        locale: The locale value to set on the WSManClient connection. This specifies
            the language in which the client wants response text to be
            translated. The value should be in the format described by RFC 3066,
            with the default being `en-US`.
        data_locale: The data locale value to set on each WSManClient request. This
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
    """

    def __init__(
        self,
        server: str,
        *,
        scheme: t.Literal["http", "https"] | None = None,
        port: int | None = None,
        path: str | None = None,
        encryption: bool | t.Literal["always", "auto", "never"] = "auto",
        ssl_context: ssl.SSLContext | None = None,
        verify: bool | str = True,
        connection_timeout: float = 30.0,
        read_timeout: float = 30.0,
        # Authentication
        auth: (
            wsman.AuthProvider | t.Literal["basic", "certificate", "credssp", "kerberos", "negotiate", "ntlm"]
        ) = "negotiate",
        username: str | None = None,
        password: str | None = None,
        # Cert auth
        certificate_pem: str | None = None,
        certificate_key_pem: str | None = None,
        certificate_key_password: str | None = None,
        # SPNEGO
        negotiate_service: str | None = None,
        negotiate_hostname: str | None = None,
        negotiate_delegate: bool = False,
        # CredSSP
        credssp_ssl_context: ssl.SSLContext | None = None,
        credssp_auth_mechanism: t.Literal["kerberos", "negotiate", "ntlm"] | None = None,
        credssp_minimum_version: int | None = None,
        # Proxies
        proxy_url: str | wsman.Proxy | None = None,
        proxy_ssl_context: ssl.SSLContext | None = None,
        proxy_ssl_verify: bool | str = True,
        proxy_username: str | None = None,
        proxy_password: str | None = None,
        proxy_auth: t.Literal["basic", "kerberos", "negotiate", "ntlm"] | None = None,
        proxy_negotiate_hostname: str | None = None,
        proxy_negotiate_service: str | None = None,
        # PSRP/WinRM Protocol
        max_envelope_size: int | None = None,
        operation_timeout: int = 20,
        locale: str = "en-US",
        data_locale: str | None = None,
        configuration_name: str = "Microsoft.PowerShell",
        buffer_mode: OutputBufferingMode = OutputBufferingMode.NONE,
        idle_timeout: int | None = None,
    ) -> None:
        self._connection_uri, is_tls, hostname = _build_url(
            server,
            scheme=scheme,
            port=port,
            path=path,
            default_ports=(5985, 5986),
        )
        self._connection_timeout = connection_timeout
        self._read_timeout = read_timeout

        self._ssl_context: ssl.SSLContext | None = None
        if is_tls:
            if ssl_context:
                self._ssl_context = ssl_context
            else:
                self._ssl_context = wsman.create_ssl_context(
                    verify=verify,
                    certfile=certificate_pem,
                    keyfile=certificate_key_pem,
                    password=certificate_key_password,
                )

        self._proxy: wsman.Proxy | None = None
        if isinstance(proxy_url, wsman.Proxy):
            self._proxy = proxy_url

        elif proxy_url:
            parse_proxy_url, is_proxy_tls, proxy_hostname = _build_url(
                proxy_url,
                path="",
                # FIXME: Set default ports for socks
                default_ports=(80, 443),
            )

            if proxy_username and not proxy_auth:
                proxy_auth = "basic"

            proxy_auth_provider = None
            if proxy_auth:
                proxy_auth_provider = wsman.AuthProvider.create(
                    auth=proxy_auth,
                    username=proxy_username,
                    password=proxy_password,
                    negotiate_hostname=proxy_negotiate_hostname or proxy_hostname,
                    negotiate_service=proxy_negotiate_service,
                    negotiate_delegate=False,
                    # Kerb/Negotiate proxies don't work well with mutual auth as
                    # they don't respond with the final token. As mutual auth
                    # only matters for the Windows target it's ok to disable.
                    negotiate_ignore_mutual=True,
                )

            proxy_url_lower = parse_proxy_url.lower()
            if proxy_url_lower.startswith("http://") or proxy_url_lower.startswith("https://"):
                if is_proxy_tls and not proxy_ssl_context:
                    proxy_ssl_context = wsman.create_ssl_context(
                        verify=proxy_ssl_verify,
                    )

                self._proxy = wsman.HTTPProxy(
                    url=parse_proxy_url,
                    connect_timeout=connection_timeout,
                    auth_provider=proxy_auth_provider,
                    ssl_context=proxy_ssl_context,
                    tunnel=is_tls,
                )

            elif proxy_url_lower.startswith("socks5://") or proxy_url_lower.startswith("socks5h://"):
                self._proxy = wsman.SOCKS5Proxy(
                    url=parse_proxy_url,
                    connect_timeout=connection_timeout,
                    auth_provider=proxy_auth_provider,
                )

            else:
                raise ValueError("Unknown proxy scheme")

        self._max_envelope_size = max_envelope_size
        self._operation_timeout = operation_timeout
        self._locale = locale
        self._data_locale = data_locale
        self._configuration_name = configuration_name
        self._buffer_mode = buffer_mode
        self._idle_timeout = idle_timeout

        if isinstance(auth, wsman.AuthProvider):
            self._auth_provider = auth
        else:
            self._auth_provider = wsman.AuthProvider.create(
                auth=auth,
                username=username,
                password=password,
                negotiate_hostname=negotiate_hostname or hostname,
                negotiate_service=negotiate_service,
                negotiate_delegate=negotiate_delegate,
                credssp_minimum_version=credssp_minimum_version,
                credssp_ssl_context=credssp_ssl_context,
                credssp_auth_mechanism=credssp_auth_mechanism,
            )

        if isinstance(self._auth_provider, wsman.WSManCertificateAuth):
            if not is_tls:
                raise ValueError("Auth protocol certificate can only be used with a https connection")

            elif not certificate_pem:
                raise ValueError("Auth protocol certificate requires the certificate_pem value to be specified")

        self._message_encryption: bool
        if isinstance(encryption, bool):
            self._message_encryption = encryption

        elif encryption == "always":
            self._message_encryption = True

        elif encryption == "auto":
            self._message_encryption = not is_tls

        elif encryption == "never":
            self._message_encryption = False

        else:
            raise ValueError(f"Invalid encryption value '{encryption}', must be always, auto, or never")

        if self._message_encryption and not isinstance(self._auth_provider, wsman.WSManEncryptionProvider):
            msg = "".join(
                [
                    f"Message encryption has been enabled but authentication provider '{type(self._auth_provider)} ",
                    "does not support message encryption. Either use a https endpoint, set encryption='never', or ",
                    "use a different authentication provider which supports message encryption",
                ]
            )
            raise ValueError(msg)

        # Used by enumerate as it contains the required selectors.
        self._shell: wsman.WinRS | None = None

    @property
    def connection_uri(self) -> str:
        """The WSMan connection URI that will be used."""
        return self._connection_uri

    @property
    def max_envelope_size(self) -> int | None:
        """The maximum enveloper size used to fragment each PSRP packet."""
        return self._max_envelope_size

    @property
    def operation_timeout(self) -> int:
        """The timeout, in seconds, to set on a WSMan operation."""
        return self._operation_timeout

    @property
    def locale(self) -> str:
        """The configured locale culutre."""
        return self._locale

    @property
    def data_locale(self) -> str | None:
        """The configured data locale culture."""
        return self._data_locale

    @property
    def configuration_name(self) -> str | None:
        """The PSRP configuration name to use for the connection."""
        return self._configuration_name

    @property
    def buffer_mode(self) -> OutputBufferingMode:
        """The buffering mode to use when the session is disconnected."""
        return self._buffer_mode

    @property
    def idle_timeout(self) -> int | None:
        """The disconnection idle timeout value to use."""
        return self._idle_timeout

    def create_sync(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
    ) -> "SyncWSManConnection":
        return SyncWSManConnection(
            pool,
            callback,
            self.buffer_mode,
            self.idle_timeout,
            self.max_envelope_size,
            self._new_winrs_shell(pool),
            self._new_sync_connection(),
        )

    async def create_async(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
    ) -> "AsyncWSManConnection":
        return AsyncWSManConnection(
            pool,
            callback,
            self.buffer_mode,
            self.idle_timeout,
            self.max_envelope_size,
            self._new_winrs_shell(pool),
            self._new_async_connection(),
        )

    def enumerate_sync(self) -> collections.abc.Iterator[EnumerationRunspaceResult]:
        with self._new_sync_connection() as connection:
            client = wsman.WSManClient(self.connection_uri)

            wsman.WinRS.enumerate_winrs(client)
            with _map_wsman_exceptions():
                resp = connection.wsman_post(client.data_to_send())

            shells = wsman.WinRS.receive_winrs_enumeration(client, resp)[0]
            for shell in shells:
                if not shell.resource_uri.startswith(f"{PS_RESOURCE_PREFIX}/"):
                    continue

                wsman.WinRS.enumerate_winrs(
                    client,
                    resource_uri="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                    selector_filter=shell.selector_set,
                )
                with _map_wsman_exceptions():
                    resp = connection.wsman_post(client.data_to_send())
                yield _process_enumeration_response(self, shell, resp)

    async def enumerate_async(self) -> collections.abc.AsyncIterator[EnumerationRunspaceResult]:
        async with self._new_async_connection() as connection:
            client = wsman.WSManClient(self.connection_uri)

            wsman.WinRS.enumerate_winrs(client)
            with _map_wsman_exceptions():
                resp = await connection.wsman_post(client.data_to_send())

            shells = wsman.WinRS.receive_winrs_enumeration(client, resp)[0]
            for shell in shells:
                if not shell.resource_uri.startswith(f"{PS_RESOURCE_PREFIX}/"):
                    continue

                wsman.WinRS.enumerate_winrs(
                    client,
                    resource_uri="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                    selector_filter=shell.selector_set,
                )
                with _map_wsman_exceptions():
                    resp = await connection.wsman_post(client.data_to_send())
                yield _process_enumeration_response(self, shell, resp)

    def _copy_with_shell(
        self,
        shell: wsman.WinRS,
    ) -> WSManInfo:
        config_name = shell.resource_uri[len(PS_RESOURCE_PREFIX) + 1 :]

        info = WSManInfo(
            self.connection_uri,
            ssl_context=self._ssl_context,
            encryption=self._message_encryption,
            connection_timeout=self._connection_timeout,
            read_timeout=self._read_timeout,
            auth=self._auth_provider.copy(),
            proxy_url=self._proxy.copy() if self._proxy else None,
            max_envelope_size=self.max_envelope_size,
            operation_timeout=self.operation_timeout,
            locale=self.locale,
            data_locale=self.data_locale,
            configuration_name=config_name,
            # TODO: Get these values from rsp:IdletimeOut and rsp:BufferMode
            buffer_mode=self.buffer_mode,
            idle_timeout=self.idle_timeout,
        )
        info._shell = shell

        return info

    def _new_async_connection(self) -> wsman.AsyncWSManHTTP:
        return wsman.AsyncWSManHTTP(
            url=self.connection_uri,
            auth_provider=self._auth_provider,
            connect_timeout=self._connection_timeout,
            encrypt=self._message_encryption,
            ssl_context=self._ssl_context,
            proxy=self._proxy,
        )

    def _new_sync_connection(self) -> wsman.SyncWSManHTTP:
        return wsman.SyncWSManHTTP(
            url=self.connection_uri,
            auth_provider=self._auth_provider,
            connect_timeout=self._connection_timeout,
            encrypt=self._message_encryption,
            ssl_context=self._ssl_context,
            proxy=self._proxy,
        )

    def _new_winrs_shell(
        self,
        pool: ClientRunspacePool,
    ) -> wsman.WinRS:
        client = wsman.WSManClient(
            self.connection_uri,
            operation_timeout=self.operation_timeout,
            locale=self.locale,
            data_locale=self.data_locale,
        )
        return self._shell or wsman.WinRS(
            client,
            f"{PS_RESOURCE_PREFIX}/{self.configuration_name}",
            shell_id=str(pool.runspace_pool_id).upper(),
            input_streams="stdin pr",
            output_streams="stdout",
        )


class SyncWSManConnection(SyncConnection):
    """Sync Connection for WSManClient."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: SyncEventCallable,
        buffer_mode: OutputBufferingMode,
        idle_timeout: int | None,
        max_envelope_size: int | None,
        shell: wsman.WinRS,
        connection: wsman.SyncWSManHTTP,
    ) -> None:
        super().__init__(pool, callback)

        self._buffer_mode = buffer_mode
        self._connection = connection
        self._idle_timeout = idle_timeout
        self._listener_tasks: dict[uuid.UUID | None, threading.Thread] = {}
        self._max_envelope_size = max_envelope_size
        self._stopped_pipelines: list[uuid.UUID] = []
        self._shell = shell
        self._pipeline_lookup: dict[uuid.UUID, uuid.UUID] = {}

    def get_fragment_size(self) -> int:
        if not self._max_envelope_size:
            self._max_envelope_size = _get_fragment_size(self.get_runspace_pool())

        if self._max_envelope_size:
            return self._max_envelope_size
        else:
            # Pre Win 8/2012 the default was 153600. This is the allowed base64
            # size based on that default.
            return 113664

    def close(
        self,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        if pipeline_id and pipeline_id in self._listener_tasks:
            pipeline_task = self._listener_tasks.pop(pipeline_id)
            self.signal(pipeline_id, signal_code=wsman.SignalCode.TERMINATE)
            pipeline_task.join()
            del self._pipeline_lookup[pipeline_id]

        elif not pipeline_id:
            # Closing the shell will implicitly stop the pipelines, mark them
            # as stopped so the listener updates the client correctly if needed.
            listener_tasks: list[threading.Thread] = []
            for pid in list(self._listener_tasks.keys()):
                listener_tasks.append(self._listener_tasks.pop(pid))

                if not pid:
                    continue

                self._stopped_pipelines.append(pid)

            self._shell.close()
            with _map_wsman_exceptions():
                resp = self._connection.wsman_post(self._shell.data_to_send())
            self._shell.receive_data(resp)

            # Ugly hack but WSManClient does not send a RnuspacePool state change response on our receive listener so this
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
        with _map_wsman_exceptions():
            resp = self._connection.wsman_post(self._shell.data_to_send())
        command_resp = t.cast(wsman.CommandResponseEvent, self._shell.receive_data(resp))

        # On older Windows hosts (Win 7) the pipeline id specified in the request isn't actually used. Will need to
        # create a mapping table to ensure that the returned command id is used if our pipeline_id is requested.
        self._pipeline_lookup[pipeline_id] = command_resp.command_id

        self._create_listener(pipeline_id)

    def create(self) -> None:
        pool = self.get_runspace_pool()
        payload = t.cast(PSRPPayload, self.next_payload())

        open_content = ElementTree.Element("creationXml", xmlns=PS_RESOURCE_PREFIX)
        open_content.text = base64.b64encode(payload.data).decode()
        options = wsman.OptionSet()
        options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})
        self._shell.open(options, open_content)

        with _map_wsman_exceptions():
            resp = self._connection.wsman_post(self._shell.data_to_send())
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
        connection: wsman.SyncWSManHTTP,
    ) -> None:
        stream = "stdin" if payload.stream_type == StreamType.default else "pr"
        command_id: uuid.UUID | None = None
        if payload.pipeline_id:
            command_id = self._pipeline_lookup[payload.pipeline_id]

        self._shell.send(stream, payload.data, command_id=command_id)
        with _map_wsman_exceptions():
            resp = connection.wsman_post(self._shell.data_to_send())
        self._shell.receive_data(resp)

    def signal(
        self,
        pipeline_id: uuid.UUID,
        signal_code: wsman.SignalCode = wsman.SignalCode.PS_CRTL_C,
    ) -> None:
        self._stopped_pipelines.append(pipeline_id)

        self._shell.signal(signal_code, self._pipeline_lookup[pipeline_id])
        with _map_wsman_exceptions():
            resp = self._connection.wsman_post(self._shell.data_to_send())

        # Older Win hosts raise this error when terminating a pipeline, just ignore it.
        with contextlib.suppress(wsman.OperationAborted):
            self._shell.receive_data(resp)

    def connect(
        self,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        rsp = wsman.NAMESPACES["rsp"]
        connect = ElementTree.Element("{%s}Connect" % rsp)
        if pipeline_id:
            connect.attrib["CommandId"] = str(pipeline_id).upper()
            options = None

        else:
            pool = self.get_runspace_pool()
            payload = t.cast(PSRPPayload, self.next_payload())

            options = wsman.OptionSet()
            options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})

            open_content = ElementTree.SubElement(connect, "connectXml", xmlns=PS_RESOURCE_PREFIX)
            open_content.text = base64.b64encode(payload.data).decode()

        self._shell.wsman.connect(
            self._shell.resource_uri, connect, option_set=options, selector_set=self._shell.selector_set
        )
        with _map_wsman_exceptions():
            resp = self._connection.wsman_post(self._shell.data_to_send())
        event = self._shell.wsman.receive_data(resp)

        if pipeline_id:
            self._pipeline_lookup[pipeline_id] = pipeline_id
        else:
            response_xml = t.cast(
                ElementTree.Element, event.body.find("rsp:ConnectResponse/pwsh:connectResponseXml", wsman.NAMESPACES)
            )

            psrp_resp = PSRPPayload(base64.b64decode(response_xml.text or ""), StreamType.default, None)
            pool.receive_data(psrp_resp)

        self._create_listener(pipeline_id=pipeline_id)

    def disconnect(self) -> None:
        rsp = wsman.NAMESPACES["rsp"]

        disconnect = ElementTree.Element("{%s}Disconnect" % rsp)
        if self._buffer_mode != OutputBufferingMode.NONE:
            buffer_mode_str = "Block" if self._buffer_mode == OutputBufferingMode.BLOCK else "Drop"
            ElementTree.SubElement(disconnect, "{%s}BufferMode" % rsp).text = buffer_mode_str

        if self._idle_timeout:
            idle_str = f"PT{self._idle_timeout}S"
            ElementTree.SubElement(disconnect, "{%s}IdleTimeout" % rsp).text = idle_str

        listener_tasks = self._listener_tasks.values()
        self._listener_tasks = {}

        self._shell.wsman.disconnect(self._shell.resource_uri, disconnect, selector_set=self._shell.selector_set)
        with _map_wsman_exceptions():
            resp = self._connection.wsman_post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        for task in listener_tasks:
            task.join()

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

    def reconnect(self) -> None:
        self._shell.wsman.reconnect(self._shell.resource_uri, selector_set=self._shell.selector_set)
        with _map_wsman_exceptions():
            resp = self._connection.wsman_post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        self._create_listener()

    def _create_listener(
        self,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        started = threading.Event()
        task = threading.Thread(target=self._listen, args=(started, pipeline_id))
        self._listener_tasks[pipeline_id] = task
        task.start()
        # started.wait()

    def _listen(
        self,
        started: threading.Event,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        command_id: uuid.UUID | None = None
        if pipeline_id:
            command_id = self._pipeline_lookup[pipeline_id]

        with self._connection.copy() as conn:
            try:
                while True:
                    self._shell.receive("stdout", command_id=command_id)
                    # resp = conn.wsman_post(self._shell.data_to_send(), data_sent=None if started.is_set() else started)
                    with _map_wsman_exceptions():
                        resp = conn.wsman_post(self._shell.data_to_send())

                    try:
                        event = t.cast(wsman.ReceiveResponseEvent, self._shell.receive_data(resp))

                    except wsman.OperationTimedOut:
                        # Occurs when there has been no output after the OperationTimeout set, just repeat the request
                        continue

                    except (
                        wsman.ErrorCancelled,
                        wsman.OperationAborted,
                        wsman.UnexpectedSelectors,
                        wsman.ServiceStreamDisconnected,
                        wsman.ShellDisconnected,
                    ):
                        if pipeline_id not in self._listener_tasks:
                            # Received when the shell or pipeline has been closed
                            break

                        else:
                            raise

                    stream_data = event.streams.get("stdout", [])
                    for psrp_data in stream_data:
                        msg = PSRPPayload(psrp_data, StreamType.default, pipeline_id)

                        payload: PSRPPayload | None = None
                        data_available = self.process_response(msg)
                        if data_available:
                            payload = self.next_payload()

                        if payload:
                            self._listener_send(payload, self._connection)

                    # If the command is done then we've got nothing left to do here.
                    if event.command_state == wsman.CommandState.DONE:
                        break

            except Exception as e:
                log.exception("WSManClient listener encountered unhandled exception")
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
        exception: Exception | None = None,
    ) -> None:
        pool = self.get_runspace_pool()
        pipe = pool.pipeline_table[pipeline_id]

        pipe.state = PSInvocationState.Stopped
        error_record: ErrorRecord | None = None
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
        exception: Exception | None = None,
    ) -> None:
        pool = self.get_runspace_pool()

        pool.state = RunspacePoolState.Broken
        error_record: ErrorRecord | None = None
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
    """Async Connection for WSManClient."""

    def __init__(
        self,
        pool: ClientRunspacePool,
        callback: AsyncEventCallable,
        buffer_mode: OutputBufferingMode,
        idle_timeout: int | None,
        max_envelope_size: int | None,
        shell: wsman.WinRS,
        connection: wsman.AsyncWSManHTTP,
    ) -> None:
        super().__init__(pool, callback)

        self._buffer_mode = buffer_mode
        self._connection = connection
        self._idle_timeout = idle_timeout
        self._listener_tasks: dict[uuid.UUID | None, asyncio.Task] = {}
        self._max_envelope_size = max_envelope_size
        self._stopped_pipelines: list[uuid.UUID] = []
        self._shell = shell
        self._pipeline_lookup: dict[uuid.UUID, uuid.UUID] = {}

    def get_fragment_size(self) -> int:
        if not self._max_envelope_size:
            self._max_envelope_size = _get_fragment_size(self.get_runspace_pool())

        if self._max_envelope_size:
            return self._max_envelope_size
        else:
            # Pre Win 8/2012 the default was 153600. This is the allowed base64
            # size based on that default.
            return 113664

    async def close(
        self,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        if pipeline_id and pipeline_id in self._listener_tasks:
            pipeline_task = self._listener_tasks.pop(pipeline_id)

            await self.signal(pipeline_id, signal_code=wsman.SignalCode.TERMINATE)
            await pipeline_task
            del self._pipeline_lookup[pipeline_id]

        elif not pipeline_id:
            # Closing the shell will implicitly stop the pipelines, mark them
            # as stopped so the listener updates the client correctly if needed.
            listener_tasks: list[asyncio.Task] = []
            for pid in list(self._listener_tasks.keys()):
                listener_tasks.append(self._listener_tasks.pop(pid))

                if not pid:
                    continue

                self._stopped_pipelines.append(pid)

            self._shell.close()
            with _map_wsman_exceptions():
                resp = await self._connection.wsman_post(self._shell.data_to_send())
            self._shell.receive_data(resp)

            # Ugly hack but WSManClient does not send a RnuspacePool state change response on our receive listener so this
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
            await self._connection.aclose()

    async def command(
        self,
        pipeline_id: uuid.UUID,
    ) -> None:
        payload = t.cast(PSRPPayload, self.next_payload())
        self._shell.command("", args=[base64.b64encode(payload.data).decode()], command_id=pipeline_id)
        with _map_wsman_exceptions():
            resp = await self._connection.wsman_post(self._shell.data_to_send())
        command_resp = t.cast(wsman.CommandResponseEvent, self._shell.receive_data(resp))

        # On older Windows hosts (Win 7) the pipeline id specified in the request isn't actually used. Will need to
        # create a mapping table to ensure that the returned command id is used if our pipeline_id is requested.
        self._pipeline_lookup[pipeline_id] = command_resp.command_id

        await self._create_listener(pipeline_id)

    async def create(self) -> None:
        pool = self.get_runspace_pool()
        payload = t.cast(PSRPPayload, self.next_payload())

        open_content = ElementTree.Element("creationXml", xmlns=PS_RESOURCE_PREFIX)
        open_content.text = base64.b64encode(payload.data).decode()
        options = wsman.OptionSet()
        options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})
        self._shell.open(options, open_content)

        with _map_wsman_exceptions():
            resp = await self._connection.wsman_post(self._shell.data_to_send())
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
        connection: wsman.AsyncWSManHTTP,
    ) -> None:
        stream = "stdin" if payload.stream_type == StreamType.default else "pr"
        command_id: uuid.UUID | None = None
        if payload.pipeline_id:
            command_id = self._pipeline_lookup[payload.pipeline_id]

        self._shell.send(stream, payload.data, command_id=command_id)
        with _map_wsman_exceptions():
            resp = await connection.wsman_post(self._shell.data_to_send())
        self._shell.receive_data(resp)

    async def signal(
        self,
        pipeline_id: uuid.UUID,
        signal_code: wsman.SignalCode = wsman.SignalCode.PS_CRTL_C,
    ) -> None:
        self._stopped_pipelines.append(pipeline_id)

        self._shell.signal(signal_code, self._pipeline_lookup[pipeline_id])
        with _map_wsman_exceptions():
            resp = await self._connection.wsman_post(self._shell.data_to_send())

        # Older Win hosts raise this error when terminating a pipeline, just ignore it.
        with contextlib.suppress(wsman.OperationAborted):
            self._shell.receive_data(resp)

    async def connect(
        self,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        rsp = wsman.NAMESPACES["rsp"]
        connect = ElementTree.Element("{%s}Connect" % rsp)
        if pipeline_id:
            connect.attrib["CommandId"] = str(pipeline_id).upper()
            options = None

        else:
            pool = self.get_runspace_pool()
            payload = t.cast(PSRPPayload, self.next_payload())

            options = wsman.OptionSet()
            options.add_option("protocolversion", str(pool.our_capability.protocolversion), {"MustComply": "true"})

            open_content = ElementTree.SubElement(connect, "connectXml", xmlns=PS_RESOURCE_PREFIX)
            open_content.text = base64.b64encode(payload.data).decode()

        self._shell.wsman.connect(
            self._shell.resource_uri, connect, option_set=options, selector_set=self._shell.selector_set
        )
        with _map_wsman_exceptions():
            resp = await self._connection.wsman_post(self._shell.data_to_send())
        event = self._shell.wsman.receive_data(resp)

        if pipeline_id:
            self._pipeline_lookup[pipeline_id] = pipeline_id
        else:
            response_xml = t.cast(
                ElementTree.Element, event.body.find("rsp:ConnectResponse/pwsh:connectResponseXml", wsman.NAMESPACES)
            )

            psrp_resp = PSRPPayload(base64.b64decode(response_xml.text or ""), StreamType.default, None)
            pool.receive_data(psrp_resp)

        await self._create_listener(pipeline_id=pipeline_id)

    async def disconnect(self) -> None:
        rsp = wsman.NAMESPACES["rsp"]

        disconnect = ElementTree.Element("{%s}Disconnect" % rsp)
        if self._buffer_mode != OutputBufferingMode.NONE:
            buffer_mode_str = "Block" if self._buffer_mode == OutputBufferingMode.BLOCK else "Drop"
            ElementTree.SubElement(disconnect, "{%s}BufferMode" % rsp).text = buffer_mode_str

        if self._idle_timeout:
            idle_str = f"PT{self._idle_timeout}S"
            ElementTree.SubElement(disconnect, "{%s}IdleTimeout" % rsp).text = idle_str

        listener_tasks = self._listener_tasks
        self._listener_tasks = {}
        self._shell.wsman.disconnect(self._shell.resource_uri, disconnect, selector_set=self._shell.selector_set)
        with _map_wsman_exceptions():
            resp = await self._connection.wsman_post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        await asyncio.gather(*listener_tasks.values())

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

    async def reconnect(self) -> None:
        self._shell.wsman.reconnect(self._shell.resource_uri, selector_set=self._shell.selector_set)
        with _map_wsman_exceptions():
            resp = await self._connection.wsman_post(self._shell.data_to_send())
        self._shell.receive_data(resp)

        await self._create_listener()

    async def _create_listener(
        self,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        started = asyncio.Event()
        task = asyncio.create_task(self._listen(started, pipeline_id))
        self._listener_tasks[pipeline_id] = task
        # await started.wait()

    async def _listen(
        self,
        started: asyncio.Event,
        pipeline_id: uuid.UUID | None = None,
    ) -> None:
        command_id: uuid.UUID | None = None
        if pipeline_id:
            command_id = self._pipeline_lookup[pipeline_id]

        async with self._connection.copy() as conn:
            try:
                while True:
                    self._shell.receive("stdout", command_id=command_id)
                    # resp = await conn.wsman_post(
                    #     self._shell.data_to_send(), data_sent=None if started.is_set() else started
                    # )
                    with _map_wsman_exceptions():
                        resp = await conn.wsman_post(self._shell.data_to_send())

                    try:
                        event = t.cast(wsman.ReceiveResponseEvent, self._shell.receive_data(resp))

                    except wsman.OperationTimedOut:
                        # Occurs when there has been no output after the OperationTimeout set, just repeat the request
                        continue

                    except (
                        wsman.ErrorCancelled,
                        wsman.OperationAborted,
                        wsman.UnexpectedSelectors,
                        wsman.ServiceStreamDisconnected,
                        wsman.ShellDisconnected,
                    ) as e:
                        if pipeline_id not in self._listener_tasks:
                            # Received when the shell or pipeline has been closed
                            break

                        else:
                            raise

                    stream_data = event.streams.get("stdout", [])
                    for psrp_data in stream_data:
                        msg = PSRPPayload(psrp_data, StreamType.default, pipeline_id)

                        payload: PSRPPayload | None = None
                        data_available = await self.process_response(msg)
                        if data_available:
                            payload = self.next_payload()

                        if payload:
                            await self._listener_send(payload, self._connection)

                    # If the command is done then we've got nothing left to do here.
                    if pipeline_id and event.command_state == wsman.CommandState.DONE:
                        break

            except Exception as e:
                log.exception("WSManClient listener encountered unhandled exception")
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
        exception: Exception | None = None,
    ) -> None:
        pool = self.get_runspace_pool()
        pipe = pool.pipeline_table[pipeline_id]

        pipe.state = PSInvocationState.Stopped
        error_record: ErrorRecord | None = None
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
        exception: Exception | None = None,
    ) -> None:
        pool = self.get_runspace_pool()

        pool.state = RunspacePoolState.Broken
        error_record: ErrorRecord | None = None
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
