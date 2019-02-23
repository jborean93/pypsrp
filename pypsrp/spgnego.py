# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import binascii
import logging
import struct

from abc import ABCMeta, abstractmethod
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct
from ntlm_auth.ntlm import NtlmContext
from six import with_metaclass

from pypsrp.exceptions import AuthenticationError
from pypsrp._utils import to_bytes

HAS_GSSAPI = True
try:  # pragma: no cover
    import gssapi
    from gssapi.raw import acquire_cred_with_password
    from gssapi.raw import set_sec_context_option
    from gssapi.raw import ChannelBindings
except ImportError:  # pragma: no cover
    HAS_GSSAPI = False

HAS_GSSAPI_ENCRYPTION = True
try:  # pragma: no cover
    from gssapi.raw import wrap_iov, IOV, IOVBufferType
except ImportError:  # pragma: no cover
    HAS_GSSAPI_ENCRYPTION = False

HAS_SSPI = True
try:  # pragma: no cover
    import sspi
    import sspicon
    import win32security
except ImportError:  # pragma: no cover
    HAS_SSPI = False

log = logging.getLogger(__name__)


def get_auth_context(username, password, auth_provider, cbt_app_data,
                     hostname, service, delegate, wrap_required):
    """
    Returns an AuthContext used in the Negotiate process which provides methods
    to generate the auth token as well as wrap/unwrap data sent to and from the
    server.

    This function tries to get the context based on the provider that is
    specified otherwise it tries to get the best provider available. Here is
    the basic logic it uses when getting the auth provider

    * If SSPI is available use that (Windows only)
    * If GSSAPI is available with NTLM/SPNEGO support, use that when auto or
        kerberos is specified as the provider
    * If GSSAPI is available with only Kerberos support, try and use that when
        auto or kerberos is specified as the provider
    * In all other cases use the fallback ntlm-auth library

    :param username: The username to authenticate with, can be None if on
        Windows and SSPI is being used or GSSAPI is available and kerberos is
        used.
    :param password: The password, same rules apply as username
    :param auth_provider: The auth provider to use
        auto: Try Kerberos if available and fallback to NTLM if that fails
        kerberos: Only allow Kerberos with no fallback to NTLM
        ntlm: Only use NTLM, do not try Kerberos
    :param cbt_app_data: The CBT application data field to bind to the auth
    :param hostname: The hostname to build the SPN with
    :param service: The service to build the SPN with
    :param delegate: Whether to add the delegate flag to the kerb ticket
    :param wrap_required: Whether we need encryption/wrapping in the auth
        provider, if we need wrapping and GSSAPI does not offer it then we
        will fallback to ntlm-auth
    :return:
    """
    if auth_provider not in ["auto", "kerberos", "ntlm"]:
        raise ValueError("Invalid auth_provider specified %s, must be "
                         "auto, kerberos, or ntlm" % auth_provider)

    context_gen = None
    out_token = None

    if HAS_SSPI:
        # always use SSPI when available
        log.debug("SSPI is available and will be used as the auth backend")
        context = SSPIContext(username, password, auth_provider, cbt_app_data,
                              hostname, service, delegate)
    elif HAS_GSSAPI and auth_provider != "ntlm":
        log.debug("GSSAPI is available, determine if it can handle the auth "
                  "provider specified or whether the NTLM fallback is used")
        mechs_available = GSSAPIContext.get_available_mechs(wrap_required)

        if auth_provider in mechs_available:
            log.debug("GSSAPI with mech %s is being used as the auth backend"
                      % auth_provider)
            context = GSSAPIContext(username, password, auth_provider,
                                    cbt_app_data, hostname, service, delegate,
                                    wrap_required)
        elif auth_provider == "kerberos":
            raise ValueError("The auth_provider specified 'kerberos' is not "
                             "available as message encryption is required but "
                             "is not available on the current system. Either "
                             "disable encryption, use https or specify "
                             "auto/ntlm")
        elif auth_provider == "auto" and "kerberos" in mechs_available:
            log.debug("GSSAPI is available but SPNEGO/NTLM is not natively "
                      "supported, try to use Kerberos explicitly and fallback "
                      "to NTLM with ntlm-auth if that fails")
            # we can't rely on SPNEGO in GSSAPI as NTLM is not available, try
            # and initialise a kerb context and get the first token. If that
            # fails, fallback to NTLM with ntlm-auth
            try:
                log.debug("Attempting to use GSSAPI Kerberos as auth backend")
                context = GSSAPIContext(username, password, "kerberos",
                                        cbt_app_data, hostname, service,
                                        delegate, wrap_required)
                context.init_context()
                context_gen = context.step()
                out_token = next(context_gen)
                log.debug("GSSAPI with mech kerberos is being used as the "
                          "auth backend")
            except gssapi.exceptions.GSSError as err:
                log.warning("Failed to initialise a GSSAPI context, failling "
                            "back to NTLM: %s" % str(err))
                context_gen = None
                out_token = None
                context = NTLMContext(username, password, cbt_app_data)
        else:
            log.debug("GSSAPI is available but does not support NTLM or "
                      "Kerberos with encryption, fallback to ntlm-auth")
            context = NTLMContext(username, password, cbt_app_data)
    else:
        if auth_provider not in ["auto", "ntlm"]:
            raise ValueError("The auth_provider specified '%s' cannot be used "
                             "without GSSAPI or SSPI being installed, select "
                             "auto or install GSSAPI or SSPI"
                             % auth_provider)
        log.debug("SSPI or GSSAPI is not available, using ntlm-auth as the "
                  "auth backend")
        context = NTLMContext(username, password, cbt_app_data)

    if context_gen is None:
        context.init_context()
        context_gen = context.step()
        out_token = next(context_gen)

    return context, context_gen, out_token


class AuthContext(with_metaclass(ABCMeta, object)):
    _AUTH_PROVIDERS = {}

    def __init__(self, password, auth_provider, cbt_app_data):
        self.password = password
        self.auth_provider = self._AUTH_PROVIDERS[auth_provider]
        self.cbt_app_data = cbt_app_data
        self._context = None

    @property
    @abstractmethod
    def domain(self):
        pass  # pragma: no cover

    @property
    @abstractmethod
    def username(self):
        pass  # pragma: no cover

    @property
    @abstractmethod
    def complete(self):
        pass  # pragma: no cover

    @abstractmethod
    def init_context(self):
        pass  # pragma: no cover

    @abstractmethod
    def step(self):
        pass  # pragma: no cover

    @abstractmethod
    def wrap(self, data):
        pass  # pragma: no cover

    @abstractmethod
    def unwrap(self, header, data):
        pass  # pragma: no cover

    @staticmethod
    def _get_domain_username(username):
        """
        Splits the username password in into a domain/user tuple. If the
        username is in the Netlogon form then it is split by the first
        backslash, if the user is in the UPN form (user@domain) then it
        is not split.

        :param username: The username to parse
        :return: domain, username
        """
        if username is None:
            return None, None

        try:
            domain, username = username.split("\\", 1)
        except ValueError:
            username = username
            domain = ''
        return domain, username


class SSPIContext(AuthContext):
    _AUTH_PROVIDERS = {
        'auto': 'Negotiate',
        'kerberos': 'Kerberos',
        'ntlm': 'Ntlm'
    }

    def __init__(self, username, password, auth_provider, cbt_app_data,
                 hostname, service, delegate):
        super(SSPIContext, self).__init__(password, auth_provider,
                                          cbt_app_data)
        self._domain, self._username = self._get_domain_username(username)
        self._target_spn = "%s/%s" % (service.upper(), hostname)
        self._delegate = delegate
        self._call_counter = 0

        if self.cbt_app_data is not None:
            # need to hand craft the SEC_CHANNEL_BINDINGS structure for SSPI
            # https://msdn.microsoft.com/en-us/library/windows/desktop/dd919963(v=vs.85).aspx
            cbt_struct = b"\x00" * 24
            cbt_struct += struct.pack("<I", len(self.cbt_app_data))
            cbt_struct += struct.pack("<I", len(cbt_struct) + 4)
            cbt_struct += self.cbt_app_data
            self.cbt_app_data = cbt_struct

    @property
    def domain(self):
        return self._domain

    @property
    def username(self):
        return self._username

    @property
    def complete(self):
        return self._context.authenticated

    def init_context(self):
        flags = sspicon.ISC_REQ_INTEGRITY | \
                sspicon.ISC_REQ_CONFIDENTIALITY | \
                sspicon.ISC_REQ_REPLAY_DETECT | \
                sspicon.ISC_REQ_SEQUENCE_DETECT | \
                sspicon.ISC_REQ_MUTUAL_AUTH

        if self._delegate:
            flags |= sspicon.ISC_REQ_DELEGATE

        self._context = sspi.ClientAuth(
            pkg_name=self.auth_provider,
            auth_info=(self.username, self.domain, self.password),
            targetspn=self._target_spn,
            scflags=flags
        )

    def step(self):
        in_token = None
        while not self.complete:
            out_token = self._step(in_token)
            in_token = yield out_token if out_token != b"" else None

    def wrap(self, data):
        enc_data, header = self._context.encrypt(data)
        return header, enc_data

    def unwrap(self, header, data):
        dec_data = self._context.decrypt(data, header)
        return dec_data

    def _step(self, token):
        success_codes = [
            sspicon.SEC_E_OK,
            sspicon.SEC_I_COMPLETE_AND_CONTINUE,
            sspicon.SEC_I_COMPLETE_NEEDED,
            sspicon.SEC_I_CONTINUE_NEEDED
        ]

        sec_tokens = []
        if token is not None:
            sec_token = win32security.PySecBufferType(
                self._context.pkg_info['MaxToken'],
                sspicon.SECBUFFER_TOKEN
            )
            sec_token.Buffer = token
            sec_tokens.append(sec_token)
        if self.cbt_app_data is not None:
            sec_token = win32security.PySecBufferType(
                len(self.cbt_app_data),
                sspicon.SECBUFFER_CHANNEL_BINDINGS
            )
            sec_token.Buffer = self.cbt_app_data
            sec_tokens.append(sec_token)

        if len(sec_tokens) > 0:
            sec_buffer = win32security.PySecBufferDescType()
            for sec_token in sec_tokens:
                sec_buffer.append(sec_token)
        else:
            sec_buffer = None

        rc, out_buffer = self._context.authorize(sec_buffer_in=sec_buffer)
        self._call_counter += 1
        if rc not in success_codes:
            rc_name = "Unknown Error"
            for name, value in vars(sspicon).items():
                if isinstance(value, int) and name.startswith("SEC_") and \
                        value == rc:
                    rc_name = name
                    break
            raise AuthenticationError(
                "InitializeSecurityContext failed on call %d: (%d) %s 0x%s"
                % (self._call_counter, rc, rc_name, format(rc, 'x'))
            )

        return out_buffer[0].Buffer


class GSSAPIContext(AuthContext):
    _AUTH_PROVIDERS = {
        'auto': '1.3.6.1.5.5.2',  # SPNEGO OID
        'kerberos': '1.2.840.113554.1.2.2',
        'ntlm': '1.3.6.1.4.1.311.2.2.10'
    }

    def __init__(self, username, password, auth_provider, cbt_app_data,
                 hostname, service, delegate, wrap_required):
        super(GSSAPIContext, self).__init__(password, auth_provider,
                                            cbt_app_data)
        self._username = username
        self._target_spn = "%s@%s" % (service.lower(), hostname)
        self._delegate = delegate
        self.wrap_required = wrap_required

    @property
    def domain(self):
        return ""

    @property
    def username(self):
        return self._username

    @property
    def complete(self):
        return self._context.complete

    def init_context(self):
        if self.auth_provider != self._AUTH_PROVIDERS['kerberos']:
            name_type = gssapi.NameType.user
        else:
            name_type = gssapi.NameType.kerberos_principal
        mech = gssapi.OID.from_int_seq(self.auth_provider)

        cbt_app_data = None
        if self.cbt_app_data is not None:
            cbt_app_data = ChannelBindings(application_data=self.cbt_app_data)

        log.debug("GSSAPI: Acquiring security context for user %s with mech "
                  "%s" % (self.username, self.auth_provider))
        self._context = GSSAPIContext._get_security_context(
            name_type, mech, self._target_spn, self.username, self.password,
            self._delegate, self.wrap_required, cbt_app_data
        )

    def step(self):
        in_token = None
        while not self._context.complete:
            log.debug("GSSAPI: Calling gss_init_sec_context()")
            out_token = self._context.step(in_token)
            in_token = yield out_token

    def wrap(self, data):
        iov = IOV(IOVBufferType.header, data, IOVBufferType.padding,
                  std_layout=False)
        wrap_iov(self._context, iov, confidential=True)
        return iov[0].value, iov[1].value + (iov[2].value or b"")

    def unwrap(self, header, data):
        return self._context.unwrap(header + data)[0]

    @staticmethod
    def _get_security_context(name_type, mech, spn, username, password,
                              delegate, wrap_required, channel_bindings=None):
        if username is not None:
            username = gssapi.Name(base=username, name_type=name_type)

        server_name = gssapi.Name(spn,
                                  name_type=gssapi.NameType.hostbased_service)

        # first try and get the cred from the existing cache, if that fails
        # then get a new ticket with the password (if specified). The cache
        # can only be used for Kerberos, NTLM/SPNEGO must have acquire the
        # cred with a pass
        cred = None
        kerb_oid = GSSAPIContext._AUTH_PROVIDERS['kerberos']
        kerb_mech = gssapi.OID.from_int_seq(kerb_oid)
        if mech == kerb_mech:
            try:
                cred = gssapi.Credentials(name=username, usage='initiate',
                                          mechs=[mech])
                # raises ExpiredCredentialsError if it has expired
                cred.lifetime
            except gssapi.raw.GSSError:
                # we can't acquire the cred if no password was supplied
                if password is None:
                    raise
                cred = None
        elif username is None or password is None:
            raise ValueError("Can only use implicit credentials with kerberos "
                             "authentication")

        if cred is None:
            # error when trying to access the existing cache, get our own
            # credentials with the password specified
            b_password = to_bytes(password)
            cred = gssapi.raw.acquire_cred_with_password(username, b_password,
                                                         usage='initiate',
                                                         mechs=[mech])
            cred = cred.creds

        flags = gssapi.RequirementFlag.mutual_authentication | \
            gssapi.RequirementFlag.out_of_sequence_detection
        if delegate:
            flags |= gssapi.RequirementFlag.delegate_to_peer
        if wrap_required:
            flags |= gssapi.RequirementFlag.confidentiality

        context = gssapi.SecurityContext(name=server_name,
                                         creds=cred,
                                         usage='initiate',
                                         mech=mech,
                                         flags=flags,
                                         channel_bindings=channel_bindings)

        return context

    @staticmethod
    def get_available_mechs(encryption_required=False):
        available_mechs = ["kerberos"]

        # while kerb auth might be available, if we require wrapping and the
        # extension is not available then we can't use it
        if encryption_required and not HAS_GSSAPI_ENCRYPTION:
            available_mechs.pop(0)

        ntlm_oid = GSSAPIContext._AUTH_PROVIDERS['ntlm']
        ntlm_mech = gssapi.OID.from_int_seq(ntlm_oid)
        # GSS_NTLMSSP_RESET_CRYPTO_OID_LENGTH
        # github.com/simo5/gss-ntlmssp/blob/master/src/gssapi_ntlmssp.h#L68
        reset_mech = gssapi.OID.from_int_seq("1.3.6.1.4.1.7165.655.1.3")

        try:
            # we don't actually care about the account used here so just use
            # a random username and password
            ntlm_context = GSSAPIContext._get_security_context(
                gssapi.NameType.user,
                ntlm_mech,
                "http@server",
                "username",
                "password",
                False,
                encryption_required
            )
            ntlm_context.step()
            gssapi.raw.set_sec_context_option(reset_mech, context=ntlm_context,
                                              value=b"\x00" * 4)

            # gss-ntlmssp is available which in turn means we can use native
            # SPNEGO or NTLM with the GSSAPI
            available_mechs.extend(["auto", "ntlm"])
        except gssapi.exceptions.GSSError as exc:
            # failed to init NTLM and verify gss-ntlmssp is available, this
            # means NTLM is either not available or won't work
            # (not gss-ntlmssp) so we return kerberos as the only available
            # mechanism for the GSSAPI Context
            log.debug("Failed to init test NTLM context with GSSAPI: %s"
                      % str(exc))
        return available_mechs


class NTLMContext(AuthContext):
    _AUTH_PROVIDERS = {
        'ntlm': ''
    }

    def __init__(self, username, password, cbt_app_data):
        if username is None:
            raise ValueError("Cannot use ntlm-auth with no username set")
        if password is None:
            raise ValueError("Cannot use ntlm-auth with no password set")
        super(NTLMContext, self).__init__(password, "ntlm", cbt_app_data)
        self._domain, self._username = self._get_domain_username(username)

    @property
    def domain(self):
        return self._domain

    @property
    def username(self):
        return self._username

    @property
    def complete(self):
        return self._context.complete

    def init_context(self):
        cbt_struct = None
        if self.cbt_app_data:
            cbt_struct = GssChannelBindingsStruct()
            cbt_struct[cbt_struct.APPLICATION_DATA] = self.cbt_app_data
        self._context = NtlmContext(self.username, self.password, self.domain,
                                    cbt_data=cbt_struct)

    def step(self):
        msg1 = self._context.step()
        log.debug("NTLM Negotiate message: %s" % binascii.hexlify(msg1))

        msg2 = yield msg1
        log.debug("NTLM: Parsing Challenge message and generating "
                  "Authenticate message: %s" % binascii.hexlify(msg2))
        msg3 = self._context.step(msg2)

        yield msg3

    def wrap(self, data):
        wrapped_data = self._context.wrap(data)
        return wrapped_data[:16], wrapped_data[16:]

    def unwrap(self, header, data):
        return self._context.unwrap(header + data)
