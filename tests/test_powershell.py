# -*- coding: utf-8 -*-

import logging
import time
import warnings

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from pypsrp.complex_objects import Command, CommandType, ErrorRecord, \
    GenericComplexObject, ObjectMeta, ParameterMetadata, PSInvocationState, \
    RunspacePoolState
from pypsrp.exceptions import InvalidPipelineStateError, \
    InvalidPSRPOperation, InvalidRunspacePoolStateError, FragmentError, \
    WSManFaultError
from pypsrp.messages import Destination, Message, MessageType, PipelineInput, \
    RunspacePoolHostCall, RunspacePoolStateMessage, UserEvent, WarningRecord, ErrorRecordMessage
from pypsrp.powershell import Fragment, Fragmenter, RunspacePool, PowerShell, RunspacePoolWarning
from pypsrp.serializer import Serializer
from pypsrp.wsman import WSMan


def gen_rsa_keypair(public_exponent, key_size, backend):
    # for a pasing test against mocked results, we need the same key
    # for each run

    # private key numbers
    d = 21617696977064831737076881102083866512588021127782856037972563073160418492784722157229048881139551797965254106994729989171004895438848876105403145818526588448619012753150859908505079457128264842711189718538434996465875355972895683414261775421352553376878242391757860294122032733780201193753125763293334069627997366690578378643268496972715558088736335242616446993490560907175346811363459760219154246765368454269083276034064771683561116425318584728938420495690895295417261302673227504350398337950587166908640861984752151206832712112769733009288056773792011545187027621461752928443722277452545442134981026071169761569129
    dmp1 = 129490813503009185789974379255770561425157574567257502592607367628590256916193790244618544180042259447193585640234142495635548617466553819050739804131538251753363069954266652888546939369520788464015077722316584767752481491358983245279072645160828476778216654224017198857901235711822454725809127201111535934753
    dmq1 = 48648800397834409354931458481260042874431001732145738308246185682766008281764239801132482123299506611633669689538582946696791307965087683313609603490735622965494394760749284568774366017328170855872209094830510839953297302962573968041079091285470051311421587284299491265676844471173504726139132522742725727613
    iqmp = 39631089624266744377721024140775526581242717587318543319284349361749959043577498327792652579346928867008103676271384098405811933888254575054903735904994321302658687548878487654303384553639708412577672820397125886631056454780398875240593971733447420281054575014889376749144359968455995345232769795875325417317
    p = 174331130742537243408330955079815843963035167715989214203198624738597363753422194561659111132445142920926993058833709875440980890363712769908141629896643845627776407469038077862709547359496382776626050712560846670587394813048350142683947903572416102765283173128172045224943986952459084128294017448217886823253
    q = 141639112913055250372907285405879139487409354087944702421480687298597773645578986399236760591500655922107321654521995138945695777437048045372013886449237695348272152351631535441304559114954968164429007883070066144736528002854651716726263900736377199146896337887655964419309789253989248300176824884184363216819

    # public key numbers
    e = 65537
    n = 24692106711502830011203227021058444318027801046612842012663747949974978593541529463344548800446917862266219189049856550539417324579114258210080798360122994007305091566363663241781504651372764226027210216355916383975880112316706422502404691353489765771310270171473497918954906308690817673196552680498374521519566949221302301125182104198985782657283395055909134373469597836420671163965867038455758131344733786842283328454828820406016508955409107145350345035248825315933976893356673777910251028486191789752627573225093968284278302684745743589192378470115772764709506475265246795419324395050366115533203601201395969892207

    public_numbers = rsa.RSAPublicNumbers(e, n)
    numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp,
                                    public_numbers)
    key = default_backend().load_rsa_private_numbers(numbers)

    return key


class RSPoolTest(object):
    def __init__(self):
        self.protocol_version = "2.3"
        self.pipelines = {}


class TestRunspacePool(object):

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_open_runspace']],
                             indirect=True)
    def test_psrp_open_runspace(self, wsman_conn):
        runspace_pool = RunspacePool(wsman_conn)
        assert runspace_pool.state == RunspacePoolState.BEFORE_OPEN
        runspace_pool.open()
        assert runspace_pool.application_private_data is not None
        assert runspace_pool.state == RunspacePoolState.OPENED
        runspace_pool.close()
        assert runspace_pool.state == RunspacePoolState.CLOSED

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_set_runspaces']],
                             indirect=True)
    def test_psrp_set_runspaces(self, wsman_conn):
        runspace_pool = RunspacePool(wsman_conn)
        assert runspace_pool.min_runspaces == 1
        assert runspace_pool.max_runspaces == 1

        # test changing before open works
        runspace_pool.min_runspaces = 2
        runspace_pool.max_runspaces = 2
        assert runspace_pool.min_runspaces == 2
        assert runspace_pool.max_runspaces == 2

        # reset back to one for msg testing
        runspace_pool.min_runspaces = 1
        runspace_pool.max_runspaces = 1

        # open the pool and test changing after open
        try:
            runspace_pool.open()
            actual = runspace_pool.get_available_runspaces()
            assert actual == 1
            runspace_pool.min_runspaces = 1
            runspace_pool.max_runspaces = 5
            actual = runspace_pool.get_available_runspaces()
            assert runspace_pool.min_runspaces == 1
            assert runspace_pool.max_runspaces == 5
            assert actual == 5

            runspace_pool.min_runspaces = 2
            assert runspace_pool.min_runspaces == 2

            runspace_pool.max_runspaces = 5
            assert runspace_pool.max_runspaces == 5

            with pytest.raises(InvalidPSRPOperation) as exc:
                runspace_pool.min_runspaces = -1
            assert str(exc.value) == "Failed to set minimum runspaces"

            with pytest.raises(InvalidPSRPOperation) as exc:
                runspace_pool.max_runspaces = -1
            assert str(exc.value) == "Failed to set maximum runspaces"
        finally:
            runspace_pool.close()

    @pytest.mark.parametrize('wsman_conn',
                             # cannot really test in a real life scenario so
                             # rely on pre-built responses with a timeout in
                             # the reply
                             [[False, 'test_psrp_key_exchange_timeout']],
                             indirect=True)
    def test_psrp_key_exchange_timeout(self, wsman_conn, monkeypatch):
        monkeypatch.setattr('cryptography.hazmat.primitives.asymmetric.rsa.'
                            'generate_private_key', gen_rsa_keypair)
        with RunspacePool(wsman_conn, session_key_timeout_ms=500) as pool:
            with pytest.raises(InvalidPSRPOperation) as exc:
                pool.exchange_keys()
            assert str(exc.value) == "Timeout while waiting for key exchange"

    @pytest.mark.parametrize('wsman_conn',
                             # due to tests sometimes leaving pools open
                             # we are going to mock the data for this one
                             [[False, 'test_psrp_disconnect_runspaces']],
                             indirect=True)
    def test_psrp_disconnect_runspaces(self, wsman_conn):
        runspace_pool = RunspacePool(wsman_conn)
        runspace_pool.open()
        runspace_pool.disconnect()
        assert runspace_pool.state == RunspacePoolState.DISCONNECTED
        runspace_pool.connect()
        assert runspace_pool.state == RunspacePoolState.OPENED
        runspace_pool.disconnect()

        actual = []
        try:
            runspace_pool2 = RunspacePool(wsman_conn)
            runspace_pool2.open()
            runspace_pool2.disconnect()

            # build a new WSMan object with new unique ID and new requests
            # session
            wsman2 = WSMan(wsman_conn.transport.server)
            wsman2.transport = wsman_conn.transport
            wsman2.transport.session = None
            actual = RunspacePool.get_runspace_pools(wsman2)
            assert len(actual) == 2
            assert actual[0].id == runspace_pool.id or \
                actual[1].id == runspace_pool.id
            assert actual[0].id == runspace_pool2.id or \
                actual[1].id == runspace_pool2.id
            assert actual[0].state == RunspacePoolState.DISCONNECTED
            assert actual[1].state == RunspacePoolState.DISCONNECTED
            for pool in actual:
                pool.connect()
                assert pool.state == RunspacePoolState.OPENED
        finally:
            for pool in actual:
                pool.close()
                assert pool.state == RunspacePoolState.CLOSED

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_application_args']],
                             indirect=True)
    def test_psrp_application_args(self, wsman_conn):
        app_arguments = {
            "test_var": "abcdef12345"
        }

        pool = RunspacePool(wsman_conn)
        pool.open(app_arguments)
        try:
            ps = PowerShell(pool)
            ps.add_script("$PSSenderInfo.ApplicationArguments")
            actual = ps.invoke()
            assert actual[0] == app_arguments
        finally:
            pool.close()

    @pytest.mark.parametrize('wsman_conn',
                             # the commands on the server could differ based on
                             # each version, used existing responses instead
                             [[False, 'test_psrp_get_command_metadata']],
                             indirect=True)
    def test_psrp_get_command_metadata(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            actual_full = pool.get_command_metadata("new-pssession*")
            actual_types = pool.get_command_metadata(["new-*"], command_types=CommandType.FUNCTION)
            actual_namespaced = pool.get_command_metadata("Get-*", namespace=["Microsoft.WSMan.Management"])

        assert len(actual_full) == 3
        assert actual_full[0].name == "New-PSSession"
        assert actual_full[1].name == "New-PSSessionConfigurationFile"
        assert actual_full[2].name == "New-PSSessionOption"

        assert len(actual_types) == 2
        assert actual_types[0].name == "New-Guid"
        assert actual_types[1].name == "New-TemporaryFile"

        assert len(actual_namespaced) == 2
        assert actual_namespaced[0].name == "Get-WSManCredSSP"
        assert actual_namespaced[1].name == "Get-WSManInstance"
        actual = actual_full
        actual.extend(actual_types)
        actual.extend(actual_namespaced)

        for command in actual:
            assert isinstance(command.command_type, CommandType)
            assert isinstance(command.parameters, dict)
            for key, value in command.parameters.items():
                assert isinstance(key, str)
                assert isinstance(value, ParameterMetadata)

    @pytest.mark.parametrize('wsman_conn',
                             # reset was only added in v2.3, use existing
                             # responses for test
                             [[False, 'test_psrp_reset_runspace_state']],
                             indirect=True)
    def test_psrp_reset_runspace_state(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script("echo hi")
            ps.invoke(add_to_history=True)

            pool.reset_runspace_state()

            ps = PowerShell(pool)
            ps.add_cmdlet("Get-History")
            actual = ps.invoke()

        # should be empty after clearing history
        assert actual == []

    @pytest.mark.parametrize('wsman_conn',
                             # reset was only added in v2.3, use existing
                             # responses for test
                             [[False, 'test_psrp_reset_runspace_state_fail']],
                             indirect=True)
    def test_psrp_reset_runspace_state_fail(self, wsman_conn):
        pool = RunspacePool(wsman_conn)
        pool.open()

        try:
            with pytest.raises(InvalidPSRPOperation) as err:
                pool.reset_runspace_state()
            assert str(err.value) == "Failed to reset runspace state"
        finally:
            pool.close()

    @pytest.mark.parametrize('wsman_conn',
                             # JEA endpoint was configured manually to only
                             # allow Get-Item and access to the WSMan provider
                             [[False, 'test_psrp_with_jea_configuration']],
                             indirect=True)
    def test_psrp_with_jea_configuration(self, wsman_conn):
        with RunspacePool(wsman_conn, configuration_name="JEARole") as pool:
            ps = PowerShell(pool)
            ps.add_cmdlet("Get-Item").add_parameter(
                "Path", "WSMan:\\localhost\\Service\\AllowUnencrypted"
            )
            actual = ps.invoke()

            ps_fail = PowerShell(pool)
            ps_fail.add_cmdlet("Get-Item").add_parameter("Path", "C:\\Windows")
            ps_fail.add_statement().add_script(
                "Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted "
                "-Value $false"
            )
            actual_fail = ps_fail.invoke()

        assert len(actual) == 1
        assert str(actual[0]) == \
            "Microsoft.WSMan.Management.WSManConfigLeafElement"
        assert actual[0].property_sets[0].adapted_properties['Value'] == 'true'
        assert ps.had_errors is False

        assert actual_fail == []
        assert ps_fail.had_errors is True
        assert len(ps_fail.streams.error) == 2
        assert str(ps_fail.streams.error[0]) == \
            "Cannot find a provider with the name 'FileSystem'."
        assert str(ps_fail.streams.error[1]) == \
            "The syntax is not supported by this runspace. This can occur " \
            "if the runspace is in no-language mode."

    def test_psrp_connect_already_opened(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        rs.state = RunspacePoolState.OPENED
        rs.connect()

    def test_psrp_connect_invalid_state(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        with pytest.raises(InvalidRunspacePoolStateError) as err:
            rs.connect()
        assert err.value.action == "connect to a disconnected Runspace Pool"
        assert err.value.current_state == RunspacePoolState.BEFORE_OPEN
        assert err.value.expected_state == RunspacePoolState.DISCONNECTED
        assert str(err.value) == \
            "Cannot 'connect to a disconnected Runspace Pool' on the " \
            "current state 'BeforeOpen', expecting state(s): 'Disconnected'"

    def test_psrp_disconnect_already_disconnected(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        rs.state = RunspacePoolState.DISCONNECTED
        rs.disconnect()

    def test_psrp_disconnect_invalid_state(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        with pytest.raises(InvalidRunspacePoolStateError) as err:
            rs.disconnect()
        assert err.value.action == "disconnect a Runspace Pool"
        assert err.value.current_state == RunspacePoolState.BEFORE_OPEN
        assert err.value.expected_state == RunspacePoolState.OPENED
        assert str(err.value) == \
            "Cannot 'disconnect a Runspace Pool' on the " \
            "current state 'BeforeOpen', expecting state(s): 'Opened'"

    def test_psrp_get_command_meta_invalid_state(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        with pytest.raises(InvalidRunspacePoolStateError) as err:
            rs.get_command_metadata("")
        assert err.value.action == "get command metadata"
        assert err.value.current_state == RunspacePoolState.BEFORE_OPEN
        assert err.value.expected_state == RunspacePoolState.OPENED
        assert str(err.value) == \
            "Cannot 'get command metadata' on the current state " \
            "'BeforeOpen', expecting state(s): 'Opened'"

    def test_psrp_open_invalid_state(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        rs.state = RunspacePoolState.DISCONNECTED
        with pytest.raises(InvalidRunspacePoolStateError) as err:
            rs.open()
        assert err.value.action == "open a new Runspace Pool"
        assert err.value.current_state == RunspacePoolState.DISCONNECTED
        assert err.value.expected_state == RunspacePoolState.BEFORE_OPEN
        assert str(err.value) == \
            "Cannot 'open a new Runspace Pool' on the current state " \
            "'Disconnected', expecting state(s): 'BeforeOpen'"

    def test_psrp_parse_state_failure(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)
        empty_uuid = "00000000-0000-0000-0000-000000000000"

        state_msg = RunspacePoolStateMessage(RunspacePoolState.OPENED)
        message = Message(0x2, empty_uuid, empty_uuid, state_msg, None)
        rs._process_runspacepool_state(message)
        assert rs.state == RunspacePoolState.OPENED

        excp = ErrorRecord()
        excp._to_string = "error msg"
        state_msg = RunspacePoolStateMessage(RunspacePoolState.BROKEN, excp)
        message = Message(0x2, empty_uuid, empty_uuid, state_msg, None)
        with pytest.raises(InvalidPSRPOperation) as err:
            rs._process_runspacepool_state(message)
        assert str(err.value) == "Received a broken RunspacePoolState " \
                                 "message: error msg"

    def test_psrp_reset_state_failure(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)

        # before connecting this should just return None
        rs.reset_runspace_state()

        # when state is not BeforeOpen or Opened then it should fail
        rs.state = RunspacePoolState.BROKEN
        with pytest.raises(InvalidRunspacePoolStateError) as err:
            rs.reset_runspace_state()
        assert err.value.action == "reset RunspacePool state"
        assert err.value.current_state == RunspacePoolState.BROKEN
        assert err.value.expected_state == [RunspacePoolState.BEFORE_OPEN,
                                            RunspacePoolState.OPENED]
        assert str(err.value) == \
            "Cannot 'reset RunspacePool state' on the current state " \
            "'Broken', expecting state(s): 'BeforeOpen, Opened'"

        rs.state = RunspacePoolState.OPENED
        rs.protocol_version = "2.2"
        with pytest.raises(InvalidPSRPOperation) as err:
            rs.reset_runspace_state()
        assert str(err.value) == \
            "Cannot reset runspace state on protocol versions older than " \
            "2.3, actual: 2.2"

    def test_psrp_runspace_host_call_no_host(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)

        msg = Message(Destination.CLIENT, None, None, RunspacePoolHostCall(),
                      None)
        actual = rs._process_runspacepool_host_call(msg)
        assert actual == msg.data

    def test_psrp_process_user_event(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)

        msg = Message(Destination.CLIENT, None, None, UserEvent(), None)
        rs._process_user_event(msg)
        assert len(rs.user_events) == 1
        assert rs.user_events[0] == msg.data

    def test_psrp_warning(self):
        wsman = WSMan("")
        rs = RunspacePool(wsman)

        msg = Message(Destination.CLIENT, None, None, WarningRecord(message='warning msg'), None)
        msg.data._to_string = 'warning msg'

        with pytest.warns(RunspacePoolWarning, match="warning msg"):
            rs._process_runspacepool_warning(msg)

    def test_psrp_receive_unknown_message_type(self, caplog):
        wsman = WSMan("")
        rs = RunspacePool(wsman)

        # ERROR_RECORD
        msg_data = b"\x01\x00\x00\x00\x05\x10\x04\x00" + b"\x00" * 32
        msg_data += b'<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.ErrorRecord</T><T>System.Object</T></TN><ToString>error</ToString>' \
                    b'<MS><B N="SerializeExtendedInfo">false</B><S N="FullyQualifiedErrorId">ErrorId</S><I32 N="ErrorCategory_Category">1</I32></MS></Obj>'
        fragment = Fragment(0, 0, msg_data, start=True, end=True).pack()

        with caplog.at_level(logging.WARNING, logger="pypsrp.powershell"):
            actual = rs._parse_responses(fragment)

        assert len(actual) == 1
        assert actual[0][0] == 266245
        assert str(actual[0][1].data) == 'error'
        assert len(caplog.messages) == 1
        assert caplog.messages[0] == "Unsupported message type '266245' received"


class TestPSRPScenarios(object):

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_multiple_commands']],
                             indirect=True)
    def test_psrp_multiple_commands(self, wsman_conn, monkeypatch):
        monkeypatch.setattr('cryptography.hazmat.primitives.asymmetric.rsa.'
                            'generate_private_key', gen_rsa_keypair)

        with RunspacePool(wsman_conn) as pool:
            assert pool.state == RunspacePoolState.OPENED
            # verify we can still manually call open on an opened pool
            pool.open()

            pool.exchange_keys()
            # exchange keys again and we shouldn't do any ops
            pool.exchange_keys()

            ps = PowerShell(pool)

            # Test out Secure Strings
            sec_string = pool.serialize(u"Hello World", ObjectMeta("SS"))
            ps.add_cmdlet("Set-Variable")
            ps.add_parameter("Name", "sec_string")
            ps.add_parameter("Value", sec_string)

            ps.add_statement().add_script(
                "[System.Runtime.InteropServices.marshal]"
                "::PtrToStringAuto([System.Runtime.InteropServices.marshal]"
                "::SecureStringToBSTR($sec_string))"
            )
            ps.add_statement().add_cmdlet("ConvertTo-SecureString")
            ps.add_parameter("String", "abc")
            ps.add_parameter("AsPlainText")
            ps.add_parameter("Force")

            # Test out Unicode and complex info
            string_value = u"こんにちは - actual_x000A_string\nnewline: %s" \
                           % b"\xD8\x01\xDC\x37".decode('utf-16-be')
            ps.add_statement().add_cmdlet("Set-Variable")
            ps.add_parameter("Name", "unicode_string")
            ps.add_parameter("Value", string_value)
            ps.add_statement().add_script("$unicode_string")

            # Arguments
            ps.add_statement().add_cmdlet("cmd.exe").add_argument("/c echo hi")

            # Create Command directly
            command = Command(cmd="whoami.exe", is_script=False)
            ps.add_statement().add_command(command)

            # An integer
            ps.add_statement().add_cmdlet("Set-Variable")
            ps.add_parameter("Name", "integer")
            ps.add_parameter("Value", 123)
            ps.add_statement().add_script("$integer")

            # PSCustomObject
            ps.add_statement().add_cmdlet("Get-Service").\
                add_parameter("Name", "winrm")

            output = ps.invoke()
            assert ps.state == PSInvocationState.COMPLETED

        assert pool.state == RunspacePoolState.CLOSED
        # verify we can still call close on a closed pool
        pool.close()

        assert len(output) == 7
        assert output[0] == u"Hello World"
        assert output[1] == u"abc"
        assert output[2] == string_value
        assert output[3] == u"hi\""
        # this result differs on whether this is mocked or not
        if type(wsman_conn.transport).__name__ == "TransportFake":
            assert output[4] == "win-nnmu24vvkj0\\vagrant"
        else:
            assert wsman_conn.transport.username.lower() in output[4].lower()
        assert output[5] == 123
        assert isinstance(output[6], GenericComplexObject)
        assert str(output[6]) == "winrm"
        assert output[6].adapted_properties['DisplayName'] == \
            'Windows Remote Management (WS-Management)'
        assert output[6].adapted_properties['ServiceName'] == 'winrm'
        assert output[6].extended_properties['Name'] == 'winrm'

    @pytest.mark.parametrize('wsman_conn',
                             # because we are seeing how the client handles
                             # different server protocol versions, we want to
                             # use existing responses
                             [
                                 [False, 'test_psrp_run_protocol_version_2.1'],
                                 [False, 'test_psrp_run_protocol_version_2.2'],
                                 [False, 'test_psrp_run_protocol_version_2.3'],
                             ],
                             indirect=True)
    def test_psrp_run_protocol_version(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            if type(wsman_conn.transport).__name__ == "TransportFake":
                expected_version = \
                    wsman_conn.transport._test_name.split("_")[-1]
                actual_version = pool.protocol_version
                assert actual_version == expected_version

            ps = PowerShell(pool)
            ps.add_script('''begin {
    $DebugPreference = 'Continue'
    Write-Debug "Start Block"
    Write-Error "error"
}
process {
    $input
}
end {
    Write-Debug "End Block"
}''')
            # this tests the merge logic works on v2.1
            ps.merge_error("output")
            actual = ps.invoke(["message 1", 2, ["3", 3]])

            assert len(actual) == 4
            assert str(actual[0]) == "error"
            assert isinstance(actual[0], ErrorRecord)
            assert actual[1] == u"message 1"
            assert actual[2] == 2
            assert actual[3] == [u"3", 3]
            assert ps.state == PSInvocationState.COMPLETED
            assert ps.had_errors is False
            assert ps.streams.error == []
            assert len(ps.streams.debug) == 2
            assert str(ps.streams.debug[0]) == "Start Block"
            assert str(ps.streams.debug[1]) == "End Block"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_nested_command']],
                             indirect=True)
    def test_psrp_nested_command(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script("$i = 0; while ($true) { $i++ }")
            ps.begin_invoke()
            time.sleep(0.05)

            nested_ps = ps.create_nested_power_shell()
            nested_ps.add_cmdlet("Get-Variable").add_parameter("Name", "i")
            actual = nested_ps.invoke()
            ps.stop()

        assert actual[0].adapted_properties['Value'] > 0

    @pytest.mark.parametrize('wsman_conn',
                             # information stream is not available on all hosts
                             # so we just use existing messages
                             [[False, 'test_psrp_stream_output_invocation']],
                             indirect=True)
    def test_psrp_stream_output_invocation(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)

            script = '''$DebugPreference = 'Continue'
            $VerbosePreference = 'Continue'
            Write-Debug 'debug stream'
            Write-Verbose 'verbose stream'
            Write-Error 'error stream'
            Write-Output 'output stream'
            Write-Warning 'warning stream'
            Write-Information 'information stream'
            '''

            ps.add_script(script)
            actual = ps.invoke()

        assert ps.state == PSInvocationState.COMPLETED
        assert actual == ["output stream"]
        assert ps.had_errors is False
        assert ps.output == ["output stream"]
        assert len(ps.streams.debug) == 1
        assert str(ps.streams.debug[0]) == "debug stream"
        assert ps.streams.debug[0].invocation
        assert len(ps.streams.error) == 1
        assert str(ps.streams.error[0]) == "error stream"
        assert ps.streams.error[0].invocation
        assert len(ps.streams.information) == 1
        assert ps.streams.information[0].message_data == "information stream"
        assert len(ps.streams.progress) == 1
        assert str(ps.streams.progress[0].progress_type) == "Completed"
        assert len(ps.streams.verbose) == 1
        assert str(ps.streams.verbose[0]) == "verbose stream"
        assert ps.streams.verbose[0].invocation
        assert len(ps.streams.warning) == 1
        assert str(ps.streams.warning[0]) == "warning stream"
        assert ps.streams.warning[0].invocation

    @pytest.mark.parametrize('wsman_conn',
                             # information stream is not available on all hosts
                             # so we just use existing messages
                             [[False, 'test_psrp_stream_no_output_invocation']],
                             indirect=True)
    def test_psrp_stream_no_output_invocation(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)

            script = '''$DebugPreference = 'Continue'
            $VerbosePreference = 'Continue'
            Write-Debug 'debug stream'
            Write-Verbose 'verbose stream'
            Write-Error 'error stream'
            Write-Output 'output stream'
            Write-Warning 'warning stream'
            Write-Information 'information stream'
            '''

            ps.add_script(script)
            actual = ps.invoke(remote_stream_options=0)

        assert ps.state == PSInvocationState.COMPLETED
        assert actual == ["output stream"]
        assert ps.had_errors is False
        assert ps.output == ["output stream"]
        assert len(ps.streams.debug) == 1
        assert str(ps.streams.debug[0]) == "debug stream"
        assert ps.streams.debug[0].invocation is False
        assert len(ps.streams.error) == 1
        assert str(ps.streams.error[0]) == "error stream"
        assert ps.streams.error[0].invocation is False
        assert len(ps.streams.information) == 1
        assert ps.streams.information[0].message_data == "information stream"
        assert len(ps.streams.progress) == 1
        assert str(ps.streams.progress[0].progress_type) == "Completed"
        assert len(ps.streams.verbose) == 1
        assert str(ps.streams.verbose[0]) == "verbose stream"
        assert ps.streams.verbose[0].invocation is False
        assert len(ps.streams.warning) == 1
        assert str(ps.streams.warning[0]) == "warning stream"
        assert ps.streams.warning[0].invocation is False

    @pytest.mark.parametrize('wsman_conn',
                             # due to sending the information stream we need
                             # to use existing responses as not all servers
                             # support this
                             [[False, 'test_psrp_merge_commands']],
                             indirect=True)
    def test_psrp_merge_commands(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)

            script = '''$DebugPreference = 'Continue'
            $VerbosePreference = 'Continue'
            Write-Debug 'debug stream'
            Write-Verbose 'verbose stream'
            Write-Error 'error stream'
            Write-Output 'output stream'
            Write-Warning 'warning stream'
            Write-Information 'information stream'
            '''
            ps.add_script(script)
            ps.merge_all("output")
            ps.merge_previous(True)

            ps.add_statement().add_script(script)
            ps.merge_all("output")
            ps.merge_reset()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                actual = ps.invoke()

            assert len(actual) == 7
            assert len(ps.streams.debug) == 1
            assert len(ps.streams.error) == 1
            assert len(ps.streams.information) == 1
            assert len(ps.streams.progress) == 1
            assert len(ps.streams.verbose) == 1
            assert len(ps.streams.warning) == 1

            assert str(actual[0]) == "debug stream"
            assert str(actual[1]) == "verbose stream"
            assert str(actual[2]) == "error stream"
            assert str(actual[3]) == "output stream"
            assert str(actual[4]) == "warning stream"
            assert str(actual[5]) == "information stream"

            # the 2nd statement should only have the output stream
            assert str(actual[6]) == "output stream"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_error_failed']], indirect=True)
    def test_psrp_error_failed(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script("$ErrorActionPreference = 'Stop'; "
                          "Write-Output before; "
                          "Write-Error error; Write-Output after")
            actual = ps.invoke()

        assert ps.state == PSInvocationState.FAILED
        assert ps.had_errors
        assert actual == ["before"]
        assert len(ps.streams.error) == 1
        assert str(ps.streams.error[0]) == "error"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_with_history']],
                             indirect=True)
    def test_psrp_with_history(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script("Write-Output 1; Write-Output 2")
            ps.invoke(add_to_history=True)
            ps_hist = PowerShell(pool)
            ps_hist.add_script("Get-History")
            actual = ps_hist.invoke()
        assert len(actual) == 1
        assert actual[0].adapted_properties['CommandLine'] == \
            "Write-Output 1; Write-Output 2"
        assert actual[0].adapted_properties['ExecutionStatus'] == "Completed"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_with_no_history']],
                             indirect=True)
    def test_psrp_with_no_history(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script("Write-Output 1; Write-Output 2")
            ps.invoke()
            ps_hist = PowerShell(pool)
            ps_hist.add_script("Get-History")
            actual = ps_hist.invoke()
        assert actual == []

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_with_input']],
                             indirect=True)
    def test_psrp_with_input(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script('''begin {
                $DebugPreference = 'Continue'
                Write-Debug "Start Block"
            }
            process {
                $input
            }
            end {
                Write-Debug "End Block"
            }''')
            actual = ps.invoke(["1", 2, {"a": "b"}, ["a", "b"]])

        assert actual == [
            u"1",
            2,
            {u"a": u"b"},
            [u"a", u"b"]
        ]
        assert str(ps.streams.debug[0]) == "Start Block"
        assert str(ps.streams.debug[1]) == "End Block"

    @pytest.mark.parametrize('wsman_conn',
                             # the message size can differ from hosts, we will
                             # just use existing responses to get the same
                             # scenario each time
                             [[False, 'test_psrp_small_msg_size']],
                             indirect=True)
    def test_psrp_small_msg_size(self, wsman_conn):
        # we need to set the endpoint for the fake tests to the same length as
        # the one that created the message. This is so the max payload size is
        # the same
        wsman_conn.transport.endpoint = "https://127.0.0.1:55986/wsman"
        wsman_conn.update_max_payload_size()

        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            # there seems to be a bug in the PSRP implementation, I cannot get
            # it to response with a fragment larger than the max allowed so
            # we will just test it receives our large fragments that are split
            ps.add_script('''begin {
    $big_var = '%s'
} process {
    $input
} end {
    $big_var[0..19999] -join ""
    $big_var[20000..30000] -join ""
}''' % ("a" * 30000))
            actual = ps.invoke("input")
        assert actual[0] == u"input"
        assert actual[1] == u"a" * 20000
        assert actual[2] == u"a" * 10000

    @pytest.mark.parametrize('wsman_conn',
                             # so we don't wait 10 seconds in a test we use
                             # pre-built responses
                             [[False, 'test_psrp_long_running_cmdlet']],
                             indirect=True)
    def test_psrp_long_running_cmdlet(self, wsman_conn):
        wsman_conn.operation_timeout = 5

        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_cmdlet("Start-Sleep").add_parameter("Seconds", 10)
            ps.add_statement().add_script("echo hi")
            actual = ps.invoke()
        assert actual[0] == u"hi"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_clear_commands']],
                             indirect=True)
    def test_psrp_clear_command(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.add_script("echo original")
            ps.clear_commands()
            ps.add_script("echo new")
            actual = ps.invoke()
        assert actual[0] == u"new"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_receive_failure']],
                             indirect=True)
    def test_psrp_receive_failure(self, wsman_conn):
        with RunspacePool(wsman_conn) as pool:
            ps = PowerShell(pool)
            ps.state = PSInvocationState.RUNNING
            ps._command_id = ps.id

            with pytest.raises(WSManFaultError) as err:
                ps.end_invoke()
            assert str(err.value.reason) == \
                "The Windows Remote Shell received a request to perform an " \
                "operation on a command identifier that does not exist. " \
                "Either the command has completed execution or the client " \
                "specified an invalid command identifier."

    @pytest.mark.parametrize('wsman_conn',
                             # due to tests sometimes leaving pools open
                             # we are going to mock the data for this one
                             [[False, 'test_psrp_disconnected_commands']],
                             indirect=True)
    def test_psrp_disconnected_commands(self, wsman_conn):
        pools = None
        try:
            script = "Write-Output 'a'; Start-Sleep -Seconds 5; " \
                     "Write-Output 'b'"
            pool1 = RunspacePool(wsman_conn)
            pool1.open()
            ps1 = PowerShell(pool1)
            ps1.add_script(script)
            ps1.begin_invoke()
            pool1.disconnect()

            pool2 = RunspacePool(wsman_conn)
            pool2.open()
            ps2 = PowerShell(pool2)
            ps2.add_script(script)
            ps2.begin_invoke()
            pool2.disconnect()

            pools = RunspacePool.get_runspace_pools(wsman_conn)
            assert len(pools) == 2
            assert len(pools[0].pipelines.keys()) == 1
            assert len(pools[1].pipelines.keys()) == 1
            for idx, pool in enumerate(pools):
                pool.connect()
                pipelines = pool.create_disconnected_power_shells()
                for pipeline in pipelines:
                    if idx == 0:
                        pipeline.connect_async()

                        with pytest.raises(InvalidPSRPOperation) as exc:
                            pipeline.create_nested_power_shell()
                        assert str(exc.value) == \
                            "Cannot created a nested PowerShell pipeline " \
                            "from an existing pipeline that was connected to" \
                            " remotely"
                        actual = pipeline.end_invoke()
                    else:
                        actual = pipeline.connect()
                    assert actual == ["a", "b"]
        finally:
            if pools is None:
                pools = RunspacePool.get_runspace_pools(wsman_conn)
            for pool in pools:
                pool.connect()
                pool.close()

    def test_add_parameters(self):
        ps = PowerShell(RSPoolTest())
        ps.add_cmdlet("Test-Path")
        ps.add_parameters({"Path": "path", "ItemType": "Leaf"})
        assert len(ps.commands) == 1
        assert ps.commands[0].cmd == "Test-Path"

        # we can't guarantee the dict order so this is the next best thing
        args = ps.commands[0].args
        assert args[0].name == 'Path' or args[0].name == 'ItemType'
        assert args[1].name == 'Path' or args[1].name == 'ItemType'

    def test_connect_async_invalid_state(self):
        ps = PowerShell(RSPoolTest())
        with pytest.raises(InvalidPipelineStateError) as err:
            ps.connect()
        assert err.value.action == "connect to a disconnected pipeline"
        assert err.value.current_state == PSInvocationState.NOT_STARTED
        assert err.value.expected_state == PSInvocationState.DISCONNECTED
        assert str(err.value) == \
            "Cannot 'connect to a disconnected pipeline' on the current " \
            "state 'NotStarted', expecting state(s): 'Disconnected'"

    def test_psrp_create_nested_invalid_state(self):
        ps = PowerShell(RSPoolTest())
        with pytest.raises(InvalidPipelineStateError) as err:
            ps.create_nested_power_shell()
        assert err.value.action == "create a nested PowerShell pipeline"
        assert err.value.current_state == PSInvocationState.NOT_STARTED
        assert err.value.expected_state == PSInvocationState.RUNNING
        assert str(err.value) == \
            "Cannot 'create a nested PowerShell pipeline' on the current " \
            "state 'NotStarted', expecting state(s): 'Running'"

    def test_psrp_create_nested_from_disconnect(self):
        ps = PowerShell(RSPoolTest())
        ps.state = PSInvocationState.RUNNING
        ps._from_disconnect = True
        with pytest.raises(InvalidPSRPOperation) as err:
            ps.create_nested_power_shell()
        assert str(err.value) == \
            "Cannot created a nested PowerShell pipeline from an existing " \
            "pipeline that was connected to remotely"

    def test_psrp_begin_invoke_invalid_state(self):
        ps = PowerShell(RSPoolTest())
        ps.state = PSInvocationState.COMPLETED
        with pytest.raises(InvalidPipelineStateError) as err:
            ps.begin_invoke()
        assert err.value.action == "start a PowerShell pipeline"
        assert err.value.current_state == PSInvocationState.COMPLETED
        assert err.value.expected_state == PSInvocationState.NOT_STARTED
        assert str(err.value) == \
            "Cannot 'start a PowerShell pipeline' on the current state " \
            "'Completed', expecting state(s): 'NotStarted'"

    def test_psrp_being_invoke_no_commands(self):
        ps = PowerShell(RSPoolTest())
        with pytest.raises(InvalidPSRPOperation) as err:
            ps.begin_invoke()
        assert str(err.value) == "Cannot invoke PowerShell without any " \
                                 "commands being set"

    def test_psrp_stop_already_stopped(self):
        ps = PowerShell(RSPoolTest())
        ps.state = PSInvocationState.STOPPED
        ps.stop()
        ps.state = PSInvocationState.STOPPING

    def test_psrp_stop_non_running_pipeline(self):
        ps = PowerShell(RSPoolTest())
        states = [
            PSInvocationState.NOT_STARTED,
            PSInvocationState.COMPLETED,
            PSInvocationState.DISCONNECTED,
            PSInvocationState.FAILED
        ]
        state_msg = {
            PSInvocationState.NOT_STARTED: "NotStarted",
            PSInvocationState.COMPLETED: "Completed",
            PSInvocationState.DISCONNECTED: "Disconnected",
            PSInvocationState.FAILED: "Failed"
        }

        for state in states:
            with pytest.raises(InvalidPipelineStateError) as err:
                ps.state = state
                ps.stop()

            assert err.value.action == "stop a running pipeline"
            assert err.value.current_state == state
            assert err.value.expected_state == PSInvocationState.RUNNING
            assert str(err.value) == \
                "Cannot 'stop a running pipeline' on the current state '%s'," \
                " expecting state(s): 'Running'" % state_msg[state]

    def test_set_merge_to_invalid_to(self):
        ps = PowerShell(RSPoolTest())
        with pytest.raises(InvalidPSRPOperation) as err:
            ps._set_merge_to("error", "fake", None)
        assert str(err.value) == "Invalid merge to option 'fake', valid " \
                                 "values none, null, output"

        with pytest.raises(InvalidPSRPOperation) as err:
            ps._set_merge_to("error", "fake", ["option1", "option2"])
        assert str(err.value) == \
            "Invalid merge to option 'fake', valid values option1, option2"

    def test_set_merge_to_invalid_protocol(self):
        ps = PowerShell(RSPoolTest())
        with pytest.raises(InvalidPSRPOperation) as err:
            ps._set_merge_to("error", "output", None, "3.0")
        assert str(err.value) == "Merge option for 'error' is not supported " \
                                 "in the current protocol version 2.3, " \
                                 "minimum version required 3.0"


class TestFragmenter(object):

    def test_fragment_one_one_fragment(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        empty_uuid = "00000000-0000-0000-0000-000000000000"
        pipeline_input = PipelineInput("12")

        actual = fragmenter.fragment(pipeline_input, empty_uuid)
        assert actual == [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>12</S>"
        ]

    def test_fragment_one_multiple_fragments(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        empty_uuid = "00000000-0000-0000-0000-000000000000"
        pipeline_input = PipelineInput("1234")

        actual = fragmenter.fragment(pipeline_input, empty_uuid)
        assert actual == [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>1234</",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x02"
            b"\x00\x00\x00\x02"
            b"S>"
        ]

    def test_fragment_really_large(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        empty_uuid = "00000000-0000-0000-0000-000000000000"
        pipeline_input = PipelineInput("a" * 60)

        actual = fragmenter.fragment(pipeline_input, empty_uuid)
        assert actual == [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>aaaaaa",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00"
            b"\x00\x00\x00\x31"
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x02"
            b"\x02"
            b"\x00\x00\x00\x09"
            b"aaaaa</S>",
        ]

    def test_fragment_multiple(self):
        serial = Serializer()
        fragmenter = Fragmenter(140, serial)
        empty_uuid = "00000000-0000-0000-0000-000000000000"
        msg1 = PipelineInput("12")
        msg2 = PipelineInput("34")
        msg3 = PipelineInput("567")
        msg4 = PipelineInput("890")

        actual = fragmenter.fragment_multiple([msg1, msg2, msg3, msg4],
                                              empty_uuid)
        assert actual == [
            # actual 1 should fit both msg 1 and 2 exactly
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>12</S>"
            b"\x00\x00\x00\x00\x00\x00\x00\x02"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>34</S>",
            # actual 2 should fit msg 3 and the start of msg 4
            b"\x00\x00\x00\x00\x00\x00\x00\x03"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x32"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>567</S>"
            b"\x00\x00\x00\x00\x00\x00\x00\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x30"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>890</",
            # actual 3 should contain the rest of msg 4
            b"\x00\x00\x00\x00\x00\x00\x00\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x02"
            b"\x00\x00\x00\x02"
            b"S>"
        ]

    def test_defragment_one_fragment(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        fragments = [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>12</S>"
        ]
        actual = []
        for fragment in fragments:
            actual.extend(fragmenter.defragment(fragment))

        assert len(actual) == 1
        assert actual[0].message_type == MessageType.PIPELINE_INPUT
        assert actual[0].data.data == "12"

    def test_defragment_two_fragments_one_message(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        fragments = [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>1234</",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x02"
            b"\x00\x00\x00\x02"
            b"S>"
        ]
        actual = []
        for fragment in fragments:
            actual.extend(fragmenter.defragment(fragment))

        assert len(actual) == 1
        assert actual[0].message_type == MessageType.PIPELINE_INPUT
        assert actual[0].data.data == "1234"

    def test_defragment_large_message(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        fragments = [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>aaaaaa",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00"
            b"\x00\x00\x00\x31"
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x02"
            b"\x02"
            b"\x00\x00\x00\x09"
            b"aaaaa</S>",
        ]
        actual = []
        for fragment in fragments:
            actual.extend(fragmenter.defragment(fragment))

        assert len(actual) == 1
        assert actual[0].message_type == MessageType.PIPELINE_INPUT
        assert actual[0].data.data == "a" * 60

    def test_defragment_multiple_fragments_multiple_messages(self):
        serial = Serializer()
        fragmenter = Fragmenter(140, serial)
        fragments = [
            # actual 1 should fit both msg 1 and 2 exactly
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>12</S>"
            b"\x00\x00\x00\x00\x00\x00\x00\x02"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>34</S>",
            # actual 2 should fit msg 3 and the start of msg 4
            b"\x00\x00\x00\x00\x00\x00\x00\x03"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x03"
            b"\x00\x00\x00\x32"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>567</S>"
            b"\x00\x00\x00\x00\x00\x00\x00\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x30"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>890</",
            # actual 3 should contain the rest of msg 4
            b"\x00\x00\x00\x00\x00\x00\x00\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x02"
            b"\x00\x00\x00\x02"
            b"S>"
        ]
        actual = []
        for fragment in fragments:
            actual.extend(fragmenter.defragment(fragment))

        assert len(actual) == 4
        assert actual[0].message_type == MessageType.PIPELINE_INPUT
        assert actual[0].data.data == "12"
        assert actual[1].message_type == MessageType.PIPELINE_INPUT
        assert actual[1].data.data == "34"
        assert actual[2].message_type == MessageType.PIPELINE_INPUT
        assert actual[2].data.data == "567"
        assert actual[3].message_type == MessageType.PIPELINE_INPUT
        assert actual[3].data.data == "890"

    def test_defragment_invalid_frag_id(self):
        serial = Serializer()
        fragmenter = Fragmenter(70, serial)
        fragments = [
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00\x31"
            b"\x02\x00\x00\x00"
            b"\x02\x10\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"<S>aaaaaa",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x02"
            b"\x02"
            b"\x00\x00\x00\x09"
            b"aaaaa</S>",
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x00"
            b"\x00\x00\x00\x31"
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        fragmenter.defragment(fragments[0])
        with pytest.raises(FragmentError) as err:
            fragmenter.defragment(fragments[1])
        assert str(err.value) == \
            "Fragment Fragment Id: 2 != Expected Fragment Id: 1"
