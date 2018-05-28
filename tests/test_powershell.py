# -*- coding: utf-8 -*-

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from pypsrp.complex_objects import Command, GenericComplexObject, ObjectMeta, \
    PSInvocationState, RunspacePoolState
from pypsrp.exceptions import InvalidPSRPOperation
from pypsrp.powershell import RunspacePool, PowerShell
from pypsrp.wsman import WSMan


class TestRunspacePool(object):

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_psrp_open_runspace']],
                             indirect=True)
    def test_psrp_open_runspace(self, winrm_transport):
        # TODO also test out small packet size and large init_runspace_pool
        wsman = WSMan(winrm_transport)
        runspace_pool = RunspacePool(wsman)
        assert runspace_pool.state == RunspacePoolState.BEFORE_OPEN
        runspace_pool.open()
        assert runspace_pool.application_private_data is not None
        assert runspace_pool.state == RunspacePoolState.OPENED
        runspace_pool.close()
        assert runspace_pool.state == RunspacePoolState.CLOSED

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_psrp_set_runspaces']],
                             indirect=True)
    def test_psrp_set_runspaces(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        runspace_pool = RunspacePool(wsman)
        assert runspace_pool.min_runspaces == 1
        assert runspace_pool.max_runspaces == 1

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

            with pytest.raises(InvalidPSRPOperation) as exc:
                runspace_pool.min_runspaces = -1
            assert str(exc.value) == "Failed to set minimum runspaces"

            with pytest.raises(InvalidPSRPOperation) as exc:
                runspace_pool.max_runspaces = -1
            assert str(exc.value) == "Failed to set maximum runspaces"
        finally:
            runspace_pool.close()

    @pytest.mark.parametrize('winrm_transport',
                             # due to tests sometimes leaving pools open
                             # we are going to mock the data for this one
                             [[False, 'test_psrp_disconnect_runspaces']],
                             indirect=True)
    def test_psrp_disconnect_runspaces(self, winrm_transport):
        wsman = WSMan(winrm_transport)
        runspace_pool = RunspacePool(wsman)
        runspace_pool.open()
        runspace_pool.disconnect()
        assert runspace_pool.state == RunspacePoolState.DISCONNECTED
        runspace_pool.connect()
        assert runspace_pool.state == RunspacePoolState.OPENED
        runspace_pool.disconnect()

        actual = []
        try:
            runspace_pool2 = RunspacePool(wsman)
            runspace_pool2.open()
            runspace_pool2.disconnect()

            wsman2 = WSMan(winrm_transport)
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


class TestPSRPScenarios(object):

    @pytest.mark.parametrize('winrm_transport',
                             [[True, 'test_psrp_multiple_commands']],
                             indirect=True)
    def test_psrp_multiple_commands(self, winrm_transport, monkeypatch):
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
        monkeypatch.setattr('cryptography.hazmat.primitives.asymmetric.rsa.'
                            'generate_private_key', gen_rsa_keypair)

        wsman = WSMan(winrm_transport)
        runspace_pool = None
        with RunspacePool(wsman) as pool:
            runspace_pool = pool
            assert pool.state == RunspacePoolState.OPENED
            # verify we can still manually call open on an opened pool
            pool.open()

            pool.exchange_keys()
            # exchange keys again and we shouldn't do any ops
            pool.exchange_keys()

            ps = PowerShell(pool)

            # Test out Secure Strings
            sec_string = pool._serializer.serialize(u"Hello World",
                                                    ObjectMeta("SS"))
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

        assert runspace_pool.state == RunspacePoolState.CLOSED
        # verify we can still call close on a closed pool
        runspace_pool.close()

        assert len(output) == 7
        assert output[0] == u"Hello World"
        assert output[1] == u"abc"
        assert output[2] == string_value
        assert output[3] == u"hi\""
        # this result differs on whether this is mocked or not
        if type(winrm_transport).__name__ == "TransportFake":
            assert output[4] == "win-j4ractt2gq8\\vagrant"
        else:
            assert winrm_transport.username.lower() in output[4].lower()
        assert output[5] == 123
        assert isinstance(output[6], GenericComplexObject)
        assert str(output[6]) == "winrm"
        assert output[6].adapted_properties['DisplayName'] == 'Windows Remote Management (WS-Management)'
        assert output[6].adapted_properties['ServiceName'] == 'winrm'
        assert output[6].extended_properties['Name'] == 'winrm'
