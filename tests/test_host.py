import uuid

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from pypsrp.complex_objects import Color, ControlKeyState, Coordinates, \
    CultureInfo, KeyInfo, KeyInfoDotNet, GenericComplexObject, \
    HostMethodIdentifier, ObjectMeta, PSCredential, Size
from pypsrp.host import PSHost, PSHostRawUserInterface, PSHostUserInterface
from pypsrp.messages import ProgressRecord
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


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


class TestPSHost(object):

    @pytest.mark.parametrize('wsman_conn',
                             # The actual culture can vary from host to host
                             [[True, 'test_psrp_pshost_methods']],
                             indirect=True)
    def test_psrp_pshost_methods(self, wsman_conn):
        host = PSHost(None, None, False, "host name", None, None, "1.0")

        with RunspacePool(wsman_conn, host=host) as pool:
            ps = PowerShell(pool)
            # SetShouldExit is really the only one that seems to work so
            # we will just test that
            ps.add_script('$host.CurrentCulture; $host.SetShouldExit(1)')
            actual = ps.invoke()
            assert len(actual) == 1
            assert str(actual[0]) == "en-US"
            assert isinstance(actual[0], CultureInfo)
            assert host.rc == 1

    def test_pshost_not_implemented_methods(self):
        host = PSHost(None, None, False, None, None, None, None)
        with pytest.raises(NotImplementedError):
            host.EnterNestedPrompt(None, None)
        with pytest.raises(NotImplementedError):
            host.ExitNestedPrompt(None, None)

    def test_pshost_methods(self):
        wsman = WSMan("server")
        runspace = RunspacePool(wsman)
        host = PSHost(CultureInfo(), CultureInfo(), True, "name", None, None,
                      "1.0")

        assert host.GetName(None, None) == "name"
        actual_version = host.GetVersion(runspace, None)
        assert actual_version.text == "1.0"
        assert actual_version.tag == "Version"
        assert isinstance(host.GetInstanceId(None, None), uuid.UUID)
        assert isinstance(host.GetCurrentCulture(None, None), CultureInfo)
        assert isinstance(host.GetCurrentUICulture(None, None), CultureInfo)
        host.NotifyBeginApplication(None, None)
        host.NotifyEndApplication(None, None)

    def test_pshost_run_method_not_implemented(self):
        host = PSHost(None, None, False, None, None, None, None)
        actual = host.run_method(HostMethodIdentifier(value=53), [], None)
        assert actual is None


class TestPSHostUserInterface(object):

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_psrp_pshost_ui_mocked_methods']],
                             indirect=True)
    def test_psrp_pshost_ui_mocked_methods(self, wsman_conn, monkeypatch):
        # This tests that the args from an actual host call match up with our
        # definitions
        monkeypatch.setattr('cryptography.hazmat.primitives.asymmetric.rsa.'
                            'generate_private_key', gen_rsa_keypair)

        mock_read_line = MagicMock(return_value="ReadLine response")
        mock_read_line_as_ss = MagicMock()
        mock_write1 = MagicMock(return_value=None)
        mock_write2 = MagicMock(return_value=None)
        mock_write_line1 = MagicMock(return_value=None)
        mock_write_line2 = MagicMock(return_value=None)
        mock_write_line3 = MagicMock(return_value=None)
        mock_write_error = MagicMock(return_value=None)
        mock_write_debug = MagicMock(return_value=None)
        mock_write_progress = MagicMock(return_value=None)
        mock_write_verbose = MagicMock(return_value=None)
        mock_write_warning = MagicMock(return_value=None)
        mock_prompt = MagicMock(return_value={
            "prompt field": "prompt response",
        })
        mock_prompt_credential = MagicMock()
        mock_prompt_choice = MagicMock(return_value=1)

        host_ui = PSHostUserInterface()
        host_ui.ReadLine = mock_read_line
        host_ui.ReadLineAsSecureString = mock_read_line_as_ss
        host_ui.Write1 = mock_write1
        host_ui.Write2 = mock_write2
        host_ui.WriteLine1 = mock_write_line1
        host_ui.WriteLine2 = mock_write_line2
        host_ui.WriteLine3 = mock_write_line3
        host_ui.WriteErrorLine = mock_write_error
        host_ui.WriteDebugLine = mock_write_debug
        host_ui.WriteProgress = mock_write_progress
        host_ui.WriteVerboseLine = mock_write_verbose
        host_ui.WriteWarningLine = mock_write_warning
        host_ui.Prompt = mock_prompt
        # seems like PS never calls PromptForCredential1 so we will skip that
        host_ui.PromptForCredential2 = mock_prompt_credential
        host_ui.PromptForChoice = mock_prompt_choice

        host = PSHost(None, None, False, None, None, host_ui, None)

        with RunspacePool(wsman_conn, host=host) as pool:
            pool.exchange_keys()
            mock_read_line_as_ss.return_value = pool.serialize(
                u"ReadLineAsSecureString response", ObjectMeta("SS")
            )
            mock_ps_credential = PSCredential(username="username",
                                              password=u"password")
            mock_prompt_credential.return_value = mock_ps_credential

            ps = PowerShell(pool)
            ps.add_script('''$host.UI.ReadLine()
$host.UI.ReadLineAsSecureString()
$host.UI.Write("Write1")
$host.UI.Write([System.ConsoleColor]::Blue, [System.ConsoleColor]::White, "Write2")
$host.UI.WriteLine()
$host.UI.WriteLine("WriteLine2")
$host.UI.WriteLine([System.ConsoleColor]::Gray, [System.ConsoleColor]::Green, "WriteLine3")
$host.UI.WriteErrorLine("WriteErrorLine")
$host.UI.WriteDebugLine("WriteDebugLine")
$host.UI.WriteProgress(1, (New-Object -TypeName System.Management.Automation.ProgressRecord -ArgumentList 2, "activity", "description"))
$host.UI.WriteVerboseLine("WriteVerboseLine")
$host.UI.WriteWarningLine("WriteWarningLine")

$prompt_field = New-Object -TypeName System.Management.Automation.Host.FieldDescription -ArgumentList @("prompt field")
$prompt_field.Label = "PromptLabel"
$host.UI.Prompt("Prompt caption", "Prompt message", $prompt_field)

$host.UI.PromptForCredential("PromptForCredential caption", "PromptForCredential message", "PromptForCredential user", "PromptForCredential target")

$choice_field1 = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList "Prompt1 label", "Prompt1 help"
$choice_field2 = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList "Prompt2 label", "Prompt2 help"
$host.UI.PromptForChoice("PromptForChoice caption", "PromptForChoice message", @($choice_field1, $choice_field2), 0)''')
            actual = ps.invoke()

        assert len(actual) == 5

        assert actual[0] == "ReadLine response"
        assert mock_read_line.call_count == 1
        assert isinstance(mock_read_line.call_args[0][0], RunspacePool)
        assert isinstance(mock_read_line.call_args[0][1], PowerShell)

        assert actual[1] == "ReadLineAsSecureString response"
        assert mock_read_line_as_ss.call_count == 1
        assert isinstance(mock_read_line_as_ss.call_args[0][0],
                          RunspacePool)
        assert isinstance(mock_read_line_as_ss.call_args[0][1], PowerShell)

        assert mock_write1.call_count == 1
        assert isinstance(mock_write1.call_args[0][0], RunspacePool)
        assert isinstance(mock_write1.call_args[0][1], PowerShell)
        assert mock_write1.call_args[0][2] == "Write1"

        assert mock_write2.call_count == 1
        assert isinstance(mock_write2.call_args[0][0], RunspacePool)
        assert isinstance(mock_write2.call_args[0][1], PowerShell)
        assert mock_write2.call_args[0][2] == Color.BLUE
        assert mock_write2.call_args[0][3] == Color.WHITE
        assert mock_write2.call_args[0][4] == "Write2"

        assert mock_write_line1.call_count == 1
        assert isinstance(mock_write_line1.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_line1.call_args[0][1], PowerShell)

        assert mock_write_line2.call_count == 1
        assert isinstance(mock_write_line2.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_line2.call_args[0][1], PowerShell)
        assert mock_write_line2.call_args[0][2] == "WriteLine2"

        assert mock_write_line3.call_count == 1
        assert isinstance(mock_write_line3.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_line3.call_args[0][1], PowerShell)
        assert mock_write_line3.call_args[0][2] == Color.GRAY
        assert mock_write_line3.call_args[0][3] == Color.GREEN
        assert mock_write_line3.call_args[0][4] == "WriteLine3"

        assert mock_write_error.call_count == 1
        assert isinstance(mock_write_error.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_error.call_args[0][1], PowerShell)
        assert mock_write_error.call_args[0][2] == "WriteErrorLine"

        assert mock_write_debug.call_count == 1
        assert isinstance(mock_write_debug.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_debug.call_args[0][1], PowerShell)
        assert mock_write_debug.call_args[0][2] == "WriteDebugLine"

        # On PSv5 a progress record is always sent, we still sent one
        # ourselves to ensure it works so we verify we received at least
        # one and assert the last
        assert mock_write_progress.call_count > 0
        progress_args = mock_write_progress.call_args_list[-1]
        assert isinstance(progress_args[0][0], RunspacePool)
        assert isinstance(progress_args[0][1], PowerShell)
        assert progress_args[0][2] == 1
        progress_record = pool._serializer.deserialize(
            progress_args[0][3], ObjectMeta("Obj", object=ProgressRecord)
        )
        assert progress_record.activity == "activity"
        assert progress_record.activity_id == 2
        assert progress_record.description == "description"

        assert mock_write_verbose.call_count == 1
        assert isinstance(mock_write_verbose.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_verbose.call_args[0][1], PowerShell)
        assert mock_write_verbose.call_args[0][2] == "WriteVerboseLine"

        assert mock_write_warning.call_count == 1
        assert isinstance(mock_write_warning.call_args[0][0], RunspacePool)
        assert isinstance(mock_write_warning.call_args[0][1], PowerShell)
        assert mock_write_warning.call_args[0][2] == "WriteWarningLine"

        assert actual[2] == {"prompt field": "prompt response"}
        assert mock_prompt.call_count == 1
        assert isinstance(mock_prompt.call_args[0][0], RunspacePool)
        assert isinstance(mock_prompt.call_args[0][1], PowerShell)
        assert mock_prompt.call_args[0][2] == "Prompt caption"
        assert mock_prompt.call_args[0][3] == "Prompt message"
        assert isinstance(mock_prompt.call_args[0][4], list)
        assert len(mock_prompt.call_args[0][4]) == 1
        assert mock_prompt.call_args[0][4][0].extended_properties['name'] == \
            'prompt field'
        assert mock_prompt.call_args[0][4][0].extended_properties['label'] == \
            'PromptLabel'

        assert isinstance(actual[3], PSCredential)
        assert actual[3].username == "username"
        assert actual[3].password == "password"
        assert mock_prompt_credential.call_count == 1
        assert isinstance(mock_prompt_credential.call_args[0][0],
                          RunspacePool)
        assert isinstance(mock_prompt_credential.call_args[0][1],
                          PowerShell)
        assert mock_prompt_credential.call_args[0][2] == \
            "PromptForCredential caption"
        assert mock_prompt_credential.call_args[0][3] == \
            "PromptForCredential message"
        assert mock_prompt_credential.call_args[0][4] == \
            "PromptForCredential user"
        assert mock_prompt_credential.call_args[0][5] == \
            "PromptForCredential target"
        assert mock_prompt_credential.call_args[0][6] == 3
        assert mock_prompt_credential.call_args[0][7] == 1

        assert actual[4] == 1
        assert mock_prompt_choice.call_count == 1
        assert isinstance(mock_prompt_choice.call_args[0][0], RunspacePool)
        assert isinstance(mock_prompt_choice.call_args[0][1], PowerShell)
        assert mock_prompt_choice.call_args[0][2] == "PromptForChoice caption"
        assert mock_prompt_choice.call_args[0][3] == "PromptForChoice message"
        assert isinstance(mock_prompt_choice.call_args[0][4], list)
        assert len(mock_prompt_choice.call_args[0][4]) == 2
        assert mock_prompt_choice.call_args[0][4][0].extended_properties[
            'label'] == "Prompt1 label"
        assert mock_prompt_choice.call_args[0][4][0].extended_properties[
            'helpMessage'] == "Prompt1 help"
        assert mock_prompt_choice.call_args[0][4][1].extended_properties[
            'label'] == "Prompt2 label"
        assert mock_prompt_choice.call_args[0][4][1].extended_properties[
            'helpMessage'] == "Prompt2 help"

    def test_ps_host_ui_implemented(self):
        ui = PSHostUserInterface()
        ui.Write1(None, None, "value")
        assert ui.stdout == ["value"]

        ui = PSHostUserInterface()
        ui.Write2(None, None, 1, 1, "value")
        assert ui.stdout == ["value"]

        ui = PSHostUserInterface()
        ui.WriteLine1(None, None)
        assert ui.stdout == ["\r\n"]

        ui = PSHostUserInterface()
        ui.WriteLine2(None, None, "value")
        assert ui.stdout == ["value\r\n"]

        ui = PSHostUserInterface()
        ui.WriteLine3(None, None, 1, 1, "value")
        assert ui.stdout == ["value\r\n"]

        ui = PSHostUserInterface()
        ui.WriteErrorLine(None, None, "value")
        assert ui.stderr == ["value\r\n"]

        ui = PSHostUserInterface()
        ui.WriteDebugLine(None, None, "value")
        assert ui.stdout == ["DEBUG: value\r\n"]

        ui = PSHostUserInterface()
        ui.WriteProgress(None, None, 1, None)
        assert ui.stdout == []

        ui = PSHostUserInterface()
        ui.WriteVerboseLine(None, None, "value")
        assert ui.stdout == ["VERBOSE: value\r\n"]

        ui = PSHostUserInterface()
        ui.WriteWarningLine(None, None, "value")
        assert ui.stdout == ["WARNING: value\r\n"]

    def test_pshost_ui_not_implemented(self):
        # tests that methods we have marked as not implemented raise the error
        ui = PSHostUserInterface()

        with pytest.raises(NotImplementedError):
            ui.ReadLine(None, None)

        with pytest.raises(NotImplementedError):
            ui.ReadLineAsSecureString(None, None)

        with pytest.raises(NotImplementedError):
            ui.Prompt(None, None, None, None, None)

        with pytest.raises(NotImplementedError):
            ui.PromptForCredential1(None, None, None, None, None, None)

        with pytest.raises(NotImplementedError):
            ui.PromptForCredential2(None, None, None, None, None, None, None,
                                    None)

        with pytest.raises(NotImplementedError):
            ui.PromptForChoice(None, None, None, None, None, None)


class TestPSHostRawUserInterface(object):

    @pytest.mark.parametrize(
        'wsman_conn', [[True, 'test_psrp_pshost_raw_ui_mocked_methods']],
        indirect=True
    )
    def test_psrp_pshost_raw_ui_mocked_methods(self, wsman_conn,
                                               monkeypatch):
        # in a mocked context the calculated size differs on a few variables
        # we will mock out that call and return the ones used in our existing
        # responses
        mock_calc = MagicMock()
        mock_calc.side_effect = [113955, 382750]

        key_info = KeyInfo(code=65, character="a",
                           state=ControlKeyState.CapsLockOn, key_down=True)

        set_foreground_color = MagicMock(return_value=None)
        set_background_color = MagicMock(return_value=None)
        set_cursor_position = MagicMock(return_value=None)
        set_window_position = MagicMock(return_value=None)
        set_cursor_size = MagicMock(return_value=None)
        set_buffer_size = MagicMock(return_value=None)
        set_window_size = MagicMock(return_value=None)
        set_window_title = MagicMock(return_value=None)
        read_key = MagicMock(return_value=key_info)
        flush_input = MagicMock(return_value=None)
        set_buffer1 = MagicMock(return_value=None)
        set_buffer2 = MagicMock(return_value=None)
        scroll_buffer = MagicMock(return_value=None)

        window_title = "pypsrp window"
        cursor_size = 50
        foreground_color = Color(value=Color.WHITE)
        background_color = Color(value=Color.BLUE)
        cursor_position = Coordinates(x=1, y=2)
        window_position = Coordinates(x=3, y=4)
        buffer_size = Size(width=80, height=80)
        max_physical_window_size = Size(width=80, height=80)
        max_window_size = Size(width=80, height=80)
        window_size = Size(width=80, height=80)

        host_raw_ui = PSHostRawUserInterface(window_title, cursor_size,
                                             foreground_color,
                                             background_color, cursor_position,
                                             window_position, buffer_size,
                                             max_physical_window_size,
                                             max_window_size, window_size)
        host_raw_ui.SetForegroundColor = set_foreground_color
        host_raw_ui.SetBackgroundColor = set_background_color
        host_raw_ui.SetCursorPosition = set_cursor_position
        host_raw_ui.SetWindowPosition = set_window_position
        host_raw_ui.SetCursorSize = set_cursor_size
        host_raw_ui.SetBufferSize = set_buffer_size
        host_raw_ui.SetWindowSize = set_window_size
        host_raw_ui.SetWindowTitle = set_window_title
        host_raw_ui.ReadKey = read_key
        host_raw_ui.FlushInputBuffer = flush_input
        host_raw_ui.SetBufferContents1 = set_buffer1
        host_raw_ui.SetBufferContents2 = set_buffer2
        host_raw_ui.ScrollBufferContents = scroll_buffer

        host_ui = PSHostUserInterface(host_raw_ui)
        host = PSHost(None, None, False, None, None, host_ui, None)

        with RunspacePool(wsman_conn, host=host) as pool:
            ps = PowerShell(pool)
            ps.add_script('''$host.UI.RawUI.ForegroundColor
$host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::Green
$host.UI.RawUI.ForegroundColor

$host.UI.RawUI.BackgroundColor
$host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Red
$host.UI.RawUI.BackgroundColor

$host.UI.RawUI.CursorPosition
$host.UI.RawUI.CursorPosition = (New-Object -TypeName System.Management.Automation.Host.Coordinates -ArgumentList 11, 12)
$host.UI.RawUI.CursorPosition

$host.UI.RawUI.WindowPosition
$host.UI.RawUI.WindowPosition = (New-Object -TypeName System.Management.Automation.Host.Coordinates -ArgumentList 13, 14)
$host.UI.RawUI.WindowPosition

$host.UI.RawUI.CursorSize
$host.UI.RawUI.CursorSize = 25
$host.UI.RawUI.CursorSize

$host.UI.RawUI.BufferSize
$host.UI.RawUI.BufferSize = (New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList 8, 9)
$host.UI.RawUI.BufferSize

$host.UI.RawUI.WindowSize
$host.UI.RawUI.WindowSize = (New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList 8, 9)
$host.UI.RawUI.WindowSize

$host.UI.RawUI.WindowTitle
$host.UI.RawUI.WindowTitle = "New Window Title"
$host.UI.RawUI.WindowTitle

$host.UI.RawUI.ReadKey()

$host.UI.RawUI.FlushInputBuffer()

$buffer_cell = New-Object -TypeName System.Management.Automation.Host.BufferCell -ArgumentList "Z", ([System.ConsoleColor]::Red), ([System.ConsoleColor]::Green), ([System.Management.Automation.Host.BufferCellType]::Complete)
$rectangle = New-Object -TypeName System.Management.Automation.Host.Rectangle -ArgumentList 1, 2, 3, 4
$host.UI.RawUI.SetBufferContents($rectangle, $buffer_cell)

$coordinates = New-Object -TypeName System.Management.Automation.Host.Coordinates -ArgumentList 15, 15

$buffer_cell1_1 = New-Object -TypeName System.Management.Automation.Host.BufferCell -ArgumentList "A", ([System.ConsoleColor]::Black), ([System.ConsoleColor]::White), ([System.Management.Automation.Host.BufferCellType]::Leading)
$buffer_cell1_2 = New-Object -TypeName System.Management.Automation.Host.BufferCell -ArgumentList "B", ([System.ConsoleColor]::Black), ([System.ConsoleColor]::White), ([System.Management.Automation.Host.BufferCellType]::Trailing)
$buffer_cell2_1 = New-Object -TypeName System.Management.Automation.Host.BufferCell -ArgumentList "C", ([System.ConsoleColor]::Black), ([System.ConsoleColor]::White), ([System.Management.Automation.Host.BufferCellType]::Leading)
$buffer_cell2_2 = New-Object -TypeName System.Management.Automation.Host.BufferCell -ArgumentList "D", ([System.ConsoleColor]::Black), ([System.ConsoleColor]::White), ([System.Management.Automation.Host.BufferCellType]::Trailing)

$cells = New-Object -TypeName "System.Management.Automation.Host.BufferCell[,]" -ArgumentList 2,2
$cells[0,0] = $buffer_cell1_1
$cells[0,1] = $buffer_cell1_2
$cells[1,1] = $buffer_cell2_2
$cells[1,0] = $buffer_cell2_1
$host.UI.RawUI.SetBufferContents($coordinates, $cells)

$host.UI.RawUI.ScrollBufferContents($rectangle, $coordinates, $rectangle, $buffer_cell)''')
            actual = ps.invoke()

        assert len(actual) == 17

        assert str(actual[0]) == "White"
        assert str(actual[1]) == "Green"
        assert set_foreground_color.call_count == 1
        assert isinstance(set_foreground_color.call_args[0][0], RunspacePool)
        assert isinstance(set_foreground_color.call_args[0][1], PowerShell)
        assert set_foreground_color.call_args[0][2] == Color.GREEN

        assert str(actual[2]) == "Blue"
        assert str(actual[3]) == "Red"
        assert set_background_color.call_count == 1
        assert isinstance(set_background_color.call_args[0][0], RunspacePool)
        assert isinstance(set_background_color.call_args[0][1], PowerShell)
        assert set_background_color.call_args[0][2] == Color.RED

        assert str(actual[4]) == "1,2"
        assert str(actual[5]) == "11,12"
        assert set_cursor_position.call_count == 1
        assert isinstance(set_cursor_position.call_args[0][0], RunspacePool)
        assert isinstance(set_cursor_position.call_args[0][1], PowerShell)
        assert set_cursor_position.call_args[0][2].extended_properties['x'] \
            == 11
        assert set_cursor_position.call_args[0][2].extended_properties['y'] \
            == 12

        assert str(actual[6]) == "3,4"
        assert str(actual[7]) == "13,14"
        assert set_window_position.call_count == 1
        assert isinstance(set_window_position.call_args[0][0], RunspacePool)
        assert isinstance(set_window_position.call_args[0][1], PowerShell)
        assert set_window_position.call_args[0][2].extended_properties['x'] \
            == 13
        assert set_window_position.call_args[0][2].extended_properties['y'] \
            == 14

        assert actual[8] == 50
        assert actual[9] == 25
        assert set_cursor_size.call_count == 1
        assert isinstance(set_cursor_size.call_args[0][0], RunspacePool)
        assert isinstance(set_cursor_size.call_args[0][1], PowerShell)
        assert set_cursor_size.call_args[0][2] == 25

        assert str(actual[10]) == "80,80"
        assert str(actual[11]) == "8,9"
        assert set_buffer_size.call_count == 1
        assert isinstance(set_buffer_size.call_args[0][0], RunspacePool)
        assert isinstance(set_buffer_size.call_args[0][1], PowerShell)
        assert isinstance(set_buffer_size.call_args[0][2],
                          GenericComplexObject)
        assert set_buffer_size.call_args[0][2].extended_properties['width'] \
            == 8
        assert set_buffer_size.call_args[0][2].extended_properties['height'] \
            == 9

        assert str(actual[12]) == "80,80"
        assert str(actual[13]) == "8,9"
        assert set_window_size.call_count == 1
        assert isinstance(set_window_size.call_args[0][0], RunspacePool)
        assert isinstance(set_window_size.call_args[0][1], PowerShell)
        assert isinstance(set_window_size.call_args[0][2],
                          GenericComplexObject)
        assert set_window_size.call_args[0][2].extended_properties['width'] \
            == 8
        assert set_window_size.call_args[0][2].extended_properties['height'] \
            == 9

        assert actual[14] == "pypsrp window"
        assert actual[15] == "New Window Title"
        assert set_window_title.call_count == 1
        assert isinstance(set_window_title.call_args[0][0], RunspacePool)
        assert isinstance(set_window_title.call_args[0][1], PowerShell)
        assert set_window_title.call_args[0][2] == "New Window Title"

        assert str(actual[16]) == "65,a,CapsLockOn,True"
        assert isinstance(actual[16], KeyInfoDotNet)
        assert read_key.call_count == 1
        assert isinstance(read_key.call_args[0][0], RunspacePool)
        assert isinstance(read_key.call_args[0][1], PowerShell)
        assert read_key.call_args[0][2] == 4

        assert flush_input.call_count == 1
        assert isinstance(flush_input.call_args[0][0], RunspacePool)
        assert isinstance(flush_input.call_args[0][1], PowerShell)

        assert set_buffer1.call_count == 1
        assert isinstance(set_buffer1.call_args[0][0], RunspacePool)
        assert isinstance(set_buffer1.call_args[0][1], PowerShell)
        assert isinstance(set_buffer1.call_args[0][2], GenericComplexObject)
        assert set_buffer1.call_args[0][2].extended_properties['left'] == 1
        assert set_buffer1.call_args[0][2].extended_properties['top'] == 2
        assert set_buffer1.call_args[0][2].extended_properties['right'] == 3
        assert set_buffer1.call_args[0][2].extended_properties['bottom'] == 4
        fill = set_buffer1.call_args[0][3]
        assert isinstance(fill, GenericComplexObject)
        assert fill.extended_properties['character'] == "Z"
        assert fill.extended_properties['foregroundColor'] == 12
        assert fill.extended_properties['backgroundColor'] == 10
        assert fill.extended_properties['bufferCellType'] == 0

        assert set_buffer2.call_count == 1
        assert isinstance(set_buffer2.call_args[0][0], RunspacePool)
        assert isinstance(set_buffer2.call_args[0][1], PowerShell)
        assert isinstance(set_buffer2.call_args[0][2], GenericComplexObject)
        assert set_buffer2.call_args[0][2].extended_properties['x'] == 15
        assert set_buffer2.call_args[0][2].extended_properties['y'] == 15
        assert isinstance(set_buffer2.call_args[0][3], GenericComplexObject)
        assert set_buffer2.call_args[0][3].extended_properties['mal'] == [2, 2]
        set_contents = set_buffer2.call_args[0][3].extended_properties['mae']
        assert len(set_contents) == 4
        assert set_contents[0].extended_properties['character'] == "A"
        assert set_contents[0].extended_properties['foregroundColor'] == 0
        assert set_contents[0].extended_properties['backgroundColor'] == 15
        assert set_contents[0].extended_properties['bufferCellType'] == 1
        assert set_contents[1].extended_properties['character'] == "B"
        assert set_contents[1].extended_properties['foregroundColor'] == 0
        assert set_contents[1].extended_properties['backgroundColor'] == 15
        assert set_contents[1].extended_properties['bufferCellType'] == 2
        assert set_contents[2].extended_properties['character'] == "C"
        assert set_contents[2].extended_properties['foregroundColor'] == 0
        assert set_contents[2].extended_properties['backgroundColor'] == 15
        assert set_contents[2].extended_properties['bufferCellType'] == 1
        assert set_contents[3].extended_properties['character'] == "D"
        assert set_contents[3].extended_properties['foregroundColor'] == 0
        assert set_contents[3].extended_properties['backgroundColor'] == 15
        assert set_contents[3].extended_properties['bufferCellType'] == 2

        assert scroll_buffer.call_count == 1
        assert isinstance(scroll_buffer.call_args[0][0], RunspacePool)
        assert isinstance(scroll_buffer.call_args[0][1], PowerShell)
        source = scroll_buffer.call_args[0][2]
        assert isinstance(source, GenericComplexObject)
        assert source.extended_properties['left'] == 1
        assert source.extended_properties['top'] == 2
        assert source.extended_properties['right'] == 3
        assert source.extended_properties['bottom'] == 4
        destination = scroll_buffer.call_args[0][3]
        assert isinstance(destination, GenericComplexObject)
        assert destination.extended_properties['x'] == 15
        assert destination.extended_properties['y'] == 15
        clip = scroll_buffer.call_args[0][4]
        assert isinstance(clip, GenericComplexObject)
        assert clip.extended_properties['left'] == 1
        assert clip.extended_properties['top'] == 2
        assert clip.extended_properties['right'] == 3
        assert clip.extended_properties['bottom'] == 4
        fill = scroll_buffer.call_args[0][5]
        assert isinstance(fill, GenericComplexObject)
        assert fill.extended_properties['character'] == "Z"
        assert fill.extended_properties['foregroundColor'] == 12
        assert fill.extended_properties['backgroundColor'] == 10
        assert fill.extended_properties['bufferCellType'] == 0

    def test_ps_host_raw_ui_method(self):
        window_title = "pypsrp window"
        cursor_size = 50
        foreground_color = Color(value=Color.WHITE)
        background_color = Color(value=Color.BLUE)
        cursor_position = Coordinates(x=1, y=2)
        window_position = Coordinates(x=3, y=4)
        buffer_size = Size(width=80, height=80)
        max_physical_window_size = Size(width=80, height=80)
        max_window_size = Size(width=80, height=80)
        window_size = Size(width=80, height=80)

        raw_ui = PSHostRawUserInterface(
            window_title, cursor_size, foreground_color, background_color,
            cursor_position, window_position, buffer_size,
            max_physical_window_size, max_window_size, window_size
        )

        actual_foreground_color = raw_ui.GetForegroundColor(None, None)
        assert actual_foreground_color == foreground_color
        raw_ui.SetForegroundColor(None, None, Color.MAGENTA)
        assert isinstance(raw_ui.foreground_color, Color)
        assert raw_ui.foreground_color.value == Color.MAGENTA

        actual_background_color = raw_ui.GetBackgroundColor(None, None)
        assert actual_background_color == background_color
        raw_ui.SetBackgroundColor(None, None, Color.DARK_MAGENTA)
        assert isinstance(raw_ui.background_color, Color)
        assert raw_ui.background_color.value == Color.DARK_MAGENTA

        coordinates = GenericComplexObject()
        coordinates.extended_properties['x'] = 11
        coordinates.extended_properties['y'] = 12

        actual_cursor_position = raw_ui.GetCursorPosition(None, None)
        assert actual_cursor_position == cursor_position
        raw_ui.SetCursorPosition(None, None, coordinates)
        assert isinstance(raw_ui.cursor_position, Coordinates)
        assert raw_ui.cursor_position.x == 11
        assert raw_ui.cursor_position.y == 12

        actual_window_position = raw_ui.GetWindowPosition(None, None)
        assert actual_window_position == window_position
        raw_ui.SetWindowPosition(None, None, coordinates)
        assert isinstance(raw_ui.window_position, Coordinates)
        assert raw_ui.window_position.x == 11
        assert raw_ui.window_position.y == 12

        actual_cursor_size = raw_ui.GetCursorSize(None, None)
        assert actual_cursor_size == cursor_size
        raw_ui.SetCursorSize(None, None, 25)
        assert raw_ui.cursor_size == 25

        size = GenericComplexObject()
        size.extended_properties['height'] = 160
        size.extended_properties['width'] = 160

        actual_buffer_size = raw_ui.GetBufferSize(None, None)
        assert actual_buffer_size == buffer_size
        raw_ui.SetBufferSize(None, None, size)
        assert isinstance(raw_ui.buffer_size, Size)
        assert raw_ui.buffer_size.height == 160
        assert raw_ui.buffer_size.width == 160

        actual_window_size = raw_ui.GetWindowSize(None, None)
        assert actual_window_size == window_size
        raw_ui.SetWindowSize(None, None, size)
        assert isinstance(raw_ui.window_size, Size)
        assert raw_ui.window_size.height == 160
        assert raw_ui.window_size.width == 160

        actual_window_title = raw_ui.GetWindowTitle(None, None)
        assert actual_window_title == window_title
        raw_ui.SetWindowTitle(None, None, "new title")
        assert raw_ui.window_title == "new title"

        actual_max_window_size = raw_ui.GetMaxWindowSize(None, None)
        assert actual_max_window_size == max_window_size

        actual_physical_window_size = raw_ui.GetMaxPhysicalWindowSize(None,
                                                                      None)
        assert actual_physical_window_size == max_physical_window_size

        raw_ui.key_available = True
        actual_key_available = raw_ui.GetKeyAvailable(None, None)
        assert actual_key_available is True

        raw_ui.FlushInputBuffer(None, None)

        rectangle = GenericComplexObject()
        rectangle.extended_properties['left'] = 1
        rectangle.extended_properties['top'] = 2
        rectangle.extended_properties['right'] = 3
        rectangle.extended_properties['bottom'] = 4

        fill = GenericComplexObject()
        fill.extended_properties['character'] = "A"
        fill.extended_properties['foregroundColor'] = 12
        fill.extended_properties['backgroundColor'] = 10
        fill.extended_properties['bufferCellType'] = 0

        contents = GenericComplexObject()
        contents.extended_properties['mal'] = [2, 2]
        contents.extended_properties['mae'] = [[fill, fill], [fill, fill]]

        raw_ui.SetBufferContents1(None, None, rectangle, fill)
        raw_ui.SetBufferContents2(None, None, coordinates, contents)
        raw_ui.ScrollBufferContents(None, None, rectangle, coordinates,
                                    rectangle, fill)

    def test_ps_host_raw_ui_not_implemented(self):
        raw_ui = PSHostRawUserInterface(None, None, None, None, None, None,
                                        None, None, None, None)

        with pytest.raises(NotImplementedError):
            raw_ui.ReadKey(None, None)

        with pytest.raises(NotImplementedError):
            raw_ui.GetBufferContents(None, None, None)
