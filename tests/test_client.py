import hashlib
import os
import tempfile

import pytest

from pypsrp.client import Client
from pypsrp.exceptions import WinRMError
from pypsrp.powershell import PSDataStreams
from pypsrp.wsman import WSMan
from pypsrp._utils import to_unicode

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


class TestClient(object):

    def _get_client(self, wsman):
        # the connection object was already created as part of test fixture
        # we need to apply it to the Client object and set the values so the
        # test will work with existing responses
        client = Client("")
        client.wsman = wsman
        return client

    @pytest.mark.parametrize('wsman_conn',
                             [[False, 'test_client_copy_file']], indirect=True)
    def test_client_copy_file(self, wsman_conn):
        client = self._get_client(wsman_conn)
        test_string = b"abcdefghijklmnopqrstuvwxyz"

        temp_file, path = tempfile.mkstemp()
        try:
            os.write(temp_file, test_string)
            actual = client.copy(path, "test_file")

            # run it a 2nd time to ensure it doesn't fail
            actual = client.copy(path, actual)
        finally:
            os.close(temp_file)
            os.remove(path)

        try:
            # verify the returned object is the full path
            assert actual.startswith("C:\\Users\\")

            actual_content = client.execute_cmd(
                "powershell.exe Get-Content %s" % actual
            )[0].strip()
            assert actual_content == to_unicode(test_string)
        finally:
            client.execute_cmd("powershell Remove-Item -Path '%s'" % actual)

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_copy_file_empty']],
                             indirect=True)
    def test_client_copy_file_empty(self, wsman_conn):
        client = self._get_client(wsman_conn)

        temp_file, path = tempfile.mkstemp()
        try:
            actual = client.copy(path, "test_file")
        finally:
            os.close(temp_file)
            os.remove(path)

        try:
            # verify the returned object is the full path
            assert actual.startswith("C:\\Users\\")

            actual_content = client.execute_cmd(
                "powershell.exe Get-Content %s" % actual
            )[0].strip()
            assert actual_content == ""
        finally:
            client.execute_cmd("powershell Remove-Item -Path '%s'" % actual)

    @pytest.mark.parametrize('wsman_conn',
                             # checks as to whether the correct number of calls
                             # were sent and the remote requirements are too
                             # variable to trust reliable
                             [[False, 'test_client_copy_file_double_payload']],
                             indirect=True)
    def test_client_copy_file_double_payload(self, wsman_conn):
        client = self._get_client(wsman_conn)
        client.wsman.max_payload_size = 113955

        # data sent in 3 packets (2 * data + hash)
        test_string = b"abcdefghijklmnopqrstuvwxyz" * 5000

        temp_file, path = tempfile.mkstemp()
        try:
            os.write(temp_file, test_string)
            actual = client.copy(path, "test_file")
        finally:
            os.close(temp_file)
            os.remove(path)

        # verify the returned object is the full path
        assert actual == u"C:\\Users\\vagrant\\test_file"

    @pytest.mark.parametrize('wsman_conn',
                             # checks as to whether the correct number of calls
                             # were sent and the remote requirements are too
                             # variable to trust reliable
                             [[False, 'test_client_copy_file_quad_payload']],
                             indirect=True)
    def test_client_copy_file_quad_payload(self, wsman_conn, monkeypatch):
        # in a mocked context the calculated size differs on a few variables
        # we will mock out that call and return the ones used in our existing
        # responses
        mock_calc = MagicMock()
        mock_calc.side_effect = [113955, 382750]
        monkeypatch.setattr(WSMan, "_calc_envelope_size", mock_calc)

        client = self._get_client(wsman_conn)

        # data sent in 3 packets (get size + data + hash)
        test_string = b"abcdefghijklmnopqrstuvwxyz" * 10000

        temp_file, path = tempfile.mkstemp()
        try:
            os.write(temp_file, test_string)
            actual = client.copy(path, "test_file")
        finally:
            os.close(temp_file)
            os.remove(path)

        # verify the returned object is the full path
        assert actual == u"C:\\Users\\vagrant\\test_file"

    @pytest.mark.parametrize('wsman_conn',
                             # checks as to whether the correct number of calls
                             # were sent and the remote requirements are too
                             # variable to trust reliable
                             [[False, 'test_client_copy_file_really_large']],
                             indirect=True)
    def test_client_copy_file_really_large(self, wsman_conn, monkeypatch):
        # in a mocked context the calculated size differs on a few variables
        # we will mock out that call and return the ones used in our existing
        # responses
        mock_calc = MagicMock()
        mock_calc.side_effect = [113955, 382750]
        monkeypatch.setattr(WSMan, "_calc_envelope_size", mock_calc)

        client = self._get_client(wsman_conn)

        # data sent in 4 packets (get size + 2 * data + hash)
        test_string = b"abcdefghijklmnopqrstuvwxyz" * 20000

        temp_file, path = tempfile.mkstemp()
        try:
            os.write(temp_file, test_string)
            actual = client.copy(path, "test_file")
        finally:
            os.close(temp_file)
            os.remove(path)

        # verify the returned object is the full path
        assert actual == u"C:\\Users\\vagrant\\test_file"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_copy_file_failure']],
                             indirect=True)
    def test_client_copy_file_failure(self, wsman_conn, monkeypatch):
        # set to a hash that is not the actual to verify the script will
        # fail in a hash mismatch scenario
        mock_hash = MagicMock()
        mock_hash.return_value.hexdigest.return_value = \
            "c3499c2729730a7f807efb8676a92dcb6f8a3f8f"
        monkeypatch.setattr(hashlib, "sha1", mock_hash)

        client = self._get_client(wsman_conn)
        test_string = b"abcdefghijklmnopqrstuvwxyz"

        temp_file, path = tempfile.mkstemp()
        try:
            os.write(temp_file, test_string)
            with pytest.raises(WinRMError) as err:
                actual = client.copy(path, "test_file")
            expected_err = \
                "Failed to copy file: Transport failure, hash mistmatch\r\n" \
                "Actual: 32d10c7b8cf96570ca04ce37f2a19d84240d3a89\r\n" \
                "Expected: c3499c2729730a7f807efb8676a92dcb6f8a3f8f"
            assert expected_err in str(err.value)
        finally:
            os.close(temp_file)
            os.remove(path)

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_execute_cmd']],
                             indirect=True)
    def test_client_execute_cmd(self, wsman_conn):
        client = self._get_client(wsman_conn)
        actual = client.execute_cmd("dir")
        actual_args = client.execute_cmd("echo abc")

        assert u"Volume in drive C" in actual[0]
        assert actual[1] == u""
        assert actual[2] == 0

        assert actual_args[0] == u"abc\r\n"
        assert actual_args[1] == u""
        assert actual_args[2] == 0

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_execute_ps']], indirect=True)
    def test_client_execute_ps(self, wsman_conn):
        client = self._get_client(wsman_conn)

        expected_stdout = u'winrm\nRunning\n\nStatus   Name               ' \
                          u'DisplayName                           \n------' \
                          u'   ----               -----------             ' \
                          u'              \nRunning  winrm              Wi' \
                          u'ndows Remote Management (WS-Manag...\n\n'
        actual = client.execute_ps("$serv = Get-Service -Name winrm; "
                                   "$serv.Name; $serv.Status; $serv")
        assert actual[0] == expected_stdout
        assert isinstance(actual[1], PSDataStreams)
        assert actual[2] is False

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_execute_ps_failure']],
                             indirect=True)
    def test_client_execute_ps_failure(self, wsman_conn):
        client = self._get_client(wsman_conn)

        actual = client.execute_ps("Get-ServiceTypo -Name winrm")

        assert actual[0] == u""
        assert len(actual[1].error) == 1
        assert str(actual[1].error[0]) == \
            "The term 'Get-ServiceTypo' is not recognized as the name of a " \
            "cmdlet, function, script file, or operable program. Check the " \
            "spelling of the name, or if a path was included, verify that " \
            "the path is correct and try again."
        assert actual[2] is True

    @pytest.mark.parametrize('wsman_conn',
                             # means we don't need to create files on the
                             # remote side
                             [[False, 'test_client_fetch_file']], indirect=True)
    def test_client_fetch_file(self, wsman_conn, monkeypatch):
        # in a mocked context the calculated size differs on a few variables
        # we will mock out that call and return the ones used in our existing
        # responses
        mock_calc = MagicMock()
        mock_calc.side_effect = [113955, 382750]
        monkeypatch.setattr(WSMan, "_calc_envelope_size", mock_calc)

        client = self._get_client(wsman_conn)

        # file was created with
        # Set-Content -Path C:\temp\file.txt -Value ("abc`r`n" * 50000)

        temp_file, path = tempfile.mkstemp()
        os.close(temp_file)
        os.remove(path)
        try:
            client.fetch("C:\\temp\\file.txt", path)
            expected_hash = b"\x70\xe3\xbe\xa8\xcd\xb0\xd0\xc8" \
                            b"\x83\xbc\xcf\xf5\x22\x89\x33\xd9" \
                            b"\x33\xb8\x8a\x80"
            hash = hashlib.sha1()
            with open(path, "rb") as temp_file:
                while True:
                    data = temp_file.read(65536)
                    if not data:
                        break
                    hash.update(data)
            actual_hash = hash.digest()
            assert actual_hash == expected_hash
        finally:
            if os.path.exists(path):
                os.remove(path)

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_fetch_file_fail_dir']],
                             indirect=True)
    def test_client_fetch_file_fail_dir(self, wsman_conn, monkeypatch):
        # in a mocked context the calculated size differs on a few variables
        # we will mock out that call and return the ones used in our existing
        # responses
        mock_calc = MagicMock()
        mock_calc.side_effect = [113955, 382750]
        monkeypatch.setattr(WSMan, "_calc_envelope_size", mock_calc)

        client = self._get_client(wsman_conn)
        with pytest.raises(WinRMError) as err:
            client.fetch("C:\\Windows", "")
        assert str(err.value) == \
            "Failed to fetch file C:\\Windows: The path at 'C:\\Windows' is " \
            "a directory, src must be a file"

    @pytest.mark.parametrize('wsman_conn',
                             [[True, 'test_client_fetch_file_fail_missing']],
                             indirect=True)
    def test_client_fetch_file_fail_missing(self, wsman_conn,
                                            monkeypatch):
        # in a mocked context the calculated size differs on a few variables
        # we will mock out that call and return the ones used in our existing
        # responses
        mock_calc = MagicMock()
        mock_calc.side_effect = [113955, 382750]
        monkeypatch.setattr(WSMan, "_calc_envelope_size", mock_calc)

        client = self._get_client(wsman_conn)
        with pytest.raises(WinRMError) as err:
            client.fetch("C:\\fakefile.txt", "")
        assert str(err.value) == \
            "Failed to fetch file C:\\fakefile.txt: The path at " \
            "'C:\\fakefile.txt' does not exist"

    @pytest.mark.parametrize('wsman_conn',
                             # use existing responses so I don't need to create
                             # the file
                             [[False, 'test_client_fetch_file_hash_mismatch']],
                             indirect=True)
    def test_client_fetch_file_hash_mismatch(self, wsman_conn,
                                             monkeypatch):
        # set to a hash that is not the actual to verify the script will
        # fail in a hash mismatch scenario
        mock_hash = MagicMock()
        mock_hash.return_value.hexdigest.return_value = \
            "c3499c2729730a7f807efb8676a92dcb6f8a3f8f"
        monkeypatch.setattr(hashlib, "sha1", mock_hash)

        # file was created with
        # Set-Content -Path C:\temp\file.txt -Value ("abc`r`n" * 5)
        client = self._get_client(wsman_conn)
        with pytest.raises(WinRMError) as err:
            client.fetch("C:\\temp\\file.txt", "")
        assert str(err.value) == \
            "Failed to fetch file C:\\temp\\file.txt, hash mismatch\n" \
            "Source: eec729d9a0fa275513bc44a4cb8d4ee973b81e1a\n" \
            "Fetched: c3499c2729730a7f807efb8676a92dcb6f8a3f8f"
