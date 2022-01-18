import os

import pytest

from pypsrp.complex_objects import ObjectMeta
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.shell import Process, SignalCode, WinRS
from pypsrp.wsman import WSMan


@pytest.fixture(scope="function")
def functional_transports():
    """
    This runs the same test over multiple auth providers and on SSL/Without.
    It requires a specific host configuration of the target endpoint and for
    this config to be defined by the following environment varaibles;

    PYPSRP_RUN_INTEGRATION: if set to anything then these tests will run
    PYPSRP_SERVER: The hostname or IP of the endpoint to test on
    PYPSRP_USERNAME: The username that is an admin on the remote host
    PYPSRP_PASSWORD: THe password for the username
    PYPSRP_CERT_DIR: The directory where the cert.pem and cert_key.pem is
        located for certificate auth. If not defined then certificate auth will
        not be tested

    Here is the test matrix that is run on each test
        http with negotiate
        http with ntlm
        http with credssp
        https with negotiate
        https with ntlm
        https with credssp
        https with basic
        https with cert (depends on env var)

    Each http test has message encryption enabled while the https tests do not.
    """
    run = os.environ.get("PYPSRP_RUN_INTEGRATION", None)
    if run is None:
        pytest.skip("Skipping CI functional tests because PYPSRP_RUN_INTEGRATION has not been set")

    username = os.environ["PYPSRP_USERNAME"]
    password = os.environ["PYPSRP_PASSWORD"]
    server = os.environ["PYPSRP_SERVER"]
    cert_dir = os.environ.get("PYPSRP_CERT_DIR", None)
    http_port = int(os.environ.get("PYPSRP_HTTP_PORT", 5985))
    https_port = int(os.environ.get("PYPSRP_HTTPS_PORT", 5986))

    # can't really test kerberos in CI so it is missing from this list
    auths = ["negotiate", "ntlm", "credssp"]
    auths_ssl = ["basic"]
    if cert_dir is not None:
        auths_ssl.append("certificate")
        cert_key_pem = os.path.join(cert_dir, "cert_key.pem")
        cert_pem = os.path.join(cert_dir, "cert.pem")
    else:
        cert_key_pem = None
        cert_pem = None
    auths_ssl.extend(auths)

    wsmans = []
    for auth in auths:
        wsman = WSMan(server, username=username, password=password, ssl=False, auth=auth, port=http_port)
        wsmans.append(wsman)

    for auth in auths_ssl:
        wsman = WSMan(
            server,
            username=username,
            password=password,
            ssl=True,
            auth=auth,
            cert_validation=False,
            certificate_key_pem=cert_key_pem,
            certificate_pem=cert_pem,
            port=https_port,
        )
        wsmans.append(wsman)
    yield wsmans


class TestPowerShellFunctional(object):
    def test_winrs(self, functional_transports):
        for wsman in functional_transports:
            with wsman, WinRS(wsman) as shell:
                process = Process(shell, "echo", ["hi"])
                process.invoke()
                process.signal(SignalCode.CTRL_C)
                assert process.rc == 0
                assert process.stdout == b"hi\r\n"
                assert process.stderr == b""

    def test_psrp(self, functional_transports):
        for wsman in functional_transports:
            with wsman, RunspacePool(wsman) as pool:
                pool.exchange_keys()
                ps = PowerShell(pool)
                ps.add_cmdlet("Get-Item").add_parameter("Path", "C:\\Windows")
                ps.add_statement()

                sec_string = pool.serialize(u"super secret", ObjectMeta("SS"))
                ps.add_cmdlet("Set-Variable")
                ps.add_parameter("Name", "password")
                ps.add_parameter("Value", sec_string)

                ps.add_statement().add_script(
                    "[System.Runtime.InteropServices.marshal]"
                    "::PtrToStringAuto([System.Runtime.InteropServices.marshal]"
                    "::SecureStringToBSTR($password))"
                )
                ps.add_statement().add_cmdlet("ConvertTo-SecureString")
                ps.add_parameter("String", "host secret")
                ps.add_parameter("AsPlainText")
                ps.add_parameter("Force")

                large_string = "hello world " * 3000
                ps.add_statement()
                ps.add_script("$VerbosePreference = 'Continue'; Write-Verbose '%s'" % large_string)

                actual = ps.invoke()

            assert ps.had_errors is False
            assert len(actual) == 3
            assert str(actual[0]) == "C:\\Windows"
            assert actual[1] == u"super secret"
            assert actual[2] == u"host secret"
            assert str(ps.streams.verbose[0]) == large_string

    def test_psrp_jea(self, functional_transports):
        for wsman in functional_transports:
            with wsman, RunspacePool(wsman, configuration_name="JEARole") as pool:
                ps = PowerShell(pool)
                wsman_path = "WSMan:\\localhost\\Service\\AllowUnencrypted"
                ps.add_cmdlet("Get-Item").add_parameter("Path", wsman_path)
                ps.add_statement()
                ps.add_cmdlet("Set-Item").add_parameters({"Path": wsman_path, "Value": "True"})
                actual = ps.invoke()

            assert ps.had_errors is True
            assert len(actual) == 1
            assert actual[0].property_sets[0].adapted_properties["Value"] == "false"
            assert (
                str(ps.streams.error[0]) == "The term 'Set-Item' is not recognized as the name of a "
                "cmdlet, function, script file, or operable program. Check "
                "the spelling of the name, or if a path was included, "
                "verify that the path is correct and try again."
            )
