# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import division

import base64
import hashlib
import os
import shutil
import sys
import tempfile

import logging

from pypsrp.exceptions import WinRMError
from pypsrp.powershell import DEFAULT_CONFIGURATION_NAME, PowerShell, RunspacePool
from pypsrp.serializer import Serializer
from pypsrp.shell import Process, SignalCode, WinRS
from pypsrp.wsman import WSMan
from pypsrp._utils import to_bytes, to_unicode

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # ElementTree in Python 2.6 does not support namespaces so we need to use
    # lxml instead for this version
    from lxml import etree as ET
else:  # pragma: no cover
    import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)


class Client(object):

    def __init__(self, server, **kwargs):
        """
        Creates a client object used to do the following
            spawn new cmd command/process
            spawn new PowerShell Runspace Pool/Pipeline
            copy a file from localhost to the remote Windows host
            fetch a file from the remote Windows host to localhost

        This is just an easy to use layer on top of the objects WinRS and
        RunspacePool/PowerShell. It trades flexibility in favour of simplicity.

        If your use case needs some of that flexibility you can use these
        functions as a reference implementation for your own functions.

        :param server: The server/host to connect to
        :param kwargs: The various WSMan args to control the transport
            mechanism, see pypsrp.wsman.WSMan for these args
        """
        self.wsman = WSMan(server, **kwargs)

    def copy(self, src, dest, configuration_name=DEFAULT_CONFIGURATION_NAME):
        """
        Copies a single file from the current host to the remote Windows host.
        This can be quite slow when it comes to large files due to the
        limitations of WinRM but it is designed to be as fast as it can be.
        During the copy process, the bytes will be stored in a temporary file
        before being copied.

        When copying it will replace the file at dest if one already exists. It
        also will verify the checksum of the copied file is the same as the
        actual file locally before copying the file to the path at dest.

        :param src: The path to the local file
        :param dest: The path to the destionation file on the Windows host
        :param configuration_name: The PowerShell configuration endpoint to
            use when copying the file.
        :return: The absolute path of the file on the Windows host
        """
        def read_buffer(b_path, buffer_size):
            offset = 0
            sha1 = hashlib.sha1()

            with open(b_path, 'rb') as src_file:
                for data in iter((lambda: src_file.read(buffer_size)), b""):
                    log.debug("Reading data of file at offset=%d with size=%d"
                              % (offset, buffer_size))
                    offset += len(data)
                    sha1.update(data)
                    b64_data = base64.b64encode(data) + b"\r\n"

                    yield to_unicode(b64_data)

                # the file was empty, return empty buffer
                if offset == 0:
                    yield u""

            # the last input is the actual file hash used to verify the
            # transfer was ok
            actual_hash = b"\x00\xffHash: " + to_bytes(sha1.hexdigest())
            yield to_unicode(base64.b64encode(actual_hash))

        src = os.path.expanduser(os.path.expandvars(src))
        b_src = to_bytes(src)
        src_size = os.path.getsize(b_src)
        log.info("Copying '%s' to '%s' with a total size of %d"
                 % (src, dest, src_size))

        # MaximumAllowedMemory is required to be set to so we can send input data that exceeds the limit on a PS
        # Runspace. We use reflection to access/set this property as it is not accessible publicly. This is not ideal
        # but works on all PowerShell versions I've tested with. We originally used WinRS to send the raw bytes to the
        # host but this falls flat if someone is using a custom PS configuration name.
        command = u'''begin {
    $ErrorActionPreference = "Stop"
    $path = [System.IO.Path]::GetTempFileName()
    $fd = [System.IO.File]::Create($path)
    $algo = [System.Security.Cryptography.SHA1CryptoServiceProvider]::Create()
    $bytes = @()
    $expected_hash = ""

    $binding_flags = [System.Reflection.BindingFlags]'NonPublic, Instance'
    Function Get-Property {
        Param (
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [System.Object]
            $Object,

            [Parameter(Mandatory=$true, Position=1)]
            [System.String]
            $Name
        )

        $Object.GetType().GetProperty($Name, $binding_flags).GetValue($Object, $null)
    }

    Function Set-Property {
        Param (
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [System.Object]
            $Object,

            [Parameter(Mandatory=$true, Position=1)]
            [System.String]
            $Name,

            [Parameter(Mandatory=$true, Position=2)]
            [AllowNull()]
            [System.Object]
            $Value
        )

        $Object.GetType().GetProperty($Name, $binding_flags).SetValue($Object, $Value)
    }

    Function Get-Field {
        Param (
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [System.Object]
            $Object,

            [Parameter(Mandatory=$true, Position=1)]
            [System.String]
            $Name
        )

        $Object.GetType().GetField($Name, $binding_flags).GetValue($Object)
    }

    $dc = $Host | Get-Property 'ExternalHost' | `
        Get-Field '_transportManager' | `
        Get-Property 'Fragmentor' | `
        Get-Property 'DeserializationContext' | `
        Set-Property 'MaximumAllowedMemory' $null
} process {
    $base64_string = $input

    $bytes = [System.Convert]::FromBase64String($base64_string)
    if ($bytes.Count -eq 48 -and $bytes[0] -eq 0 -and $bytes[1] -eq 255) {
        $hash_bytes = $bytes[-40..-1]
        $expected_hash = [System.Text.Encoding]::UTF8.GetString($hash_bytes)
    } else {
        $algo.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0) > $null
        $fd.Write($bytes, 0, $bytes.Length)
    }
} end {
    $output_path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('%s')
    $dest = New-Object -TypeName System.IO.FileInfo -ArgumentList $output_path
    $fd.Close()

    try {
        $algo.TransformFinalBlock($bytes, 0, 0) > $null
        $actual_hash = [System.BitConverter]::ToString($algo.Hash)
        $actual_hash = $actual_hash.Replace("-", "").ToLowerInvariant()

        if ($actual_hash -ne $expected_hash) {
            $msg = "Transport failure, hash mistmatch"
            $msg += "`r`nActual: $actual_hash"
            $msg += "`r`nExpected: $expected_hash"
            throw $msg
        }
        [System.IO.File]::Copy($path, $output_path, $true)
        $dest.FullName
    } finally {
        [System.IO.File]::Delete($path)
    }
}''' % to_unicode(dest)

        with RunspacePool(self.wsman, configuration_name=configuration_name) as pool:
            # Get the buffer size of each fragment to send, subtract. Adjust to size of the base64 encoded bytes. Also
            # subtract 82 for the fragment, message, and other header info that PSRP adds
            buffer_size = int((self.wsman.max_payload_size - 82) / 4 * 3)

            log.info("Creating file reader with a buffer size of %d" % buffer_size)
            read_gen = read_buffer(b_src, buffer_size)

            log.debug("Starting to send file data to remote process")
            powershell = PowerShell(pool)
            powershell.add_script(command)
            powershell.invoke(input=read_gen)
            log.debug("Finished sending file data to remote process")

        if powershell.had_errors:
            errors = powershell.streams.error
            error = "\n".join([str(err) for err in errors])
            raise WinRMError("Failed to copy file: %s" % error)

        output_file = to_unicode(powershell.output[0]).strip()
        log.info("Completed file transfer of '%s' to '%s'" % (src, output_file))
        return output_file

    def execute_cmd(self, command, encoding='437', environment=None):
        """
        Executes a command in a cmd shell and returns the stdout/stderr/rc of
        that process. This uses the raw WinRS layer and can be used to execute
        a traditional process.

        :param command: The command to execute
        :param encoding: The encoding of the output std buffers, this
            correlates to the codepage of the host and traditionally en-US
            is 437. This probably doesn't need to be modified unless you are
            running a different codepage on your host
        :param environment: A dictionary containing environment keys and
            values to set on the executing process.
        :return: A tuple of
            stdout: A unicode string of the stdout
            stderr: A unicode string of the stderr
            rc: The return code of the process

        Both stdout and stderr are returned from the server as a byte string,
        they are converted to a unicode string based on the encoding variable
        set
        """
        log.info("Executing cmd process '%s'" % command)
        with WinRS(self.wsman, environment=environment) as shell:
            process = Process(shell, command)
            process.invoke()
            process.signal(SignalCode.CTRL_C)

        return to_unicode(process.stdout, encoding), \
            to_unicode(process.stderr, encoding), process.rc

    def execute_ps(self, script, configuration_name=DEFAULT_CONFIGURATION_NAME,
                   environment=None):
        """
        Executes a PowerShell script in a PowerShell runspace pool. This uses
        the PSRP layer and is designed to run a PowerShell script and not a
        raw executable.

        Because this runs in a runspace, traditional concepts like stdout,
        stderr, rc's are no longer relevant. Instead there is a output,
        error/verbose/debug streams, and a boolean that indicates if the
        script execution came across an error. If you want the traditional
        stdout/stderr/rc, use execute_cmd instead.

        :param script: The PowerShell script to run
        :param configuration_name: The PowerShell configuration endpoint to
            use when executing the script.
        :param environment: A dictionary containing environment keys and
            values to set on the executing script.
        :return: A tuple of
            output: A unicode string of the output stream
            streams: pypsrp.powershell.PSDataStreams containing the other
                PowerShell streams
            had_errors: bool that indicates whether the script had errors
                during execution
        """
        log.info("Executing PowerShell script '%s'" % script)
        with RunspacePool(self.wsman, configuration_name=configuration_name) as pool:
            powershell = PowerShell(pool)

            if environment:
                for env_key, env_value in environment.items():
                    powershell.add_cmdlet('New-Item').add_parameters({
                        'Path': "env:",
                        'Name': env_key,
                        'Value': env_value,
                        'Force': True,
                    }).add_cmdlet('Out-Null').add_statement()

            # so the client executes a powershell script and doesn't need to
            # deal with complex PS objects, we run the script in
            # Invoke-Expression and convert the output to a string
            # if a user wants to get the raw complex objects then they should
            # use RunspacePool and PowerShell directly
            powershell.add_cmdlet("Invoke-Expression").add_parameter("Command",
                                                                     script)
            powershell.add_cmdlet("Out-String").add_parameter("Stream")
            powershell.invoke()

        return "\n".join(powershell.output), powershell.streams, \
               powershell.had_errors

    def fetch(self, src, dest, configuration_name=DEFAULT_CONFIGURATION_NAME):
        """
        Will fetch a single file from the remote Windows host and create a
        local copy. Like copy(), this can be slow when it comes to fetching
        large files due to the limitation of WinRM.

        This method will first store the file in a temporary location before
        creating or replacing the file at dest if the checksum is correct.

        :param src: The path to the file on the remote host to fetch
        :param dest: The path on the localhost host to store the file as
        :param configuration_name: The PowerShell configuration endpoint to
            use when fetching the file.
        """
        dest = os.path.expanduser(os.path.expandvars(dest))
        log.info("Fetching '%s' to '%s'" % (src, dest))

        self.wsman.update_max_payload_size()

        # Need to output as a base64 string as PS Runspaces will create an
        # individual byte objects for each byte in a byte array which has way
        # more overhead than a single base64 string.
        # I also wanted to output in chunks and have the local side process
        # the output in parallel for large files but it seems like the base64
        # stream is getting sent in one chunk when in a loop so scratch that
        # idea
        script = '''$ErrorActionPreference = 'Stop'
$src_path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('%s')
if (Test-Path -LiteralPath $src_path -PathType Container) {
    throw "The path at '$src_path' is a directory, src must be a file"
} elseif (-not (Test-Path -LiteralPath $src_path)) {
    throw "The path at '$src_path' does not exist"
}

$algo = [System.Security.Cryptography.SHA1CryptoServiceProvider]::Create()
$src = New-Object -TypeName System.IO.FileInfo -ArgumentList $src_path
$buffer_size = 4096
$offset = 0
$fs = $src.OpenRead()
$total_bytes = $fs.Length
$bytes_to_read = $total_bytes - $offset
try {
    while ($bytes_to_read -ne 0) {
        $bytes = New-Object -TypeName byte[] -ArgumentList $bytes_to_read
        $read = $fs.Read($bytes, $offset, $bytes_to_read)

        Write-Output -InputObject ([System.Convert]::ToBase64String($bytes))
        $bytes_to_read -= $read
        $offset += $read

        $algo.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0) > $null
    }
} finally {
    $fs.Dispose()
}

$algo.TransformFinalBlock($bytes, 0, 0) > $Null
$hash = [System.BitConverter]::ToString($algo.Hash)
$hash.Replace("-", "").ToLowerInvariant()''' % src

        with RunspacePool(self.wsman, configuration_name=configuration_name) as pool:
            powershell = PowerShell(pool)
            powershell.add_script(script)
            log.debug("Starting remote process to output file data")
            powershell.invoke()
            log.debug("Finished remote process to output file data")

            if powershell.had_errors:
                errors = powershell.streams.error
                error = "\n".join([str(err) for err in errors])
                raise WinRMError("Failed to fetch file %s: %s" % (src, error))
            expected_hash = powershell.output[-1]

            temp_file, path = tempfile.mkstemp()
            try:
                file_bytes = base64.b64decode(powershell.output[0])
                os.write(temp_file, file_bytes)

                sha1 = hashlib.sha1()
                sha1.update(file_bytes)
                actual_hash = sha1.hexdigest()

                log.debug("Remote Hash: %s, Local Hash: %s"
                          % (expected_hash, actual_hash))
                if actual_hash != expected_hash:
                    raise WinRMError("Failed to fetch file %s, hash mismatch\n"
                                     "Source: %s\nFetched: %s"
                                     % (src, expected_hash, actual_hash))
                shutil.copy(path, dest)
            finally:
                os.close(temp_file)
                os.remove(path)

    @staticmethod
    def sanitise_clixml(clixml):
        """
        When running a powershell script in execute_cmd (WinRS), the stderr
        stream may contain some clixml. This method will clear it up and
        replace it with the error string it would represent. This isn't done
        by default on execute_cmd for various reasons but people can call it
        manually here if they like.

        :param clixml: The clixml to parse
        :return: A unicode code string of the decoded output
        """
        output = to_unicode(clixml)
        if output.startswith("#< CLIXML\r\n"):
            serializer = Serializer()
            output = output[11:]
            element = ET.fromstring(output)
            namespace = element.tag.replace("Objs", "")[1:-1]
            errors = []
            for error in element.findall("{%s}S[@S='Error']" % namespace):
                errors.append(error.text)
            output = serializer._deserialize_string("".join(errors))

        return output
