# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

begin {
    $ErrorActionPreference = "Stop"
    $path = [System.IO.Path]::GetTempFileName()
    $fd = [System.IO.File]::Create($path)
    $algo = [System.Security.Cryptography.SHA1CryptoServiceProvider]::Create()
    $bytes = $null
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

    # MaximumAllowedMemory is required to be set to so we can send input data that exceeds the limit on a PS
    # Runspace. We use reflection to access/set this property as it is not accessible publicly. This is not ideal
    # but works on all PowerShell versions I've tested with. We originally used WinRS to send the raw bytes to the
    # host but this falls flat if someone is using a custom PS configuration name so this is a workaround.
    $Host | Get-Property 'ExternalHost' | `
        Get-Field '_transportManager' | `
        Get-Property 'Fragmentor' | `
        Get-Property 'DeserializationContext' | `
        Set-Property 'MaximumAllowedMemory' $null
} process {
    # On the first input $bytes will be $null so this isn't run. This shifts each input to the next run until
    # the final input is reach (checksum of the file) which is processed in enc.
    if ($null -ne $bytes) {
        $algo.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0) > $null
        $fd.Write($bytes, 0, $bytes.Length)
    }
    $bytes = [System.Convert]::FromBase64String($input)
} end {
    $fd.Close()

    try {
        # Makes sure relative paths are resolved to an absolute path based on the current location.
        $output_path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($args[0])
        $dest = New-Object -TypeName System.IO.FileInfo -ArgumentList $output_path

        $expected_hash = [System.Text.Encoding]::UTF8.GetString($bytes)
        $algo.TransformFinalBlock($bytes, 0, 0) > $null
        $actual_hash = [System.BitConverter]::ToString($algo.Hash)
        $actual_hash = $actual_hash.Replace("-", "").ToLowerInvariant()

        if ($actual_hash -ne $expected_hash) {
            throw "Transport failure, hash mismatch`r`nActual: $actual_hash`r`nExpected: $expected_hash"
        }

        # Copy the temp file to the actual dest location and return the absolute path back to the client.
        [System.IO.File]::Copy($path, $output_path, $true)
        $dest.FullName
    } finally {
        [System.IO.File]::Delete($path)
    }
}