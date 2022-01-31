# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $Path,

    [Parameter(Mandatory = $true)]
    [int]
    $BufferSize,

    [Parameter()]
    [switch]
    $ExpandVariables
)

$ErrorActionPreference = 'Stop'

if ($ExpandVariables) {
    $Path = [System.Environment]::ExpandEnvironmentVariables($Path)
}
$Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
Write-Verbose -Message "Starting remote fetch operation for '$Path'"

if (Test-Path -LiteralPath $Path -PathType Container) {
    throw "The path at '$Path' is a directory, src must be a file"
}
elseif (-not (Test-Path -LiteralPath $Path)) {
    throw "The path at '$Path' does not exist"
}

$algo = [System.Security.Cryptography.SHA1CryptoServiceProvider]::Create()
$src = New-Object -TypeName System.IO.FileInfo -ArgumentList $Path
$buffer = New-Object -TypeName byte[] -ArgumentList $BufferSize

$fs = $src.OpenRead()
try {
    while ($fs.Position -lt $fs.Length) {
        $read = $fs.Read($buffer, 0, $buffer.Length)

        # The leading , is important to ensure it outputs as a byte array rather than byte by byte
        , ([byte[]]$buffer[0..($read - 1)])
        $algo.TransformBlock($buffer, 0, $read, $buffer, 0) > $null
    }
}
finally {
    $fs.Dispose()
}

$algo.TransformFinalBlock($buffer, 0, 0) > $Null
$hash = [System.BitConverter]::ToString($algo.Hash)
$hashValue = $hash.Replace("-", "").ToLowerInvariant()

Write-Verbose -Message "Hash value for remote file is $hashValue"
$hashValue
