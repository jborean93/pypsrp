[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [String]
    $UserName,

    [Parameter(Mandatory)]
    [String]
    $Password,

    [Parameter(Mandatory)]
    [String]
    $CertPath
)

$ErrorActionPreference = "Stop"

Write-Information -MessageData "Configuring WinRM for pypsrp tests for $UserName"

Function New-LegacySelfSignedCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $Subject,

        [Parameter(Mandatory)]
        [Int32]
        $ValidDays
    )

    Write-Information -MessageData "Creating self-signed certificate of CN=$Subject for $ValidDays days"
    $subject_name = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $subject_name.Encode("CN=$Subject", 0)

    $private_key = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $private_key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $private_key.KeySpec = 1
    $private_key.Length = 4096
    $private_key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $private_key.MachineContext = 1
    $private_key.Create()

    $server_auth_oid = New-Object -ComObject X509Enrollment.CObjectId
    $server_auth_oid.InitializeFromValue("1.3.6.1.5.5.7.3.1")

    $ekuoids = New-Object -ComObject X509Enrollment.CObjectIds
    $ekuoids.Add($server_auth_oid)

    $eku_extension = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
    $eku_extension.InitializeEncode($ekuoids)

    $name = @($env:COMPUTERNAME, ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).Hostname))
    $alt_names = New-Object -ComObject X509Enrollment.CAlternativeNames
    foreach ($name in $name) {
        $alt_name = New-Object -ComObject X509Enrollment.CAlternativeName
        $alt_name.InitializeFromString(0x3, $name)
        $alt_names.Add($alt_name)
    }
    $alt_names_extension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $alt_names_extension.InitializeEncode($alt_names)

    $digital_signature = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
    $key_encipherment = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $key_usage = [int]($digital_signature -bor $key_encipherment)
    $key_usage_extension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $key_usage_extension.InitializeEncode($key_usage)
    $key_usage_extension.Critical = $true

    $signature_oid = New-Object -ComObject X509Enrollment.CObjectId
    $sha256_oid = New-Object -TypeName Security.Cryptography.Oid -ArgumentList "SHA256"
    $signature_oid.InitializeFromValue($sha256_oid.Value)

    $certificate = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
    $certificate.InitializeFromPrivateKey(2, $private_key, "")
    $certificate.Subject = $subject_name
    $certificate.Issuer = $certificate.Subject
    $certificate.NotBefore = (Get-Date).AddDays(-1)
    $certificate.NotAfter = $certificate.NotBefore.AddDays($ValidDays)
    $certificate.X509Extensions.Add($key_usage_extension)
    $certificate.X509Extensions.Add($alt_names_extension)
    $certificate.X509Extensions.Add($eku_extension)
    $certificate.SignatureInformation.HashAlgorithm = $signature_oid
    $certificate.Encode()

    $enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
    $enrollment.InitializeFromRequest($certificate)
    $certificate_data = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certificate_data, 0, "")

    $parsed_certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsed_certificate.Import([System.Text.Encoding]::UTF8.GetBytes($certificate_data))

    return $parsed_certificate
}

function New-WinRMFirewallRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Int32]
        $Port,

        [Parameter(Mandatory)]
        [String]
        $Protocol
    )
    $fw = New-Object -ComObject HNetCfg.FWPolicy2
    $https_rule = "Windows Remote Management ($Protocol)"

    $rules = $fw.Rules | Where-Object { $_.Name -eq $https_rule }
    if (-not $rules) {
        Write-Information -MessageData "Creating a new WinRM $Protocol firewall rule"
        $rule = New-Object -ComObject HNetCfg.FwRule
        $rule.Name = $https_rule
        $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP $Port]"
        $rule.Profiles = 0x7FFFFFFF
        $rules = @($rule)
    }

    foreach ($rule in $rules) {
        $rule_details = @{
            LocalPorts      = $Port
            RemotePorts     = "*"
            LocalAddresses  = "*"
            Enabled         = $true
            Direction       = 1
            Action          = 1
            Grouping        = "Windows Remote Management"
            ApplicationName = "System"
        }
        $rule.Protocol = 6

        $changed = $false
        foreach ($detail in $rule_details.GetEnumerator()) {
            $original_value = $rule.$($detail.Name)
            $new_value = $detail.Value
            Write-Information -MessageData "Checking FW Rule property $($detail.Name) - Actual: '$original_value', Expected: '$new_value'"
            if ($original_value -ne $new_value) {
                Write-Information -MessageData "FW Rule property $($detail.Name) does not match, changing rule"
                $rule.$($detail.Name) = $new_value
                $changed = $true
            }
        }

        if ($changed) {
            Write-Information -MessageData "WinRM $Protocol firewall rule needs to be (re)created as config does not match expectation"
            try {
                $fw.Rules.Add($rule)
            }
            catch [System.Runtime.InteropServices.COMException] {
                # E_UNEXPECTED 0x80000FFFF means the rule already exists
                if ($_.Exception.ErrorCode -eq 0x8000FFFF) {
                    Write-Information -MessageData "WinRM $Protocol firewall rule already exists, deleting before recreating"
                    $fw.Rules.Remove($rule.Name)
                    $fw.Rules.Add($rule)
                }
                else {
                    Write-Information -MessageData "Failed to add WinRM $Protocol firewall rule: $($_.Exception.Message)"
                    throw $_
                }
            }
        }
    }
}

function Reset-WinRMConfig {
    [CmdletBinding()]
    Param()

    Write-Verbose "Removing all existing WinRM listeners"
    Get-ChildItem -LiteralPath WSMan:\localhost\Listener | Remove-Item -Force -Recurse

    if (-not $CertificateThumbprint) {
        Write-Verbose "Removing all existing certificate in the personal store"
        Remove-Item -Path Cert:\LocalMachine\My\* -Force -Recurse
    }

    Write-Information -MessageData "Creating HTTP listener"
    $selectorSet = @{
        Transport = "HTTP"
        Address   = "*"
    }
    $valueSet = @{
        Enabled = $true
    }
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selectorSet -ValueSet $valueSet > $null

    $certificate = New-LegacySelfSignedCert -Subject $env:COMPUTERNAME -ValidDays 1095
    $selectorSet = @{
        Transport = "HTTPS"
        Address   = "*"
    }
    $valueSet = @{
        CertificateThumbprint = $certificate.Thumbprint
        Enabled               = $true
    }

    Write-Information -MessageData "Creating HTTPS listener"
    New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selectorSet -ValueSet $valueSet > $null

    Write-Verbose "Enabling PowerShell Remoting"
    Enable-PSRemoting -Force > $null

    Write-Information -MessageData "Enabling Basic authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

    Write-Information -MessageData "Enabling Certificate authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

    Write-Information -MessageData "Enabling CredSSP authentication"
    Enable-WSManCredSSP -Role Server -Force > $null

    Write-Information -MessageData "Setting AllowUnencrypted to True"
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

    Write-Information -MessageData "Configuring WinRM HTTPS firewall rule"
    New-WinRMFirewallRule -Port 5986 -Protocol HTTPS

    Write-Information -MessageData "Set CbtHardeningLevel to strict"
    Set-Item -Path WSMan:\localhost\Service\Auth\CbtHardeningLevel -Value Strict

    Write-Information -MessageData "Allow local admins over network auth"
    $regInfo = @{
        Path         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name         = "LocalAccountTokenFilterPolicy"
        Value        = 1
        PropertyType = "DWord"
        Force        = $true
    }
    New-ItemProperty @regInfo

    Write-Information -MessageData "WinRM and PS Remoting have been set up successfully"
}

Function New-CertificateAuthBinding {
    [CmdletBinding()]
    Param (
        [String]
        $Name,

        [String]
        $CertPath
    )

    Write-Information -MessageData "Generating self signed certificate for authentication of user $Name"
    $certInfo = @{
        Type              = "Custom"
        Subject           = "CN=$Name"
        TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=$Name@localhost")
        KeyUsage          = "DigitalSignature", "KeyEncipherment"
        KeyAlgorithm      = "RSA"
        KeyLength         = 2048
        CertStoreLocation = "Cert:\CurrentUser\My"
    }
    $cert = New-SelfSignedCertificate @certInfo

    Write-Information -MessageData "Exporting private key in a PFX file"
    $certDir = Split-Path $CertPath -Parent
    [System.IO.File]::WriteAllBytes("$certDir\cert.pfx", $cert.Export("Pfx"))

    Write-Information -MessageData "Converting private key to PEM format with openssl"
    $out = openssl.exe @(
        "pkcs12",
        "-in", "$certDir\cert.pfx",
        "-nocerts",
        "-nodes",
        "-out", "$certDir\cert_key.pem",
        "-passin", "pass:",
        "-passout", "pass:"
    ) 2>&1
    if ($LASTEXITCODE) {
        throw "Failed to extract key from PEM:`n$out"
    }
    Remove-Item -Path "$certDir\cert.pfx" -Force

    # WinRM seems to be very picky about the type of cert in the trusted root and people store. Make sure this is set
    # to the cert and not cert + key.
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)

    Write-Information -MessageData "Exporting cert and key of user certificate"
    $key_pem = Get-Content -Path "$certDir\cert_key.pem"
    Remove-Item -Path "$certDir\cert_key.pem" -Force
    [System.IO.File]::WriteAllLines($CertPath, @(
            $key_pem
            "-----BEGIN CERTIFICATE-----"
            [System.Convert]::ToBase64String($cert.RawData) -replace ".{64}", "$&`n"
            "-----END CERTIFICATE-----"
        ))

    Write-Information -MessageData "Importing cert into LocalMachine\Root"
    $store = Get-Item -Path Cert:\LocalMachine\Root
    $store.Open("MaxAllowed")
    $store.Add($cert)
    $store.Close()

    Write-Information -MessageData "Importing cert into LocalMachine\TrustedPeople"
    $store = Get-Item -Path Cert:\LocalMachine\TrustedPeople
    $store.Open("MaxAllowed")
    $store.Add($cert)
    $store.Close()

    $cert.Thumbprint
}

Function New-JEAConfiguration {
    [CmdletBinding()]
    Param (
        [string]
        $Name,

        [string]
        $JEAConfigPath
    )

    $modulePath = Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\$Name"
    Write-Information -MessageData "Setting up JEA PowerShell module path at '$modulePath'"
    if (-not (Test-Path -Path $modulePath)) {
        New-Item -Path $modulePath -ItemType Directory
    }

    $functionsPath = Join-Path -Path $modulePath -ChildPath "$($Name)Functions.psm1"
    if (-not (Test-Path -Path $functionsPath)) {
        New-Item -Path $functionsPath -ItemType File
    }

    $manifestPath = Join-Path -Path $modulePath -ChildPath "$($Name).psd1"
    if (-not (Test-Path -Path $manifestPath)) {
        New-ModuleManifest -Path $manifestPath -RootModule "$($Name)Functions.psm1"
    }

    $rolePath = Join-Path -Path $modulePath -ChildPath "RoleCapabilities"
    if (-not (Test-Path -Path $rolePath)) {
        New-Item -Path $rolePath -ItemType Directory
    }

    $jeaRoleSrc = Join-Path -Path $JEAConfigPath -ChildPath "$($Name).psrc"

    Write-Information -MessageData "Copying across JEA role configuration from '$jeaRoleSrc'"
    Copy-Item -Path $jeaRoleSrc -Destination $rolePath

    if (Get-PSSessionConfiguration | Where-Object { $_.Name -eq $name }) {
        Write-Information -MessageData "JEA role $Name already registered, removing to ensure we start fresh"
        Unregister-PSSessionConfiguration -Name $Name -NoServiceRestart
    }
}

$secPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$userCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:COMPUTERNAME\$UserName, $secPassword

Enable-PSRemoting -Force
Start-Service -Name WinRM
Reset-WinRMConfig

$localUser = New-LocalUser -Name $UserName -Password $secPassword -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member $localUser

# $thumbprint = New-CertificateAuthBinding -Name $UserName -CertPath $CertPath
# $credBinding = @{
#     Path       = "WSMan:\localhost\ClientCertificate"
#     Subject    = "$UserName@localhost"
#     URI        = "*"
#     Issuer     = $thumbprint
#     Credential = $userCredential
#     Force      = $true
# }
# New-Item @credBinding

New-JEAConfiguration -Name JEARole -JEAConfigPath $PSScriptRoot
Register-PSSessionConfiguration -Path "$PSScriptRoot\JEARoleSettings.pssc" -Name JEARole -Force

Restart-Service -Name winrm

Write-Information -MessageData "Testing WinRM connection"
$invokeParams = @{
    ComputerName  = 'localhost'
    ScriptBlock   = { whoami.exe }
    SessionOption = (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)
}
Invoke-Command @invokeParams -Credential $userCredential

# Write-Information -MessageData "Testing WinRM connection with certificates"
# Invoke-Command @invokeParams -CertificateThumbprint $thumbprint

Write-Information -MessageData "Installing OpenSSH service"
choco.exe install -y openssh --pre --no-progress --params '"/SSHServerFeature"'

$sshDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("~/.ssh")
if (-not (Test-Path -Path $sshDir)) {
    $null = New-Item -Path $sshDir -ItemType Directory
}
ssh-keygen -o -a 100 -t ed25519 -f (Join-Path $sshDir id_ed25519) -q -N '""'
Copy-Item -Path "$sshDir\id_ed25519.pub" -Destination C:\ProgramData\ssh\administrators_authorized_keys -Force
icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"

$pwshPath = (Get-Command -Name pwsh.exe).Path
$fsObj = New-Object -ComObject Scripting.FileSystemObject
$pwshShortPath = $fsObj.GetFile($pwshPath).ShortPath
$subSystemLine = "Match all`r`nSubsystem powershell $pwshShortPath -sshs -NoLogo"
Add-Content -Path C:\ProgramData\ssh\sshd_config -Value $subSystemLine -Encoding ASCII
Add-Content -Path C:\ProgramData\ssh\sshd_config -Value "PubkeyAuthentication yes" -Encoding ASCII
Restart-Service -Name sshd -Force

Write-Information -MessageData "Testing SSH connection"
ssh -o IdentityFile="$sshDir\id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost whoami
if ($LASTEXITCODE) {
    throw "SSH test failed with $LASTEXITCODE"
}
