[CmdletBinding()]
param(
    [String]$Name,
    [String]$JEAConfigPath,
    # will delete and recreate the WinRM cert and listeners, do not set when running on Vagrant box
    [switch]$ResetWinRM
)

$ErrorActionPreference = "Stop"

Write-Information -MessageData "Configuring WinRM for pypsrp tests for $Name"

Function New-LegacySelfSignedCert($subject, $valid_days) {
    Write-Information -MessageData "Creating self-signed certificate of CN=$subject for $valid_days days"
    $subject_name = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $subject_name.Encode("CN=$subject", 0)

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
    $certificate.NotAfter = $certificate.NotBefore.AddDays($valid_days)
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

function New-WinRMFirewallRule($port, $protocol) {
    $fw = New-Object -ComObject HNetCfg.FWPolicy2
    $https_rule = "Windows Remote Management ($protocol-In)"

    $rules = $fw.Rules | Where-Object { $_.Name -eq $https_rule }
    if (-not $rules) {
        Write-Information -MessageData "Creating a new WinRM $protocol firewall rule"
        $rule = New-Object -ComObject HNetCfg.FwRule
        $rule.Name = $https_rule
        $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP $port]"
        $rule.Profiles = 0x7FFFFFFF
        $rules = @($rule)
    }

    foreach ($rule in $rules) {
        $rule_details = @{
            LocalPorts = $port
            RemotePorts = "*"
            LocalAddresses = "*"
            Enabled = $true
            Direction = 1
            Action = 1
            Grouping = "Windows Remote Management"
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
            Write-Information -MessageData "WinRM $protocol firewall rule needs to be (re)created as config does not match expectation"
            try {
                $fw.Rules.Add($rule)
            } catch [System.Runtime.InteropServices.COMException] {
                # E_UNEXPECTED 0x80000FFFF means the rule already exists
                if ($_.Exception.ErrorCode -eq 0x8000FFFF) {
                    Write-Information -MessageData "WinRM $protocol firewall rule already exists, deleting before recreating"
                    $fw.Rules.Remove($rule.Name)
                    $fw.Rules.Add($rule)
                } else {
                    Write-Information -MessageData "Failed to add WinRM $protocol firewall rule: $($_.Exception.Message)"
                    throw $_
                }
            }
        }
    }
}

function Reset-WinRMConfig {
    [CmdletBinding()]
    Param(
        [string]$CertificateThumbprint,
        [switch]$ResetWinRM
    )

    if ($ResetWinRM) {
        Write-Verbose "Removing all existing WinRM listeners"
        Get-ChildItem -LiteralPath WSMan:\localhost\Listener | Remove-Item -Force -Recurse

        if (-not $CertificateThumbprint) {
            Write-Verbose "Removing all existing certificate in the personal store"
            Remove-Item -Path Cert:\LocalMachine\My\* -Force -Recurse
        }

        Write-Information -MessageData "Creating HTTP listener"
        $selector_set = @{
            Transport = "HTTP"
            Address = "*"
        }
        $value_set = @{
            Enabled = $true
        }
        New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selector_set -ValueSet $value_set > $null

        if ($CertificateThumbprint) {
            $thumbprint = $CertificateThumbprint
        } else {
            $certificate = New-LegacySelfSignedCert -subject $env:COMPUTERNAME -valid_days 1095
            $thumbprint = $certificate.Thumbprint
        }
        $selector_set = @{
            Transport = "HTTPS"
            Address = "*"
        }
        $value_set = @{
            CertificateThumbprint = $thumbprint
            Enabled = $true
        }

        Write-Information -MessageData "Creating HTTPS listener"
        New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selector_set -ValueSet $value_set > $null
    }

    Write-Verbose "Enabling PowerShell Remoting"
    # Change the verbose output for this cmdlet only as the output is really verbose
    Enable-PSRemoting -Force > $null

    Write-Information -MessageData "Enabling Basic authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

    Write-Information -MessageData "Enabling Certificate authentication"
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

    Write-Information -MessageData "Enabling CredSSP authentication"
    Enable-WSManCredSSP -role server -Force > $null

    Write-Information -MessageData "Setting AllowUnencrypted to False"
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false

    Write-Information -MessageData "Configuring WinRM HTTPS firewall rule"
    New-WinRMFirewallRule -port 5986 -protocol HTTPS

    Write-Information -MessageData "Set CbtHardeningLevel to strict"
    Set-Item -Path WSMan:\localhost\Service\Auth\CbtHardeningLevel -Value Strict

    Write-Information -MessageData "WinRM and PS Remoting have been set up successfully"
}

Function New-CertificateAuthBinding
{
    [CmdletBinding()]
    Param (
        [String]$Name
    )

    $output_path = "$($env:USERPROFILE)\Documents"

    Write-Information -MessageData "Generating self signed certificate for authentication of user $Name"
    $cert = New-SelfSignedCertificate -Type Custom `
        -Subject "CN=$Name" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=$Name@localhost") `
        -KeyUsage DigitalSignature,KeyEncipherment `
        -KeyAlgorithm RSA `
        -KeyLength 2048

    Write-Information -MessageData "Exporting public key of cert"
    $pem_output = @()
    $pem_output += "-----BEGIN CERTIFICATE-----"
    $pem_output += [System.Convert]::ToBase64String($cert.RawData) -replace ".{64}", "$&`n"
    $pem_output += "-----END CERTIFICATE-----"
    [System.IO.File]::WriteAllLines("$output_path\cert.pem", $pem_output)

    Write-Information -MessageData "Exporting private key in a PFX file"
    [System.IO.File]::WriteAllBytes("$output_path\cert.pfx", $cert.Export("Pfx"))

    Write-Information -MessageData "Converting private key to PEM format with openssl"
    &"C:\Program Files\OpenSSL\bin\openssl.exe" @("pkcs12", "-in", "$output_path\cert.pfx", "-nocerts", "-nodes", "-out", "$output_path\cert_key.pem", "-passin", "pass:", "-passout", "pass:")

    Write-Information -MessageData "Importing cert into LocalMachine\Root"
    $store_name = [System.Security.Cryptography.X509Certificates.StoreName]::Root
    $store_location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store_name, $store_location
    $store.Open("MaxAllowed")
    $store.Add($cert)
    $store.Close()

    Write-Information -MessageData "Importing cert into LocalMachine\TrustedPeople"
    $store_name = [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople
    $store_location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store_name, $store_location
    $store.Open("MaxAllowed")
    $store.Add($cert)
    $store.Close()
}

Function New-JEAConfiguration {
    [CmdletBinding()]
    Param (
        [string]$Name,
        [string]$JEAConfigPath
    )

    $module_path = Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\$Name"
    Write-Information -MessageData "Setting up JEA PowerShell module path at '$module_path'"
    if (-not (Test-Path -Path $module_path)) {
        New-Item -Path $module_path -ItemType Directory
    }

    $functions_path = Join-Path -Path $module_path -ChildPath "$($Name)Functions.psm1"
    if (-not (Test-Path -Path $functions_path)) {
        New-Item -Path $functions_path -ItemType File
    }

    $manifest_path = Join-Path -Path $module_path -ChildPath "$($Name).psd1"
    if (-not (Test-Path -Path $manifest_path)) {
        New-ModuleManifest -Path $manifest_path -RootModule "$($Name)Functions.psm1"
    }

    $role_path = Join-Path -Path $module_path -ChildPath "RoleCapabilities"
    if (-not (Test-Path -Path $role_path)) {
        New-Item -Path $role_path -ItemType Directory
    }

    $jea_role_src = Join-Path -Path $JEAConfigPath -ChildPath "$($Name).psrc"
    $jea_config_src = Join-Path -Path $JEAConfigPath -ChildPath "$($Name)Settings.pssc"

    Write-Information -MessageData "Copying across JEA role configuration from '$jea_role_src'"
    Copy-Item -Path $jea_role_src -Destination $role_path

    if (Get-PSSessionConfiguration | Where-Object { $_.Name -eq $name }) {
        Write-Information -MessageData "JEA role $Name already registered, removing to ensure we start fresh"
        Unregister-PSSessionConfiguration -Name $Name -NoServiceRestart
    }
}

Write-Information -MessageData "Installing openssl which is used to convert the authentication private key to the PEM format"
&choco.exe install -y openssl.light --no-progress

Start-Service -Name WinRM
Reset-WinRMConfig -ResetWinRM:$ResetWinRM

New-CertificateAuthBinding -Name $Name

# this doesn't actually register it, running this in WinRM will fail and so
# we need to run the following manually
# Register-PSSessionConfiguration -Path "JEARoleSettings.pssc" -Name JEARole -Force
New-JEAConfiguration -Name JEARole -JEAConfigPath $JEAConfigPath
