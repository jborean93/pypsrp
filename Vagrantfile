# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile used to setup a Windows host that will work with the
# test_integration.py tests

Vagrant.configure("2") do |config|
  config.vm.box = "jborean93/WindowsServer2016"
  config.vm.provision "file", source: "appveyor/JEARole.psrc", destination: "JEARole.psrc"
  config.vm.provision "file", source: "appveyor/JEARoleSettings.pssc", destination: "JEARoleSettings.pssc"
  config.vm.provision "shell", path: "appveyor/setup.ps1", args: "-Name vagrant -JEAConfigPath \"$($env:USERPROFILE)\\Documents\" -InformationAction Continue"
  config.vm.provision "shell", inline: 'Copy-Item -Path "$($env:USERPROFILE)\\Documents\\cert.pem" -Destination C:\\vagrant; Copy-Item -Path "$($env:USERPROFILE)\\Documents\\cert_key.pem" -Destination C:\\vagrant'
end

=begin
The above script tries to do as much as possible but because Vagrant uses WinRM
we can't register/bounce the PS configuration/service or else it will error.
Once the startup process is complete run the following manually

# connect to the Windows box with SSH on Vagrant, enter the password 'vagrant'
# when asked
vagrant ssh

# open PowerShell and run the following commands
powershell.exe
Register-PSSessionConfiguration -Path "C:\Users\vagrant\Documents\JEARoleSettings.pssc" -Name JEARole -Force

$sec_pass = ConvertTo-SecureString -String "vagrant" -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "vagrant", $sec_pass
$thumbprint = (Get-ChildItem -Path Cert:\LocalMachine\TrustedPeople)[0].Thumbprint

New-Item -Path WSMan:\localhost\ClientCertificate `
    -Subject "vagrant@localhost" `
    -URI * `
    -Issuer $thumbprint `
    -Credential $credential `
    -Force

# quit PowerShell
exit

# exit SSH session
exit
=end