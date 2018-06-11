# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile used to setup a Windows host that will work with the
# test_integration.py tests

Vagrant.configure("2") do |config|
  config.vm.box = "jborean93/WindowsServer2016"
  config.vm.provision "file", source: "appveyor/JEARole.psrc", destination: "JEARole.psrc"
  config.vm.provision "file", source: "appveyor/JEARoleSettings.pssc", destination: "JEARoleSettings.pssc"
  config.vm.provision "shell", path: "appveyor/setup.ps1", args: "-Name vagrant -Password vagrant -JEAConfigPath \"$($env:USERPROFILE)\\Documents\" -InformationAction Continue"
  config.vm.provision "shell", inline: 'Copy-Item -Path "$($env:USERPROFILE)\\Documents\\cert.pem" -Destination C:\\vagrant; Copy-Item -Path "$($env:USERPROFILE)\\Documents\\cert_key.pem" -Destination C:\\vagrant'
end
