# pypsrp - Python PowerShell Remoting Protocol Client library

[![Build Status](https://travis-ci.org/jborean93/pypsrp.svg?branch=master)](https://travis-ci.org/jborean93/pypsrp)
[![Build status](https://ci.appveyor.com/api/projects/status/ds45t1a8bqqr9kk2/branch/master?svg=true)](https://ci.appveyor.com/project/jborean93/pypsrp/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/jborean93/pypsrp/badge.svg)](https://coveralls.io/github/jborean93/pypsrp)

pypsrp is a Python client for the PowerShell Remoting Protocol (PSRP) and
Windows Remove Management (WinRM) service. It allows your to execute commands
on a remote Windows host from any machine that can run Python.

This library exposes 3 different types of APIs;

* A simple client API that can copy files to and from the remote Windows host as well as execute processes and PowerShell scripts
* A Windows Remote Shell (WinRS) layer that executes cmd commands and executables using the base WinRM protocol
* A PowerShell Remoting Protocol (PSRP) layer allows you to create remote Runspace Pools and PowerShell pipelines

At a basic level, you can use this library to;

* Execute a cmd command
* Run another executable
* Execute PowerShell scripts
* Copy a file from the localhost to the remote Windows host
* Fetch a file from the remote Windows host to the localhost
* Create a Runspace Pool that contains one or multiple PowerShell pipelines and execute them asynchronously

Currently this library only supports the WSMan transport method but is designed
to support SSH at some point in the future (PR's are welcome). By default it
supports the following authentication methods with WSMan;

* Basic
* Certificate
* NTLM

To add full support for Negotiate/Kerberos and CredSSP, optional libraries can
be installed.


## Requirements

See `How to Install` for more details

* CPython 2.6-2.7, 3.4-3.6
* [cryptography](https://github.com/pyca/cryptography)
* [requests](https://github.com/requests/requests)
* [ntlm-auth](https://github.com/jborean93/ntlm-auth)
* [six](https://github.com/benjaminp/six)

_Note: while Python 2.6 is supported it may be dropped in the future if it is
too much work in the future. You should really be using at least Python 2.7 but
preferably Python 3.5 or 3.6_

### Optional Requirements

The following Python libraries can be installed to add extra features that do
not come with the base package

* [python-gssapi](https://github.com/pythongssapi/python-gssapi) for Kerberos authentication on Linux
* [pywin32](https://github.com/mhammond/pywin32) for Kerberos authentication on Windows
* [requests-credssp](https://github.com/jborean93/requests-credssp) for CredSSP authentication


## How to Install

To install pypsrp with all basic features, run

```
pip install pypsrp
```

### Kerberos Authentication

While pypsrp supports Kerberos authentication, it isn't included by default due
to it's reliance on system packages to be present.

To install these packages, run the below

For Debian/Ubuntu

```
# For Python 2
apt-get install gcc python-dev libkrb5-dev

# For Python 3
apt-get install gcc python3-dev libkrb5-dev

# To add NTLM to the GSSAPI SPNEGO auth run
apt-get install gss-ntlmssp
```

For RHEL/Centos

```
yum install gcc python-devel krb5-devel

# To add NTLM to the GSSAPI SPNEGO auth run
yum install gssntlmssp
```

For Fedora

```
dnf install gcc python-devel krb5-devel

# To add NTLM to the GSSAPI SPNEGO auth run
dnf install gssntlmssp
```

For Arch Linux

```
pacman -S gcc krb5
```

Once installed you can install the Python packages with

```
pip install pypsrp[kerberos]
```

For Windows, running the pip install command above is usually enough but there
are cases where this will fail. The alternative is to the binary based on the
[recent release of pywin32](https://github.com/mhammond/pywin32/releases)
instead of installing through pip.

Kerberos also needs to be configured to talk to the domain but that is outside
the scope of this page.

### CredSSP Authentication

Like Kerberos auth, CredSSP is supported but isn't included by default. To add
support for CredSSP auth try to run the following

```
pip install pypsrp[credssp]
```

If that fails you may need to update pip and setuptools to a newer version
`pip install -U pip setuptools`, otherwise the following system package may be
required;

```
# For Debian/Ubuntu
apt-get install gcc python-dev

# For RHEL/Centos
yum install gcc python-devel

# For Fedora
dnf install gcc python-devel
```


## Logging

This library takes advantage of the Python logging configuration and messages
are logged to the `pypsrp` named logger as well as `pypsrp.*` where `*` is each
Python script in the `pypsrp` directory.

An easy way to turn on logging for the entire library is to create the
following JSON file and run your script with
`PYPSRP_LOG_CFG=log.json python script.py`.


```json
{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "simple": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "simple",
            "stream": "ext://sys.stdout"
        }
    },

    "loggers": {
        "pypsrp": {
            "level": "DEBUG",
            "handlers": ["console"],
            "propagate": "no"
        }
    }
}
```

You can adjust the log level by changing the level value in `logger` to `INFO`.

_Note: `DEBUG` contains a lot of information and will output all the messages
sent to and from the client. This can have the side effect of leaking sensitive
information and should only be used for debugging purposes._


## Testing

Any changes are more than welcome in pull request form, you can run the current
test suite with tox like so;

```
# make sure tox is installed
pip install tox

# run the tox suite
tox

# or run the test manually for the current Python environment
py.test -v --pep8 --cov pypsrp --cov-report term-missing
```

A lot of the tests either simulate a remote Windows host but you can also run a
lot of them against a real Windows host. To do this, set the following
environment variables before running the tests;

* `PYPSRP_SERVER`: The hostname or IP of the remote host
* `PYPSRP_USERNAME`: The username to connect with
* `PYPSRP_PASSWORD`: The password to connect with
* `PYPSRR_PORT`: The port to connect with (default: `5986`)
* `PYPSRP_AUTH`: The authentication protocol to auth with (default: `negotiate`)

There are further integration tests that require a specific host setup to run
correctly. You can use `Vagrant` to set this host up. This is done by running
the following commands;

```
# download the Vagrant box and start it up based on the Vagrantfile
vagrant up

# once the above script is complete run the following
vagrant ssh  # password is vagrant

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


# exit the remote PowerShell session
exit

# exist the SSH session
exit
```

Once complete, set the following environment variables to run the integration
tests;

* `PYPSRP_RUN_INTEGRATION`: To any value
* `PYPSRP_SERVER`: Set to `127.0.0.1`
* `PYPSRP_USERNAME`: Set to `vagrant`
* `PYPSRP_PASSWORD`: Set to `vagrant`
* `PYPSRP_HTTP_PORT`: Set to `55985`
* `PYPSRP_HTTPS_PORT`: Set to `55986`
* `PYPSRP_CERT_DIR`: Set to the full path of the project directory

From here you can run the normal test suite and it will run all the integration
tests.


## Backlog

* Look into adding SSH as a transport option
* Add support for host based calls and implement reference host object
* Live interactive console for PSRP (dependent on the above as well)
