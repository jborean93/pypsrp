# pypsrp - Python PowerShell Remoting Protocol Client library

[![Test workflow](https://github.com/jborean93/pypsrp/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/pypsrp/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/pypsrp/branch/master/graph/badge.svg)](https://codecov.io/gh/jborean93/pypsrp)
[![PyPI version](https://badge.fury.io/py/pypsrp.svg)](https://badge.fury.io/py/pypsrp)

pypsrp is a Python client for the PowerShell Remoting Protocol (PSRP) service.
It allows you to execute PowerShell scripts inside the Python script with a target being remote or some other local process.

This library has a low level API designed to mirror the [System.Management.Automation](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation?view=powershellsdk-7.0.0) namespace.
There are also some helper functions designed to make it easier to do one off scripts and copy/fetch files on the target PSSession.

The old `pypsrp` namespace only supported WSMan based transports but the `psrp` namespace supports the following:

* WSMan - targets only remote Windows hosts
* SSH - can target both remote Windows and non-Windows hosts
* Process - can spawn a new local pwsh or powershell process and run code in there
* Named Pipes - targets a named pipe, like the pwsh remoting pipe, and communicate over that

The WSMan connection supports the following authentication protocols out of the box:

* Negotiate (Default)
* Basic
* Certificate
* NTLM
* CredSSP

To support Kerberos the `kerberos` extras package must be installed.

## Requirements

See `How to Install` for more details

* CPython 3.6+
* [cryptography](https://github.com/pyca/cryptography)
* [psrpcore](https://github.com/jborean93/psrpcore)
* [pyspnego](https://github.com/jborean93/pyspnego)
* [requests](https://github.com/requests/requests) - for the `pypsrp` code
* [httpx](https://github.com/encode/httpx) - for the `psrp` code

### Optional Requirements

The following Python libraries can be installed to add extra features that do not come with the base package:

* [python-gssapi](https://github.com/pythongssapi/python-gssapi) for Kerberos authentication on Linux
* [pykrb5](https://github.com/jborean93/pykrb5) for Kerberos authentication on Linux
* [asyncssh](https://github.com/ronf/asyncssh) for SSH connections
* [psutil](https://github.com/giampaolo/psutil) for Named Pipe connections


## How to Install

To install pypsrp with all the basic features, run:

```bash
pip install pypsrp
```

### Kerberos Authentication

While pypsrp supports Kerberos authentication, it isn't included by default for Linux hosts due to it's reliance on system packages to be present.

To install these packages, depending on your distribution, run one of the following script blocks.

For Debian/Ubuntu

```bash
# For Python 2
apt-get install gcc python-dev libkrb5-dev

# For Python 3
apt-get install gcc python3-dev libkrb5-dev

# To add NTLM to the GSSAPI SPNEGO auth run
apt-get install gss-ntlmssp
```

For RHEL/Centos

```bash
yum install gcc python-devel krb5-devel

# To add NTLM to the GSSAPI SPNEGO auth run
yum install gssntlmssp
```

For Fedora

```bash
dnf install gcc python-devel krb5-devel

# To add NTLM to the GSSAPI SPNEGO auth run
dnf install gssntlmssp
```

For Arch Linux

```bash
pacman -S gcc krb5
```

Once installed you can install the Python packages with

```bash
pip install pypsrp[kerberos]
```

Kerberos also needs to be configured to talk to the domain but that is outside the scope of this page.

### SSH Connections

The SSH connection on `psrp` requires the `asyncssh` library to be installed.

```bash
pip install pypsrp[ssh]
```

### Named Pipe Connections

The Named Pipe connection on `psrp` requires the `psutil` library to be installed.

```bash
pip install pypsrp[named_pipe]
```


## How to Use

There are 3 main components that are in use within this library:

* `ConnectionInfo`: Defines the connection type and connection specific variables
* `RunspacePool`: The Runspace Pool contains a pool of pipelines that can be run on the remote target
* `Pipeline`: The code to run inside the Runspace Pool

### ConnectionInfo

These are the connection info types that are supported by `pypsrp`

|Type|Sync|Asyncio|Mandatory Requirements|Optional Requirements|
|-|-|-|-|-|
|[WSManInfo](./src/psrp/_connection/wsman.py)|Y|Y|N/A|`pypsrp[kerberos]` for Kerberos support|
|[ProcessInfo](./src/psrp/_connection/process.py)|Y|Y|N/A|N/A|
|[SSHInfo](./src/psrp/_connection/ssh.py)|N|Y|`pypsrp[ssh]`|N/A|
|[NamedPipeInfo](./src/psrp/_connection/named_pipe.py)|N|Y|`pypsrp[named_pipe]`|N/A|

The mandatory requirements are requirements that must be installed on top of what `pypsrp` requires.
The optional requirements are requirements to utilise optional features that aren't available by default.

The connection info objects do not store the connections themselves, they just define how a Runspace Pool will connect to the target.
This means they can be reused across multiple pools as needed.

The `psrp.AsyncOutOfProcConnection` and `psrp.SyncOutOfProcConnection` can also be used to define your own out of process connection type.
This is fairly advanced work as it would require an implementation on both the client and server side.

### RunspacePool

The Runspace Pool is used to create the connection to the remote target and can host multiple pipelines that run code.
A Runspace Pool comes in 2 varieties:

* `psrp.SyncRunspacePool` - uses a synchronous connection
* `psrp.AsyncRunspacePool` - uses an asyncio based connection

Both of these types must be created with a `ConnectionInfo` that describes how to connect to the remote PowerShell instance.
See the table in ConnectionInfo to see what connections are supported by a syncronous Runspace Pool and an asyncronous Runspace Pool.


```python
import psrp

async def async_rp(conn: psrp.ConnectionInfo) -> None:
    async with psrp.AsyncRunspacePool(conn) as rp:
        ...


def sync_rp(conn: psrp.ConnectionInfo) -> None:
    with psrp.SyncRunspacePool(conn) as rp:
        ...
```

Both the sync and async Runspace Pool contain the same methods and functionality, the main difference is that most operations on the async pool are coroutines that need to be awaited.

### Pipeline

A Pipeline is used to execute a command or script on the Runspace Pool it is associated with.
There are 4 types of pipelines that can be used:

* `psrp.AsyncPowerShell` - runs a PowerShell command through asyncio
* `psrp.SyncPowerShell` - runs a PowerShell command through synchronous code
* `psrp.AsyncCommandMetaPipeline` - gets command metadata on the Runspace Pool through asyncio
* `psrp.SyncCommandMetaPipeline` - gets command metadata on the Runspace Pool through syncronous code

The PowerShell pipeline is the commonly used pipeline that can run PowerShell commands, statements, and/or scripts.


## Examples

### Running PowerShell script

```python
import psrp

async def async_rp(conn: psrp.ConnectionInfo) -> None:
    async with psrp.AsyncRunspacePool(conn) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script('echo "hi"')
        output = await ps.invoke()

        print(output)


def sync_rp(conn: psrp.ConnectionInfo) -> None:
    with psrp.SyncRunspacePool(conn) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script('echo "hi"')
        output = ps.invoke()

        print(output)
```

This will run a PowerShell script and print out the output from that script.
The output from `invoke()` is a list of PowerShell objects that are output from the remote pipeline.

### Run a PowerShell command

```python
import psrp

async def async_rp(conn: psrp.ConnectionInfo) -> None:
    async with psrp.AsyncRunspacePool(conn) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_command("Get-Process").add_command("Select-Object").add_parameter("Property", "Name")
        ps.add_statement()
        ps.add_command("Get-Service").add_argument("audiosrc")
        output = await ps.invoke()

        print(output)


def sync_rp(conn: psrp.ConnectionInfo) -> None:
    with psrp.SyncRunspacePool(conn) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_command("Get-Process").add_command("Select-Object").add_parameter("Property", "Name")
        ps.add_statement()
        ps.add_command("Get-Service").add_argument("audiosrc")
        output = ps.invoke()

        print(output)
```

This will run the PowerShell command `Get-Process | Select-Object -Property Name; Get-Service audiosrv`.
Each command in a statement are piped and parameters/arguments are added to the last command.
The statement will run as a separate line/statement in the script.

### Copy a file to the remote host

```python
import psrp

def copy_file(conn: psrp.ConnectionInfo) -> None:
    psrp.copy_file(conn, "/tmp/test.txt", r"C:\temp\test.txt")
```

Copies a local file to the remote PowerShell session.

_Note: There is no asyncio analogue for this operation due to a lack of asyncio file libraries in the stdlib._

### Fetches a file from the remote host

```python
import psrp

def fetch_file(conn: psrp.ConnectionInfo) -> None:
    psrp.fetch_file(conn, r"C:\temp\test.txt", "/tmp/test.txt")
```

Fetches a remote file to the local filesystem.

_Note: There is no asyncio analogue for this operation due to a lack of asyncio file libraries in the stdlib._

### Run script with high level API

```python
import psrp

async def async_invoke_ps(conn: psrp.ConnectionInfo, script: str) -> None:
    out, streams, had_errors = await psrp.async_invoke_ps(script)

    print(f"OUTPUT: {out}")
    if had_errors:
        errors = [str(e) for e in streams.error]
        print(f"ERROR: {errors}")



async def invoke_ps(conn: psrp.ConnectionInfo, script: str) -> None:
    out, streams, had_errors = psrp.invoke_ps(script)

    print(f"OUTPUT: {out}")
    if had_errors:
        errors = [str(e) for e in streams.error]
        print(f"ERROR: {errors}")
```

Uses the high level API to execute a PowerShell script and print out any errors that are returned.


## Logging

This library takes advantage of the Python logging configuration and messages are logged to the following named loggers

* `psrp.*` - The loggers for code under the `psrp` namespace
* `pypsrp.*` - The loggers for the code under the legacy `pypsrp` namespace

_Note: `DEBUG` contains a lot of information and will output all the messages
sent to and from the client. This can have the side effect of leaking sensitive
information and should only be used for debugging purposes._


## Testing

Any changes are more than welcome in pull request form, you can run the current test suite with tox like so;

```bash
# make sure tox is installed
pip install tox

# run the tox suite
tox

# or run the test manually for the current Python environment
python -m pytest tests/tests_psrp -v --cov psrp --cov-report term-missing
```

A lot of the tests either simulate a remote Windows host but you can also run a
lot of them against a real Windows host. To do this, set the following
environment variables before running the tests;

* `PYPSRP_SERVER`: The hostname or IP of the remote host to test WSMan with
* `PYPSRP_USERNAME`: The username to use with WSMan
* `PYPSRP_PASSWORD`: The password to use with WSMan
* `PYPSRR_PORT`: The port to connect with over WSMan (default: `5985`)
* `PYPSRP_AUTH`: The authentication protocol to auth with (default: `negotiate`)
* `PYPSRP_SSH_SERVER`: The hostname or IP of the remote host to test SSH with
* `PYPSRP_SSH_USERNAME`: The username to use with SSH
* `PYPSRP_SSH_PASSWORD`: The password to use with SSH
* `PYPSRP_SSH_KEY_PATH`: The path to a private key to use with SSH
* `PYPSRP_SSH_IS_WINDOWS`: The remote SSH target is a Windows host
