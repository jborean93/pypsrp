# Changelog

## 0.3.1 - 2019-02-26

* Fix issue where `negotiate_delegate=True` did nothing with `pywin32` on Windows
* Fix instances of invalid escape sequences in strings that will break in future Python versions - https://bugs.python.org/issue27364
* Added warning if requests version is older than 2.14.0 as it does not support status retries. Pypsrp will continue but without supporting status retries.
* Fix byte ordering for the PID and RPID values of each PSRP message. This should not be an existing issue on normal hosts but it will make the move to SSH easier in the future
* Support using a direct IPv6 address as the server name
* Manually get Kerberos ticket if the one in the cache has expired and the password is set
* Added explicit documentation to state that on MacOS/Heimdal KRB5 implementations, the Kerberos ticket will persist after running


## 0.3.0 - 2018-11-14

* Added `FEATURE` dict to module to denote whether a feature has been added in installed pypsrp
* Added `read_timeout` to `pypsrp.wsman.WSMan` to control the timeout when waiting for a HTTP response from the server
* Added `reconnection_retries` and `reconnection_backoff` to control reconnection attempts on connection failures
* Changed a few log entries from `info` to `debug` as some of those log entries were quite verbose


## 0.2.0 - 2018-09-11

* Fix issue when deserialising a circular reference in a PSRP object
* Added the ability to specify the `Locale` and `DataLocale` values when creating the `WSMan` object
* Update the max envelope size default if the negotiated version is greater than or equal to `2.2` (PowerShell v3+)


## 0.1.0 - 2018-07-13

Initial release of pypsrp, it contains the following features

* Basic Windows Remote Shell over WinRM to execute raw cmd command or processes
* Various WSMan methods that can be used to execute WSMan commands
* A mostly complete implementation of the PowerShell Remoting Protocol that mimics the .NET System.Management.Automation.Runspaces interface
* Support for a reference host base implementation of PSRP for interactive scripts
* Support for all WinRM authentication protocols like Basic, Certificate, Negotiate, Kerberos, and CredSSP
* Implementation of the Windows Negotiate auth protocol to negotiate between NTLM and Kerberos auth
* Support for message encryption of HTTP with the Negotiate (NTLM/Kerberos) and CredSSP protocol
