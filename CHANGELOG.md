# Changelog

## 0.3.0 - TBD

* Added support for PSRP over SSH, can be installed with `pip install pypsrp[ssh]`
* Removed the `shell` attribute on a `RunspacePool` class, this is only used by WSMan and is not relevant to other transport options
* Reply to https://github.com/PowerShell/PowerShell/issues/7921#issuecomment-427504126
#TODO: only show latest exception in WSManFault message https://stackoverflow.com/questions/1350671/inner-exception-with-traceback-in-python

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
