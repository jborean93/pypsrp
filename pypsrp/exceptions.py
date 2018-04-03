# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


class WinRMError(Exception):
    # Base WinRM Error
    pass


class AuthenticationError(WinRMError):
    # Used when the user failed to authenticate
    pass


class WinRMTransportError(WinRMError):
    # An error occurred during the transport stage

    @property
    def protocol(self):
        return self.args[0]

    @property
    def code(self):
        return self.args[1]

    @property
    def response_text(self):
        return self.args[2]

    @property
    def message(self):
        return "Bad %s response returned from the server. Code: %d, " \
               "Content: %s"\
               % (self.protocol.upper(), self.code, self.response_text)

    def __str__(self):
        return self.message


class WSManFaultError(WinRMError):
    # Contains the WSManFault information if a WSManFault was received

    @property
    def code(self):
        return self.args[0]

    @property
    def machine(self):
        return self.args[1]

    @property
    def reason(self):
        return self.args[2]

    @property
    def provider(self):
        return self.args[3]

    @property
    def provider_path(self):
        return self.args[4]

    @property
    def provider_fault(self):
        return self.args[5]

    @property
    def message(self):
        error_details = []
        if self.code:
            error_details.append("Code: %s" % self.code)

        if self.machine:
            error_details.append("Machine: %s" % self.machine)

        if self.reason:
            error_details.append("Reason: %s" % self.reason)

        if self.provider:
            error_details.append("Provider: %s" % self.provider)

        if self.provider_path:
            error_details.append("Provider Path: %s" % self.provider_path)

        if self.provider_fault:
            error_details.append("Provider Fault: %s" % self.provider_fault)

        if len(error_details) == 0:
            error_details.append("No details returned by the server")

        error_msg = "Received a WSManFault message. (%s)" \
                    % ", ".join(error_details)
        return error_msg

    def __str__(self):
        return self.message
