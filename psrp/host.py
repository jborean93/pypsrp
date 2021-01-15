# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import functools
import typing

from .dotnet.complex_types import (
    ConsoleColor,
    Coordinates,
    HostDefaultData,
    HostInfo,
    HostMethodIdentifier,
    PSCredential,
    PSCredentialTypes,
    PSCredentialUIOptions,
    PSDict,
    PSGenericList,
    PSRPChoiceDescription,
    PSRPFieldDescription,
    Size,
)

from .dotnet.primitive_types import (
    PSBool,
    PSGuid,
    PSInt,
    PSInt64,
    PSSecureString,
    PSString,
    PSVersion,
)

from .dotnet.ps_base import (
    PSObject,
)

from .dotnet.psrp_messages import (
    ProgressRecord,
)

MethodMetadata = collections.namedtuple('MethodMetadata', ['is_void', 'invoke'])


class PSHost:

    def __init__(
            self,
            ui: typing.Optional['PSHostUI'] = None,
    ):
        self.ui = ui

    def get_host_info(self) -> HostInfo:
        """Get the PSRP HostInfo.

        Gets the PSRP HostInfo object for the current PSHost. This is called when creating the RunspacePool and
        Pipeline, if an explicit PSHost was specified.

        Returns:
            HostInfo: The HostInfo object that defines the current PSHost.
        """
        ui = self.ui
        raw_ui = ui.raw_ui if ui else None
        host_default_data = None
        if raw_ui:
            host_default_data = raw_ui.get_host_default_data()

        return HostInfo(
            is_host_null=False,
            is_host_ui_null=bool(ui is None),
            is_host_raw_ui_null=bool(raw_ui is None),
            use_runspace_host=False,
            host_default_data=host_default_data,
        )

    def get_name(self) -> PSString:
        """Name of the hosting application.

        This value reflects a user friendly identifier of the application hosting PowerShell. This value is only used
        locally and is never invoked by a remote HostCall event.

        Returns:
            PSString: The user friendly application identifier.
        """
        raise NotImplementedError()

    def get_version(self) -> PSVersion:
        """The host version.

        This value reflects the version number of the hosting application. This value is only used locally and is never
        invoked by a remote HostCall event.

        Returns:
            HostInfo: The hosting application version number.
        """
        raise NotImplementedError()

    def get_instance_id(self) -> PSGuid:
        """Unique ID for the host.

        This value reflects a unique identifier for the hosting application. This value is only used locally and is
        never invoked by a remote HostCall event.

        Returns:
            PSGuid: A GUID that uniquely identifies the hosting application.
        """
        raise NotImplementedError()

    def get_current_culture(self) -> PSString:
        """Host Culture.

        This value reflects the hosts culture value as a string. The value SHOULD be in the format as described by
        `ECMA-335`_. THis value is only used locally and is never invoked by a remote HostCall event.

        Returns:
            PSString: The hosts culture.

        .. _ECMA-335:
            https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf
        """
        raise NotImplementedError()

    def get_current_ui_culture(self) -> PSString:
        """Host UI Culture.

        This value reflects the hosts UI culture value as a string. The value SHOULD be in the format as described by
        `ECMA-335`_. THis value is only used locally and is never invoked by a remote HostCall event.

        Returns:
            PSString: The hosts UI culture.

        .. _ECMA-335:
            https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf
        """
        raise NotImplementedError()

    def set_should_exit(
            self,
            exit_code: PSInt,
    ):
        """Set should exit.

        This method is called when `$Host.SetShouldExit($int)` is called on the remote pipeline. When invoked locally
        the hosting application should shut down the hosting application and close the current runspace. When invoked
        through a remote HostCall event this just notifies the client the method was called and provides the exit
        code.

        Args:
            exit_code: The exit code that was passed into `$Host.SetShouldExit`.
        """
        raise NotImplementedError()

    def enter_nested_prompt(self):
        """Enter a nested prompt.

        This SHOULD interrupt the current pipeline and start a nested pipeline when called. This method is only used
        locally and is never invoked by a remote HostCall event.
        """
        raise NotImplementedError()

    def exit_nested_prompt(self):
        """Exit a nested prompt.

        This SHOULD stop the nested pipeline and resume the current pipeline. This method is only used locally and is
        never invoked by a remote HostCall event.
        """
        raise NotImplementedError()

    def notify_begin_application(self):
        raise NotImplementedError()

    def notify_end_application(self):
        raise NotImplementedError()

    def push_runspace(
            self,
            runspace: PSObject,
    ):
        raise NotImplementedError()

    def pop_runspace(self):
        raise NotImplementedError()

    def get_is_runspace_pushed(self) -> PSBool:
        raise NotImplementedError()

    def get_runspace(self) -> PSObject:
        raise NotImplementedError()


class PSHostUI:

    def __init__(
            self,
            raw_ui: typing.Optional['PSHostRawUI'] = None,
    ):
        self.raw_ui = raw_ui

    def read_line(self) -> PSString:
        raise NotImplementedError()

    def read_line_as_secure_string(self) -> PSSecureString:
        raise NotImplementedError()

    def write1(
            self,
            message: PSString,
    ):
        raise NotImplementedError()

    def write2(
            self,
            foreground_color: ConsoleColor,
            background_color: ConsoleColor,
            message: PSString,
    ):
        raise NotImplementedError()

    def write_line1(self):
        raise NotImplementedError()

    def write_line2(
            self,
            message: PSString,
    ):
        raise NotImplementedError()

    def write_line3(
            self,
            foreground_color: ConsoleColor,
            background_color: ConsoleColor,
            message: PSString,
    ):
        raise NotImplementedError()

    def write_error_line(
            self,
            message: PSString,
    ):
        raise NotImplementedError()

    def write_debug_line(
            self,
            message: PSString,
    ):
        raise NotImplementedError()

    def write_progress(
            self,
            source_id: PSInt64,
            record: ProgressRecord,
    ):
        raise NotImplementedError()

    def write_verbose_line(
            self,
            message: PSString,
    ):
        raise NotImplementedError()

    def write_warning_line(
            self,
            message: PSString,
    ):
        raise NotImplementedError()

    def prompt(
            self,
            caption: PSString,
            message: PSString,
            descriptions: PSGenericList[PSRPFieldDescription],
    ) -> PSDict:
        raise NotImplementedError()

    def prompt_for_credential(
            self,
            caption: PSString,
            message: PSString,
            user_name: PSString,
            target_name: PSString,
    ) -> PSCredential:
        raise NotImplementedError()

    def prompt_for_credential2(
            self,
            caption: PSString,
            message: PSString,
            user_name: PSString,
            target_name: PSString,
            allowed_credential_types: PSCredentialTypes,
            options: PSCredentialUIOptions,
    ) -> PSCredential:
        raise NotImplementedError()

    def prompt_for_choice(
            self,
            caption: PSString,
            message: PSString,
            choices: PSGenericList[PSRPChoiceDescription],
            default_choice: PSInt,
    ) -> PSInt:
        raise NotImplementedError()

    def prompt_for_choice_multiple_selection(
            self,
            caption: PSString,
            message: PSString,
            choices: PSGenericList[PSRPChoiceDescription],
            choice_choices: PSGenericList[PSInt],
    ) -> PSGenericList[PSInt]:
        raise NotImplementedError()


class PSHostRawUI:

    def get_host_default_data(self) -> HostDefaultData:
        """Get the PSRP HostDefaultData.

        Gets the PSRP HostDefaultData object for the current PSHostRawUI. This is called when creating the RunspacePool
        and Pipeline, if an explicit PSHost with a UI and RawUI implementation was specified.

        Returns:
            The HostDefaultData object that defines the host-related information.
        """
        return HostDefaultData(
            foreground_color=self.get_foreground_color(),
            background_color=self.get_background_color(),
            cursor_position=self.get_cursor_position(),
            window_position=self.get_window_position(),
            cursor_size=self.get_cursor_size(),
            buffer_size=self.get_buffer_size(),
            window_size=self.get_window_size(),
            max_window_size=self.get_max_window_size(),
            max_physical_window_size=self.get_max_physical_window_size(),
            window_title=self.get_window_title(),
        )

    def get_foreground_color(self) -> ConsoleColor:
        raise NotImplementedError()

    def set_foreground_color(
            self,
            value: ConsoleColor,
    ):
        raise NotImplementedError()

    def get_background_color(self) -> ConsoleColor:
        raise NotImplementedError()

    def set_background_color(
            self,
            value: ConsoleColor,
    ):
        raise NotImplementedError()

    def get_cursor_position(self) -> Coordinates:
        raise NotImplementedError()

    def set_cursor_position(
            self,
            value: Coordinates,
    ):
        raise NotImplementedError()

    def get_window_position(self) -> Coordinates:
        raise NotImplementedError()

    def set_window_position(
            self,
            value: Coordinates,
    ):
        raise NotImplementedError()

    def get_cursor_size(self) -> PSInt:
        raise NotImplementedError()

    def set_cursor_size(
            self,
            value: PSInt,
    ):
        raise NotImplementedError()

    def get_buffer_size(self) -> Size:
        raise NotImplementedError()

    def set_buffer_size(
            self,
            value: Size,
    ):
        raise NotImplementedError()

    def get_window_size(self) -> Size:
        raise NotImplementedError()

    def set_window_size(
            self,
            value: Size,
    ):
        raise NotImplementedError()

    def get_window_title(self) -> PSString:
        raise NotImplementedError()

    def set_window_title(
            self,
            value: PSString,
    ):
        raise NotImplementedError()

    def get_max_window_size(self) -> Size:
        raise NotImplementedError()

    def get_max_physical_window_size(self) -> Size:
        raise NotImplementedError()

    def get_key_available(self) -> PSBool:
        raise NotImplementedError()

    def read_key(self):
        raise NotImplementedError()

    def flush_input_buffer(self):
        raise NotImplementedError()

    def set_buffer_contents1(self):
        raise NotImplementedError()

    def set_buffer_contents2(self):
        raise NotImplementedError()

    def get_buffer_contents(self):
        raise NotImplementedError()

    def scroll_buffer_contents(self):
        raise NotImplementedError()


def get_host_method(
        host: PSHost,
        method_identifier: HostMethodIdentifier,
        method_parameters: typing.List,
) -> MethodMetadata:
    """Get a callable host method.

    Gets a callable host method that can be invoked from a remote host call.

    Args:
        host: The PSHost to invoke.
        method_identifier: The HostMethodIdentifier from the remote host call.
        method_parameters: The parameters from the remote host call.

    Returns:
        A tuple that contains a boolean `True` if the method does not return any value or `False` if it does and
        needs to be sent back to the remote host. The second value either `None` if the function was not defined
        on the host or a function to invoke that executes the remote host call.
    """
    name, is_void, host_type = {
        HostMethodIdentifier.GetName: ('get_name', False, 'host'),
        HostMethodIdentifier.GetVersion: ('get_version', False, 'host'),
        HostMethodIdentifier.GetInstanceId: ('get_instance_id', False, 'host'),
        HostMethodIdentifier.GetCurrentCulture: ('get_current_culture', False, 'host'),
        HostMethodIdentifier.GetCurrentUICulture: ('get_current_ui_culture', False, 'host'),
        HostMethodIdentifier.SetShouldExit: ('set_should_exit', True, 'host'),
        HostMethodIdentifier.EnterNestedPrompt: ('enter_nested_prompt', True, 'host'),
        HostMethodIdentifier.ExitNestedPrompt: ('exit_nested_prompt', True, 'host'),
        HostMethodIdentifier.NotifyBeginApplication: ('notify_begin_application', True, 'host'),
        HostMethodIdentifier.NotifyEndApplication: ('notify_end_application', True, 'host'),
        HostMethodIdentifier.PushRunspace: ('push_runspace', True, 'host'),
        HostMethodIdentifier.PopRunspace: ('pop_runspace', True, 'host'),
        HostMethodIdentifier.GetIsRunspacePushed: ('get_is_runspace_pushed', False, 'host'),
        HostMethodIdentifier.GetRunspace: ('get_runspace', False, 'host'),

        HostMethodIdentifier.ReadLine: ('read_line', False, 'ui'),
        HostMethodIdentifier.ReadLineAsSecureString: ('read_line_as_secure_string', False, 'ui'),
        HostMethodIdentifier.Write1: ('write1', True, 'ui'),
        HostMethodIdentifier.Write2: ('write2', True, 'ui'),
        HostMethodIdentifier.WriteLine1: ('write_line1', True, 'ui'),
        HostMethodIdentifier.WriteLine2: ('write_line2', True, 'ui'),
        HostMethodIdentifier.WriteLine3: ('write_line3', True, 'ui'),
        HostMethodIdentifier.WriteErrorLine: ('write_error_line', True, 'ui'),
        HostMethodIdentifier.WriteDebugLine: ('write_debug_line', True, 'ui'),
        HostMethodIdentifier.WriteProgress: ('write_progress', True, 'ui'),
        HostMethodIdentifier.WriteVerboseLine: ('write_verbose_line', True, 'ui'),
        HostMethodIdentifier.WriteWarningLine: ('write_warning_line', True, 'ui'),
        HostMethodIdentifier.Prompt: ('prompt', False, 'ui'),
        HostMethodIdentifier.PromptForCredential1: ('prompt_for_credential1', False, 'ui'),
        HostMethodIdentifier.PromptForCredential2: ('prompt_for_credential2', False, 'ui'),
        HostMethodIdentifier.PromptForChoice: ('prompt_for_choice', False, 'ui'),
        HostMethodIdentifier.PromptForChoiceMultipleSelection: ('prompt_for_choice_multiple_selection', False,
                                                                'ui'),

        HostMethodIdentifier.GetForegroundColor: ('get_foreground_color', False, 'raw_ui'),
        HostMethodIdentifier.SetForegroundColor: ('set_foreground_color', True, 'raw_ui'),
        HostMethodIdentifier.GetBackgroundColor: ('get_background_color', False, 'raw_ui'),
        HostMethodIdentifier.SetBackgroundColor: ('set_background_color', True, 'raw_ui'),
        HostMethodIdentifier.GetCursorPosition: ('get_cursor_position', False, 'raw_ui'),
        HostMethodIdentifier.SetCursorPosition: ('set_cursor_position', True, 'raw_ui'),
        HostMethodIdentifier.GetWindowPosition: ('get_window_position', False, 'raw_ui'),
        HostMethodIdentifier.SetWindowPosition: ('set_window_position', True, 'raw_ui'),
        HostMethodIdentifier.GetCursorSize: ('get_cursor_size', False, 'raw_ui'),
        HostMethodIdentifier.SetCursorSize: ('set_cursor_size', True, 'raw_ui'),
        HostMethodIdentifier.GetBufferSize: ('get_buffer_size', False, 'raw_ui'),
        HostMethodIdentifier.SetBufferSize: ('set_buffer_size', True, 'raw_ui'),
        HostMethodIdentifier.GetWindowSize: ('get_window_size', False, 'raw_ui'),
        HostMethodIdentifier.SetWindowSize: ('set_window_size', True, 'raw_ui'),
        HostMethodIdentifier.GetWindowTitle: ('get_window_title', False, 'raw_ui'),
        HostMethodIdentifier.SetWindowTitle: ('set_window_title', True, 'raw_ui'),
        HostMethodIdentifier.GetMaxWindowSize: ('get_max_window_size', False, 'raw_ui'),
        HostMethodIdentifier.GetMaxPhysicalWindowSize: ('get_max_physical_window_size', False, 'raw_ui'),
        HostMethodIdentifier.GetKeyAvailable: ('get_key_available', False, 'raw_ui'),
        HostMethodIdentifier.ReadKey: ('read_key', False, 'raw_ui'),
        HostMethodIdentifier.FlushInputBuffer: ('flush_input_buffer', True, 'raw_ui'),
        HostMethodIdentifier.SetBufferContents1: ('set_buffer_contents1', True, 'raw_ui'),
        HostMethodIdentifier.SetBufferContents2: ('set_buffer_contents2', True, 'raw_ui'),
        HostMethodIdentifier.GetBufferContents: ('get_buffer_contents', False, 'raw_ui'),
        HostMethodIdentifier.ScrollBufferContents: ('scroll_buffer_contents', True, 'raw_ui'),
    }[method_identifier]

    if host_type in ['ui', 'raw_ui']:
        ui = getattr(host, 'ui', None)
        if ui is None:
            return MethodMetadata(is_void, None)
        host = ui

    if host_type in ['raw_ui']:
        raw_ui = getattr(host, 'raw_ui', None)
        if raw_ui is None:
            return MethodMetadata(is_void, None)
        host = raw_ui

    raw_func = getattr(host, name, None)
    if raw_func is None:
        return MethodMetadata(is_void, None)

    # The parameters for these methods in a PSRP specific format that don't strictly match the public .NET types.
    # This converts the method parameters to the public types and make a PSHost implementation easier for end users to
    # build.
    if method_identifier in [HostMethodIdentifier.SetForegroundColor,
                             HostMethodIdentifier.SetBackgroundColor]:
        method_parameters = [ConsoleColor(method_parameters[0])]

    elif method_identifier in [HostMethodIdentifier.SetCursorPosition,
                               HostMethodIdentifier.SetWindowPosition]:
        raw_coordinate = method_parameters[0]
        method_parameters = [Coordinates(X=raw_coordinate.x, Y=raw_coordinate.y)]

    elif method_identifier in [HostMethodIdentifier.SetBufferSize,
                               HostMethodIdentifier.SetWindowSize]:
        raw_size = method_parameters[0]
        method_parameters = [Size(Height=raw_size.height, Width=raw_size.width)]

    func = functools.partial(raw_func, *method_parameters)

    return MethodMetadata(is_void, func)
