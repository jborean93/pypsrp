# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import functools
import typing as t
import uuid

from psrpcore import ClientHostResponder
from psrpcore.types import (
    BufferCell,
    ChoiceDescription,
    ConsoleColor,
    Coordinates,
    FieldDescription,
    HostDefaultData,
    HostInfo,
    HostMethodIdentifier,
    KeyInfo,
    ProgressRecordType,
    PSChar,
    PSCredential,
    PSCredentialTypes,
    PSCredentialUIOptions,
    PSSecureString,
    PSVersion,
    ReadKeyOptions,
    Size,
)


class MethodMetadata(t.NamedTuple):
    invoke: t.Callable  #: The callable that invokes the host method, None if the method was not found.
    format_return: t.Optional[t.Callable]  #: Callable that will process the response if expected by the server.


class PSHost:
    def __init__(
        self,
        ui: t.Optional["PSHostUI"] = None,
    ) -> None:
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
            IsHostNull=False,
            IsHostUINull=bool(ui is None),
            IsHostRawUINull=bool(raw_ui is None),
            UseRunspaceHost=False,
            HostDefaultData=host_default_data,
        )

    def get_name(
        self,
    ) -> str:
        """GetName Host Call.

        Gets the hosting application's identification in some user-friendly
        fashion. THis name can be referenced by scripts and cmdlets to identify
        the host that is executing them. The format of this value is not
        defined, but a short, simple string is recommended.

        This corresponds to the `PSHost.Name Property`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        Returns:
            str: The name identifier of the hosting application.

        .. _PSHost.Name Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.name
        """
        raise NotImplementedError()  # pragma: no cover

    def get_version(
        self,
    ) -> PSVersion:
        """GetVersion Host Call.

        Gets the version of the hosting application. This value should remain
        invariant for a particular build of the host. This value may be
        referenced by scripts and cmdlets.

        This corresponds to the `PSHost.Version Property`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        Returns:
            PSVersion: The version number of the hosting application.

        .. _PSHost.Version Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.version
        """
        raise NotImplementedError()  # pragma: no cover

    def get_instance_id(
        self,
    ) -> uuid.UUID:
        """GetInstanceId Host Call.

        Gets a GUID that uniquely identifies this instance of the host. The
        value should remain invariant for the lifetime of this instance.

        This corresponds to the `PSHost.InstanceId Property`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        Returns:
            uuid.UUID: The host instance identifier.

        .. _PSHost.InstanceId Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.instanceid
        """
        raise NotImplementedError()  # pragma: no cover

    def get_current_culture(
        self,
    ) -> str:
        """GetCurrentCulture Host Call.

        Gets the host's culture: the culture that the runspace should use to
        set the current culture on new threads.

        This value reflects the hosts culture value as a string. The value
        SHOULD be in the format as described by `ECMA-335`_.

        This corresponds to the `PSHost.CurrentCulture Property`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        Returns:
            str: The hosts current culture value.

        .. _ECMA-335:
            https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf

        .. _PSHost.CurrentCulture Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.currentculture
        """
        raise NotImplementedError()  # pragma: no cover

    def get_current_ui_culture(
        self,
    ) -> int:
        """GetCurrentUICulture Host Call.

        Gets the host's UI culture: the culture that the runspace and cmdlets
        should use to do resource loading.

        This value reflects the hosts culture value as a string. The value
        SHOULD be in the format as described by `ECMA-335`_.

        This corresponds to the `PSHost.CurrentUICulture Property`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        Returns:
            str: The hosts current UI culture value.

        .. _PSHost.CurrentUICulture Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.currentuiculture
        """
        raise NotImplementedError()  # pragma: no cover

    def set_should_exit(
        self,
        exit_code: int,
    ) -> None:
        """SetShouldExit Host Call.

        Requests by the engine to end the current engine runspace (to shut down
        and termiante the host's root runspace).

        This corresponds to the `PSHost.SetShouldExit Method`_.

        Args:
            exit_code: The exit code accompanying the exit keyword.

        .. _PSHost.SetShouldExit Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.setshouldexit
        """
        raise NotImplementedError()  # pragma: no cover

    def enter_nested_prompt(
        self,
    ) -> None:
        """EnterNestedPrompt Host Call.

        Instructs the host to interrupt the currently running pipeline and
        start a new, "nested" input loop, where an input loop is the cycle of
        prompt, input, and execute.

        This corresponds to the `PSHost.EnterNestedPrompt Method`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        .. _PSHost.EnterNestedPrompt Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.enternestedprompt
        """
        raise NotImplementedError()  # pragma: no cover

    def exit_nested_prompt(
        self,
    ) -> None:
        """ExitNestedPrompt Host Call.

        Causes the host to end the currently running input loop. If the input
        loop was created by a prior call to :meth:`enter_nested_prompt`, the
        enclosing pipeline will be resumed. If the current input loop is the
        top-most loop, then the host will act as through
        :meth:`set_should_exit` was called.

        This corresponds to the `PSHost.ExitNestedPrompt Method`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        .. _PSHost.ExitNestedPrompt Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.exitnestedprompt
        """
        raise NotImplementedError()  # pragma: no cover

    def notify_begin_application(
        self,
    ) -> None:
        """NotifyBeginApplication Host Call.

        Called by the engine to notify the host that it is about to execute a
        "legacy" command line application. A legacy application is defined as a
        console-mode executable that may do one or more of the following:

            * reads from stdin
            * writes to stdout
            * writes to stderr

        The engine will always call this method and
        :meth:`notify_end_application()` in pairs.

        This corresponds to the `PSHost.NotifyBeginApplication Method`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        .. _PSHost.NotifyBeginApplication Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.notifybeginapplication
        """
        raise NotImplementedError()  # pragma: no cover

    def notify_end_application(
        self,
    ) -> None:
        """NotifyEndApplication Host Call.

        Called by the engine to notify the host that the execution of a legacy
        command has completed.

        The engine will always call this method and
        :meth:`notify_begin_application()` in pairs.

        This corresponds to the `PSHost.NotifyEndApplication Method`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        .. _PSHost.NotifyEndApplication Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshost.notifyendapplication
        """
        raise NotImplementedError()  # pragma: no cover


class PSHostUI:
    def __init__(
        self,
        raw_ui: t.Optional["PSHostRawUI"] = None,
    ):
        self.raw_ui = raw_ui

    def read_line(
        self,
    ) -> str:
        """ReadLine Host Call.

        Reads characters from the console until a newline is encountered.

        This corresponds to the `PSHostUserInterface.ReadLine Method`_.

        Returns:
            str: The characters typed by the user.

        .. _PSHostUserInterface.ReadLine Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.readline
        """
        raise NotImplementedError()  # pragma: no cover

    def read_line_as_secure_string(
        self,
    ) -> PSSecureString:
        """ReadLineAsSecureString Host Call.

        Same as :meth:`read_line`, except that the result is a secure string
        and that the input is not echoed to the user while it is collected.

        This corresponds to the
        `PSHostUserInterface.ReadLineAsSecureString Method`_.

        Returns:
            PSSecureString: The characters typed by the user as a secure string.

        .. _PSHostUserInterface.ReadLineAsSecureString Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.readlineassecurestring
        """
        raise NotImplementedError()  # pragma: no cover

    def write(
        self,
        value: str,
        foreground_color: t.Optional[ConsoleColor] = None,
        background_color: t.Optional[ConsoleColor] = None,
    ) -> None:
        """Write Host Call.

        Writes characters to the screen buffer. Does not append a carriage
        return.

        This corresponds to the `PSHostUserInterface.Write Method`_.

        Args:
            value: The characters to write.
            foreground_color: The color to display the text with.
            background_color: The color to display the background with.

        .. _PSHostUserInterface.Write Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.write
        """
        raise NotImplementedError()  # pragma: no cover

    def write_line(
        self,
        line: t.Optional[str] = None,
        foreground_color: t.Optional[ConsoleColor] = None,
        background_color: t.Optional[ConsoleColor] = None,
    ) -> None:
        """WriteLine Host Call.

        Writes a line to the output display.

        This corresponds to the `PSHostUserInterface.WriteLine Method`_.

        Args:
            line: The line to write, if not set then just a newline is written.
            foreground_color: The color to display the line with.
            background_color: The color to display the background with.

        .. _PSHostUserInterface.WriteLine Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.writeline
        """
        raise NotImplementedError()  # pragma: no cover

    def write_error_line(
        self,
        line: str,
    ) -> None:
        """WriteErrorLine Host Call.

        Writes a line to the error display of the host, as opposed to the
        output display.

        This corresponds to the `PSHostUserInterface.WriteErrorLine Method`_.

        Args:
            line: The line to write to the error display.

        .. _PSHostUserInterface.WriteErrorLine Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.writeerrorline
        """
        raise NotImplementedError()  # pragma: no cover

    def write_debug_line(
        self,
        line: str,
    ) -> None:
        """WriteDebugLine Host Call.

        Displays a debug message to the user.

        This corresponds to the `PSHostUserInterface.WriteDebugLine Method`_.

        Args:
            line: The debug line to write to the display.

        .. _PSHostUserInterface.WriteDebugLine Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.writedebugline
        """
        raise NotImplementedError()  # pragma: no cover

    def write_progress(
        self,
        source_id: int,
        activity_id: int,
        activity: str,
        status_description: str,
        current_operation: t.Optional[str] = None,
        parent_activity_id: int = -1,
        percent_complete: int = -1,
        record_type: ProgressRecordType = ProgressRecordType.Processing,
        seconds_remaining: int = -1,
    ) -> None:
        """WriteProgress Host Call.

        Displays a progress record to the user.

        This corresponds to the `PSHostUserInterface.WriteProgress Method`_.

        Args:
            source_id: Unique identifier of the source of the record.
            activity: The description of the activity for which progress is
                being reported.
            activity_id: The Id of the activity to which this record
                corresponds. Used as a key for linking of subordinate
                activities.
            status_description: Current status of the operation, e.g.
                "35 of 50 items copied.".
            current_operation: Current operation of the many required to
                accomplish the activity, e.g. "copying foo.txt".
            parent_activity_id: The Id of the activity for which this record is
                a subordinate.
            percent_complete: The estimate of the percentage of total work for
                the activity that is completed. Set to a negative value to
                indicate that the percentage completed should not be displayed.
            record_type: The type of record represented.
            seconds_remaining: The estimate of time remaining until this
                activity is completed. Set to a negative value to indicate that
                the seconds remaining should not be displayed.

        .. _PSHostUserInterface.WriteProgress Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.writeprogress
        """
        raise NotImplementedError()  # pragma: no cover

    def write_verbose_line(
        self,
        line: str,
    ) -> None:
        """WriteVerboseLine Host Call.

        Displays a verbose processing message to the user.

        This corresponds to the `PSHostUserInterface.WriteVerboseLine Method`_.

        Args:
            line: The verbose line to write to the display.

        .. _PSHostUserInterface.WriteVerboseLine Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.writeverboseline
        """
        raise NotImplementedError()  # pragma: no cover

    def write_warning_line(
        self,
        line: str,
    ) -> None:
        """WriteWarningLine Host Call.

        Displays a warning processing message to the user.

        This corresponds to the `PSHostUserInterface.WriteWarningLine Method`_.

        Args:
            line: The warning line to write to the display.

        .. _PSHostUserInterface.WriteWarningLine Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.writewarningline
        """
        raise NotImplementedError()  # pragma: no cover

    def prompt(
        self,
        caption: str,
        message: str,
        descriptions: t.List[FieldDescription],
    ) -> t.Dict[str, t.Any]:
        """Prompt Host Call.

        Constructs a dialog where the user is presented with a number of fields
        for which to supply values.

        This corresponds to the `PSHostUserInterface.Prompt Method`_.

        Args:
            caption: The caption or title for the prompt.
            message: The message describing the set of fields.
            descriptions: A list of fields to display.

        Returns:
            Dict[str, Any]: All the options with the key being in field name
            from the input descriptions and the value being the value for that
            field.

        .. _PSHostUserInterface.Prompt Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.prompt
        """
        raise NotImplementedError()  # pragma: no cover

    def prompt_for_credential(
        self,
        caption: str,
        message: str,
        username: t.Optional[str] = None,
        target_name: t.Optional[str] = None,
        allowed_credential_types: t.Optional[PSCredentialTypes] = None,
        options: t.Optional[PSCredentialUIOptions] = None,
    ) -> PSCredential:
        """PromptForCredential Host Call.

        Prompt for credentials.

        This corresponds to the
        `PSHostUserInterface.PromptForCredential Method`_.

        Args:
            caption: The caption or title for the prompt.
            message: The message describing the credential required.
            username: The username the credential is for, if omitted or
                None/empty the username is requested in the prompt.
            target_name: The domain part of the username if set.
            allowed_credential_types: The types of credential that is being
                requested.
            options: Options to control the UI behaviour.

        Returns:
            PSCredential: The credential specified by the user.

        .. _PSHostUserInterface.PromptForCredential Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.promptforcredential
        """
        raise NotImplementedError()  # pragma: no cover

    def prompt_for_choice(
        self,
        caption: str,
        message: str,
        choices: t.List[ChoiceDescription],
        default_choice: int = -1,
    ) -> int:
        """PromptForChoice Host Call.

        Presents a dialog allowing the user to choose an option from a set of
        options.

        This corresponds to the `PSHostUserInterface.PromptForChoice Method`_.
        See :meth:`prompt_for_multiple_choice` for a way to allow the user to
        select multiple choices.

        Args:
            caption: The caption or title for the prompt.
            message: The message describing the set of choices.
            choices: A list of choices.
            default_choice: The default choice that correspond to the index of
                choices, ``-1`` means no default.

        Returns:
            int: The index of the choice that was selected.

        .. _PSHostUserInterface.PromptForChoice Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface.promptforchoice
        """
        raise NotImplementedError()  # pragma: no cover

    def prompt_for_multiple_choice(
        self,
        caption: str,
        message: str,
        choices: t.List[ChoiceDescription],
        default_choices: t.Optional[t.List[int]] = None,
    ) -> t.List[int]:
        """PromptForChoiceMultipleSelection Host Call.

        Presents a dialog allowing the user to choose options from a set of
        options.

        This corresponds to the
        `IHostUISupportsMultipleChoiceSelection.PromptForChoice Method`_.

        Args:
            caption: The caption or title for the prompt.
            message: The message describing the set of choices.
            choices: A list of choices.
            default_choices: A list of default choice that correspond to the index of
                choices.

        Returns:
            List[int]: The choices selected based on their index.

        .. _IHostUISupportsMultipleChoiceSelection.PromptForChoice Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.ihostuisupportsmultiplechoiceselection.promptforchoice
        """
        raise NotImplementedError()  # pragma: no cover


class PSHostRawUI:
    def get_host_default_data(self) -> HostDefaultData:
        """Get the PSRP HostDefaultData.

        Gets the PSRP HostDefaultData object for the current PSHostRawUI. This
        is called when creating the RunspacePool and Pipeline, if an explicit
        PSHost with a UI and RawUI implementation was specified.

        Returns:
            The HostDefaultData object that defines the host-related information.
        """
        return HostDefaultData(
            ForegroundColor=self.get_foreground_color(),
            BackgroundColor=self.get_background_color(),
            CursorPosition=self.get_cursor_position(),
            WindowPosition=self.get_window_position(),
            CursorSize=self.get_cursor_size(),
            BufferSize=self.get_buffer_size(),
            WindowSize=self.get_window_size(),
            MaxWindowSize=self.get_max_window_size(),
            MaxPhysicalWindowSize=self.get_max_physical_window_size(),
            WindowTitle=self.get_window_title(),
        )

    def get_foreground_color(
        self,
    ) -> ConsoleColor:
        """GetForegroundColor Host Call.

        Requests the foreground color of the host.

        This corresponds to the
        `PSHostRawUserInterface.ForegroundColor Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            ConsoleColor: The foreground color of the host.

        .. _PSHostRawUserInterface.ForegroundColor Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.foregroundcolor
        """
        raise NotImplementedError()  # pragma: no cover

    def set_foreground_color(
        self,
        color: ConsoleColor,
    ) -> None:
        """SetForegroundColor Host Call.

        Sets the foreground color of the host.

        This corresponds to the
        `PSHostRawUserInterface.ForegroundColor Property`_.

        Args:
            color: The color to set the foreground color to.

        .. _PSHostRawUserInterface.ForegroundColor Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.foregroundcolor
        """
        raise NotImplementedError()  # pragma: no cover

    def get_background_color(
        self,
    ) -> ConsoleColor:
        """GetBackgroundColor Host Call

        Requests the background color of the host.

        This corresponds to the
        `PSHostRawUserInterface.BackgroundColor Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            ConsoleColor: The background color of the host.

        .. _PSHostRawUserInterface.BackgroundColor Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.backgroundcolor
        """
        raise NotImplementedError()  # pragma: no cover

    def set_background_color(
        self,
        color: ConsoleColor,
    ) -> None:
        """SetBackgroundColor Host Call.

        Sets the background color of the host.

        This corresponds to the
        `PSHostRawUserInterface.BackgroundColor Property`_.

        Args:
            color: The color to set the background color to.

        .. _PSHostRawUserInterface.BackgroundColor Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.backgroundcolor
        """
        raise NotImplementedError()  # pragma: no cover

    def get_cursor_position(
        self,
    ) -> Coordinates:
        """GetCursorPosition Host Call.

        Gets the cursor position in the screen buffer.

        This corresponds to the
        `PSHostRawUserInterface.CursorPosition Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            Coordinates: The cursor position.

        .. _PSHostRawUserInterface.CursorPosition Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.cursorposition
        """
        raise NotImplementedError()  # pragma: no cover

    def set_cursor_position(
        self,
        x: int,
        y: int,
    ) -> None:
        """SetCursorPosition Host Call.

        Sets the cursor position in the screen buffer.

        This corresponds to the
        `PSHostRawUserInterface.CursorPosition Property`_.

        Args:
            x: The horizontal location to set the cursor to.
            y: The vertical location to set the cursor to.

        .. _PSHostRawUserInterface.CursorPosition Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.cursorposition
        """
        raise NotImplementedError()  # pragma: no cover

    def get_window_position(
        self,
    ) -> Coordinates:
        """GetWindowPosition Host Call.

        Gets the position of the view window relative to the screen buffer, in
        characters. 0, 0 is the upper left of the screen buffer.

        This corresponds to the
        `PSHostRawUserInterface.WindowPosition Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            Coordinates: The window position.

        .. _PSHostRawUserInterface.WindowPosition Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.windowposition
        """
        raise NotImplementedError()  # pragma: no cover

    def set_window_position(
        self,
        x: int,
        y: int,
    ) -> None:
        """SetWindowPosition Host Call.

        Sets the window position in the screen buffer.

        This corresponds to the
        `PSHostRawUserInterface.WindowPosition Property`_.

        Args:
            x: The horizontal location to set the window to.
            y: The vertical location to set the window to.

        .. _PSHostRawUserInterface.WindowPosition Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.windowposition
        """
        raise NotImplementedError()  # pragma: no cover

    def get_cursor_size(
        self,
    ) -> int:
        """GetCursorSize Host Call.

        Gets the cursor size as a percentage.

        This corresponds to the
        `PSHostRawUserInterface.CursorSize Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            int: The cursor size as a percentage.

        .. _PSHostRawUserInterface.CursorSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.cursorsize
        """
        raise NotImplementedError()  # pragma: no cover

    def set_cursor_size(
        self,
        size: int,
    ) -> None:
        """SetCursorSize Host Call.

        Sets the cursor size as a percentage.

        This corresponds to the
        `PSHostRawUserInterface.CursorSize Property`_.

        Args:
            size: The cursor size as a percentage.

        .. _PSHostRawUserInterface.CursorSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.cursorsize
        """
        raise NotImplementedError()  # pragma: no cover

    def get_buffer_size(
        self,
    ) -> Size:
        """GetBufferSize Host Call.

        Gets the current size of the screen buffer, measured in character cells.

        This corresponds to the
        `PSHostRawUserInterface.BufferSize Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            Size: The buffer size.

        .. _PSHostRawUserInterface.BufferSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.buffersize
        """
        raise NotImplementedError()  # pragma: no cover

    def set_buffer_size(
        self,
        width: int,
        height: int,
    ) -> None:
        """SetBufferSize Host Call.

        Sets the current size of the screen buffer, measures in character
        cells.

        This corresponds to the
        `PSHostRawUserInterface.BufferSize Property`_.

        Args:
            width: The number of cells in the buffer width.
            height: The number of cells in the buffer height.

        .. _PSHostRawUserInterface.BufferSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.buffersize
        """
        raise NotImplementedError()  # pragma: no cover

    def get_window_size(
        self,
    ) -> Size:
        """GetWindowSize Host Call.

        Gets the current view window size, measured in character cells. The
        window size cannot be alrger than the dimensions returned by
        :meth:`get_max_physical_window_size`.

        This corresponds to the
        `PSHostRawUserInterface.WindowSize Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            Size: The window size.

        .. _PSHostRawUserInterface.WindowSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.windowsize
        """
        raise NotImplementedError()  # pragma: no cover

    def set_window_size(
        self,
        width: int,
        height: int,
    ) -> None:
        """SetWindowSize Host Call.

        Sets the current view window size, measured in character cells. The
        window size cannot be larger than the dimensions returned by
        :meth:`get_max_physical_window_size`.

        This corresponds to the
        `PSHostRawUserInterface.WindowSize Property`_.

        Args:
            width: The number of cells in the view window width.
            height: The number of cells in the view window height.

        .. _PSHostRawUserInterface.WindowSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.windowsize
        """
        raise NotImplementedError()  # pragma: no cover

    def get_window_title(
        self,
    ) -> str:
        """GetWindowTitle Host Call.

        Gets the titlebar text of the current view window.

        This corresponds to the
        `PSHostRawUserInterface.WindowTitle Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            str: The titlebar of the current view window.

        .. _PSHostRawUserInterface.WindowTitle Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.windowtitle
        """
        raise NotImplementedError()  # pragma: no cover

    def set_window_title(
        self,
        title: str,
    ) -> None:
        """SetWindowTitle Host Call.

        Sets the titlebar text of the current view window.

        This corresponds to the
        `PSHostRawUserInterface.WindowTitle Property`_.

        Args:
            title: The title to set the host window to.

        .. _PSHostRawUserInterface.WindowTitle Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.windowtitle
        """
        raise NotImplementedError()  # pragma: no cover

    def get_max_window_size(
        self,
    ) -> Size:
        """GetMaxWindowSize Host Call.

        Gets the size of the largest window possible for the current buffer,
        current font, and current display hardware. The view window cannot be
        larger than the screen buffer or the current display.

        This corresponds to the
        `PSHostRawUserInterface.MaxWindowSize Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            Size: The size of the largest window possible for the current
                buffer.

        .. _PSHostRawUserInterface.MaxWindowSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.maxwindowsize
        """
        raise NotImplementedError()  # pragma: no cover

    def get_max_physical_window_size(
        self,
    ) -> Size:
        """GetMaxPhysicalWindowSize Host Call.

        Gets the largest window possible for the current font and display
        hardware, ignoring the current buffer dimensions.

        This corresponds to the
        `PSHostRawUserInterface.MaxPhysicalWindowSize Property`_.

        Note:
            This value is cached on the server side based on the host default
            data provided during Runspace Pool or Pipeline creation. It is not
            expected for a server to request this as part of a host call request.

        Returns:
            Size: The size of the largest window possible.

        .. _PSHostRawUserInterface.MaxPhysicalWindowSize Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.maxphysicalwindowsize
        """
        raise NotImplementedError()  # pragma: no cover

    def get_key_available(
        self,
    ) -> bool:
        """GetKeyAvailable Host Call.

        A non-blocking call to examine if a keystroke is waiting in the input
        buffer.

        This corresponds to the
        `PSHostRawUserInterface.KeyAvailable Property`_.

        Note:
            This value is only used locally and is never invoked by a remote
            host call.

        Returns:
            bool: Whether a keystroke is waiting in the input buffer.

        .. _PSHostRawUserInterface.KeyAvailable Property:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.keyavailable
        """
        raise NotImplementedError()  # pragma: no cover

    def read_key(
        self,
        options: ReadKeyOptions = ReadKeyOptions.IncludeKeyDown,
    ) -> KeyInfo:
        """ReadKey Host Call.

        Reads a key stroke from the keyboard device, blocking until a keystroke
        is typed.

        This corresponds to the
        `PSHostRawUserInterface.ReadKey Method`_.

        Args:
            options: Further options to control the read key operation.

        Returns:
            KeyInfo: The key stroke when a key is pressed.

        .. _PSHostRawUserInterface.ReadKey Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.readkey
        """
        raise NotImplementedError()  # pragma: no cover

    def flush_input_buffer(
        self,
    ) -> None:
        """FlushInputBuffer Host Call.

        Resets the keyboard input buffer.

        This corresponds to the
        `PSHostRawUserInterface.FlushInputBuffer Method`_.

        .. _PSHostRawUserInterface.FlushInputBuffer Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.flushinputbuffer
        """
        raise NotImplementedError()  # pragma: no cover

    def set_buffer_cells(
        self,
        left: int,
        top: int,
        right: int,
        bottom: int,
        character: PSChar,
        foreground: ConsoleColor = ConsoleColor.White,
        background: ConsoleColor = ConsoleColor.Black,
    ) -> None:
        """SetBufferContents Host Call.

        Copies a given character to all of the character cells in the screen
        buffer with the indicated colors.

        This corresponds to the
        `PSHostRawUserInterface.SetBufferContents Method`_. See
        :meth:`set_buffer_contents` to set the buffer contents by individual
        cells.

        Args:
            left: The left margin of the region to set the cell to.
            top: The top margin of the region to set the cell to.
            right: The right margin of the region to set the cell to.
            bottom: The bottom margin of the region to set the cell to.
            character: The character used to fill the cells in the region
                specified.
            foreground: The foreground (text) color to fill the cells in the
                region specified.
            background: The background color to fill the cells in the region
                specified.

        .. _PSHostRawUserInterface.SetBufferContents Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.setbuffercontents
        """
        raise NotImplementedError()  # pragma: no cover

    def set_buffer_contents(
        self,
        x: int,
        y: int,
        contents: t.List[t.List[BufferCell]],
    ) -> None:
        """SetBufferContents Host Call.

        Copies the buffer cell array into the screen buffer at the given
        origin, clipping such that cells in the array that would fall outside
        the screen buffer are ignored.

        The ``contents`` value is a list of a list of
        :class:`psrpcore.types.BufferCell` where the first list dimension
        represents each row and the 2nd dimension is each column of that row.

        This corresponds to the
        `PSHostRawUserInterface.SetBufferContents Method`_. See
        :meth:`set_buffer_cells` to set an individual cell across a region.

        Args:
            x: The horizontal location of the upper left corner of the region
                to write the cells from.
            y: The vertical location of the upper left corner of the region to
                write the cells from.
            contents: A list of a list of cells that should be written.

        .. _PSHostRawUserInterface.SetBufferContents Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.setbuffercontents
        """
        raise NotImplementedError()  # pragma: no cover

    def get_buffer_contents(
        self,
        left: int,
        top: int,
        right: int,
        bottom: int,
    ) -> t.List[t.List[BufferCell]]:
        """GetBufferContents Host Call.

        Extracts a rectangular region of the screen buffer.

        This corresponds to the
        `PSHostRawUserInterface.GetBufferContents Method`_.

        Note:
            PowerShell does not implement this call for security reasons.

        Args:
            left: The left margin of the buffer region.
            top: The top margin of the buffer region.
            right: The right margin of the buffer region.
            bottom: The bottom margin of the buffer region.

        Returns:
            List[List[BufferCell]]: A jagged list of buffer cells of the screen
            buffer specified.

        .. _PSHostRawUserInterface.GetBufferContents Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.getbuffercontents
        """
        raise NotImplementedError()  # pragma: no cover

    def scroll_buffer_contents(
        self,
        source_left: int,
        source_top: int,
        source_right: int,
        source_bottom: int,
        x: int,
        y: int,
        clip_left: int,
        clip_top: int,
        clip_right: int,
        clip_bottom: int,
        character: t.Union[int, str, PSChar],
        foreground: ConsoleColor = ConsoleColor.White,
        background: ConsoleColor = ConsoleColor.Black,
    ) -> None:
        """ScrollBufferContents Host Call.

        Scroll a region of the screen buffer.

        This corresponds to the
        `PSHostRawUserInterface.ScrollBufferContents Method`_.

        Note:
            This is a void method and the server should continue pipeline
            execution and expect no response from the client.

        Args:
            source_left: The left margin of the screen to be scrolled.
            source_top: The top margin of the screen to be scrolled.
            source_right: The right margin of the screen to be scrolled.
            source_bottom: The bottom margin of the screen to be scrolled.
            x: The horizontal location of the upper left coordinate to receive
                the source region contents.
            y: The vertical location of the upper left coordinate to receive
                the source region contents.
            clip_left: The left margin of the clipped region.
            clip_top: The top margin of the clipped region.
            clip_right: The right margin of the clipped region.
            clip_bottom: The bottom margin of the clipped region.
            character: The character used to fill the cells intersecting the
                source and clip region.
            foreground: The foreground (text) color to fill the cells
                intersecting the source and clip region.
            background: The background color to fill the cells intersecting
                the source and clip region.

        .. _PSHostRawUserInterface.ScrollBufferContents Method:
            https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.scrollbuffercontents
        """
        raise NotImplementedError()  # pragma: no cover


def get_host_method(
    host: PSHost,
    responder: ClientHostResponder,
    ci: int,
    method_identifier: HostMethodIdentifier,
    method_parameters: t.List,
) -> MethodMetadata:
    """Get a callable host method.

    Gets a callable host method that can be invoked from a remote host call.

    Args:
        host: The PSHost to invoke.
        method_identifier: The HostMethodIdentifier from the remote host call.
        method_parameters: The parameters from the remote host call.

    Returns:
        MethodMetadata: A tuple with the first value being a callable that
        should be called to process the host call on the client host
        implementation. The second value is an optional callable that should
        be called that queues the response from the host call.
    """
    host_ui = host.ui or PSHostUI()
    host_raw_ui = host_ui.raw_ui or PSHostRawUI()

    if method_identifier == HostMethodIdentifier.GetName:
        return MethodMetadata(
            functools.partial(host.get_name, *method_parameters),
            lambda x: responder.get_name(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.GetVersion:
        return MethodMetadata(
            functools.partial(host.get_version, *method_parameters),
            lambda x: responder.get_version(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.GetInstanceId:
        return MethodMetadata(
            functools.partial(host.get_instance_id, *method_parameters),
            lambda x: responder.get_instance_id(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.GetCurrentCulture:
        return MethodMetadata(
            functools.partial(host.get_current_culture, *method_parameters),
            lambda x: responder.get_current_culture(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.GetCurrentUICulture:
        return MethodMetadata(
            functools.partial(host.get_current_ui_culture, *method_parameters),
            lambda x: responder.get_current_ui_culture(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.SetShouldExit:
        return MethodMetadata(
            functools.partial(host.set_should_exit, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.EnterNestedPrompt:
        return MethodMetadata(
            functools.partial(host.enter_nested_prompt, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.ExitNestedPrompt:
        return MethodMetadata(
            functools.partial(host.exit_nested_prompt, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.NotifyBeginApplication:
        return MethodMetadata(
            functools.partial(host.notify_begin_application, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.NotifyEndApplication:
        return MethodMetadata(
            functools.partial(host.notify_end_application, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.ReadLine:
        return MethodMetadata(
            functools.partial(host_ui.read_line, *method_parameters),
            lambda x: responder.read_line(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.ReadLineAsSecureString:
        return MethodMetadata(
            functools.partial(host_ui.read_line_as_secure_string, *method_parameters),
            lambda x: responder.read_line_as_secure_string(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.Write1:
        return MethodMetadata(
            functools.partial(host_ui.write, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.Write2:
        return MethodMetadata(
            functools.partial(
                host_ui.write,
                method_parameters[2],
                foreground_color=method_parameters[0],
                background_color=method_parameters[1],
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteLine1:
        return MethodMetadata(
            functools.partial(host_ui.write_line, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteLine2:
        return MethodMetadata(
            functools.partial(host_ui.write_line, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteLine3:
        return MethodMetadata(
            functools.partial(
                host_ui.write_line,
                method_parameters[2],
                foreground_color=method_parameters[0],
                background_color=method_parameters[1],
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteErrorLine:
        return MethodMetadata(
            functools.partial(host_ui.write_error_line, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteDebugLine:
        return MethodMetadata(
            functools.partial(host_ui.write_debug_line, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteProgress:
        record = method_parameters[1]
        return MethodMetadata(
            functools.partial(
                host_ui.write_progress,
                method_parameters[0],
                record.ActivityId,
                record.Activity,
                record.StatusDescription,
                current_operation=record.CurrentOperation,
                parent_activity_id=record.ParentActivityId,
                percent_complete=record.PercentComplete,
                record_type=record.RecordType,
                seconds_remaining=record.SecondsRemaining,
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteVerboseLine:
        return MethodMetadata(
            functools.partial(host_ui.write_verbose_line, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.WriteWarningLine:
        return MethodMetadata(
            functools.partial(host_ui.write_warning_line, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.Prompt:
        return MethodMetadata(
            functools.partial(host_ui.prompt, *method_parameters),
            lambda x: responder.prompt(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.PromptForCredential1:
        return MethodMetadata(
            functools.partial(
                host_ui.prompt_for_credential,
                method_parameters[0],
                method_parameters[1],
                username=method_parameters[2],
                target=method_parameters[3],
            ),
            lambda x: responder.prompt_for_credential(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.PromptForCredential2:
        return MethodMetadata(
            functools.partial(
                host_ui.prompt_for_credential,
                method_parameters[0],
                method_parameters[1],
                username=method_parameters[2],
                target_name=method_parameters[3],
                allowed_credential_types=method_parameters[4],
                options=method_parameters[5],
            ),
            lambda x: responder.prompt_for_credential(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.PromptForChoice:
        return MethodMetadata(
            functools.partial(
                host_ui.prompt_for_choice,
                method_parameters[0],
                method_parameters[1],
                method_parameters[2],
                default_choice=method_parameters[3],
            ),
            lambda x: responder.prompt_for_choice(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.PromptForChoiceMultipleSelection:
        return MethodMetadata(
            functools.partial(
                host_ui.prompt_for_multiple_choice,
                method_parameters[0],
                method_parameters[1],
                method_parameters[2],
                default_choices=method_parameters[3],
            ),
            lambda x: responder.prompt_for_multiple_choice(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.GetForegroundColor:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_foreground_color, *method_parameters),
            lambda x: responder.get_foreground_color(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.SetForegroundColor:
        return MethodMetadata(
            functools.partial(host_raw_ui.set_foreground_color, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetBackgroundColor:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_background_color, *method_parameters),
            lambda x: responder.get_background_color(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.SetBackgroundColor:
        return MethodMetadata(
            functools.partial(host_raw_ui.set_background_color, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetCursorPosition:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_cursor_position, *method_parameters),
            lambda x: responder.get_cursor_position(ci, x.X, x.Y),
        )

    elif method_identifier == HostMethodIdentifier.SetCursorPosition:
        return MethodMetadata(
            functools.partial(
                host_raw_ui.set_cursor_position,
                method_parameters[0].X,
                method_parameters[0].Y,
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetWindowPosition:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_window_position, *method_parameters),
            lambda x: responder.get_window_position(ci, x.X, x.Y),
        )

    elif method_identifier == HostMethodIdentifier.SetWindowPosition:
        return MethodMetadata(
            functools.partial(
                host_raw_ui.set_window_position,
                method_parameters[0].X,
                method_parameters[0].Y,
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetCursorSize:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_cursor_size, *method_parameters),
            lambda x: responder.get_cursor_size(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.SetCursorSize:
        return MethodMetadata(
            functools.partial(host_raw_ui.set_cursor_size, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetBufferSize:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_buffer_size, *method_parameters),
            lambda x: responder.get_buffer_size(ci, x.Width, x.Height),
        )

    elif method_identifier == HostMethodIdentifier.SetBufferSize:
        return MethodMetadata(
            functools.partial(
                host_raw_ui.set_buffer_size,
                method_parameters[0].Width,
                method_parameters[0].Height,
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetWindowSize:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_window_size, *method_parameters),
            lambda x: responder.get_window_size(ci, x.Width, x.Height),
        )

    elif method_identifier == HostMethodIdentifier.SetWindowSize:
        return MethodMetadata(
            functools.partial(
                host_raw_ui.set_window_size,
                method_parameters[0].Width,
                method_parameters[0].Height,
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetWindowTitle:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_window_title, *method_parameters),
            lambda x: responder.get_window_title(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.SetWindowTitle:
        return MethodMetadata(
            functools.partial(host_raw_ui.set_window_title, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetMaxWindowSize:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_max_window_size, *method_parameters),
            lambda x: responder.get_max_window_size(ci, x.Width, x.Height),
        )

    elif method_identifier == HostMethodIdentifier.GetMaxPhysicalWindowSize:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_max_physical_window_size, *method_parameters),
            lambda x: responder.get_max_physical_window_size(ci, x.Width, x.Height),
        )

    elif method_identifier == HostMethodIdentifier.GetKeyAvailable:
        return MethodMetadata(
            functools.partial(host_raw_ui.get_key_available, *method_parameters),
            lambda x: responder.get_key_available(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.ReadKey:
        return MethodMetadata(
            functools.partial(
                host_raw_ui.read_key,
                options=method_parameters[0],
            ),
            lambda x: responder.read_key(
                ci,
                x.Character,
                x.KeyDown,
                x.ControlKeyState,
                x.VirtualKeyCode,
            ),
        )

    elif method_identifier == HostMethodIdentifier.FlushInputBuffer:
        return MethodMetadata(
            functools.partial(host_raw_ui.flush_input_buffer, *method_parameters),
            None,
        )

    elif method_identifier == HostMethodIdentifier.SetBufferContents1:
        rectangle = method_parameters[0]
        cell = method_parameters[1]
        return MethodMetadata(
            functools.partial(
                host_raw_ui.set_buffer_cells,
                rectangle.Left,
                rectangle.Top,
                rectangle.Right,
                rectangle.Bottom,
                PSChar(cell.Character),
                foreground=cell.ForegroundColor,
                background=cell.BackgroundColor,
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.SetBufferContents2:
        return MethodMetadata(
            functools.partial(
                host_raw_ui.set_buffer_contents,
                method_parameters[0].X,
                method_parameters[0].Y,
                method_parameters[1],
            ),
            None,
        )

    elif method_identifier == HostMethodIdentifier.GetBufferContents:
        rectangle = method_parameters[0]
        return MethodMetadata(
            functools.partial(
                host_raw_ui.get_buffer_contents,
                rectangle.Left,
                rectangle.Top,
                rectangle.Right,
                rectangle.Bottom,
            ),
            lambda x: responder.get_buffer_contents(ci, x),
        )

    elif method_identifier == HostMethodIdentifier.ScrollBufferContents:
        source = method_parameters[0]
        destination = method_parameters[1]
        clip = method_parameters[2]
        fill = method_parameters[3]
        return MethodMetadata(
            functools.partial(
                host_raw_ui.scroll_buffer_contents,
                source.Left,
                source.Top,
                source.Right,
                source.Bottom,
                destination.X,
                destination.Y,
                clip.Left,
                clip.Top,
                clip.Right,
                clip.Bottom,
                fill.Character,
                foreground=fill.ForegroundColor,
                background=fill.BackgroundColor,
            ),
            None,
        )

    else:

        def not_implemented() -> None:
            raise NotImplementedError()

        return MethodMetadata(not_implemented, None)
