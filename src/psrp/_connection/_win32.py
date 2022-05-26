# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import ctypes
import typing as t
from ctypes.wintypes import BOOL, DWORD, FILETIME, HANDLE, LPFILETIME

kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)  # type: ignore[attr-defined] # For POSIX
# ntdll = WinDLL("Ntdll.dll")

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

GetProcessTimes = kernel32.GetProcessTimes
GetProcessTimes.argtypes = [HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME]
GetProcessTimes.restype = BOOL

# NtQuerySystemInformation = ntdll.NtQuerySystemInformation
# NtQuerySystemInformation.argtypes = [UINT, LPVOID, ULONG, PULONG]
# NtQuerySystemInformation.restype = UINT

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, DWORD, DWORD]
OpenProcess.restype = HANDLE

# RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
# RtlNtStatusToDosError.argtypes = [UINT]
# RtlNtStatusToDosError.restype = ULONG

# MAX_PATH = 260

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# SystemProcessIdInformation = 0x58


# class UNICODE_STRING(Structure):
#     _fields_ = (
#         ("Length", USHORT),
#         ("MaximumLength", USHORT),
#         ("Buffer", LPWSTR),
#     )


# class SYSTEM_PROCESS_ID_INFORMATION(Structure):
#     _fields_ = (
#         ("ProcessId", HANDLE),
#         ("ImageName", UNICODE_STRING),
#     )


def close_handle(handle: HANDLE) -> None:
    """Wrapper for Win32 CloseHandle.

    A Python wrapper for the Win32 `CloseHandle`_ function. It closes an
    opened. object handle.

    Args:
        handle: The handle to close.

    .. _CloseHandle:
        https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    """
    CloseHandle(handle)


def get_process_times(
    process: HANDLE,
) -> t.Tuple[int, int, int, int]:
    """Wrapper for Win32 GetProcessTimes.

    A Python wrapper for the Win32 `GetProcessTimes`_ function. It retrieves
    timing information for the specified process. The return values are an
    integer in the FILETIME format, 100s of nanoseconds since 1601-01-01.

    Args:
        process: The process handle as opened by :meth:`open_process`.

    Returns:
        Tuple[int, int, int, int]: Returns the creation time, exit time,
        kernel time, and user time respectively.

    .. _GetProcessTimes:
        https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
    """
    creation_time = FILETIME()
    exit_time = FILETIME()
    kernel_time = FILETIME()
    user_time = FILETIME()
    if not GetProcessTimes(
        process,
        ctypes.byref(creation_time),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        raise ctypes.WinError(code=ctypes.get_last_error())  # type: ignore[attr-defined] # For POSIX

    def ft_to_int(ft: FILETIME) -> int:
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime  # type: ignore[operator] # No idea why mypy hates this

    ct_ft = ft_to_int(creation_time)
    et_ft = ft_to_int(exit_time)
    kt_ft = ft_to_int(kernel_time)
    ut_ft = ft_to_int(user_time)

    return ct_ft, et_ft, kt_ft, ut_ft


## We still use psutil, keep this here as a reference in case it is needed.
# def nt_query_system_process_id_information(
#     process_id: int,
# ) -> str:
#     """Wrapper for NtQuerySystemInformation.

#     A Python wrapper for `NtQuerySystemInformation`_ with the
#     SystemProcessIdInformation information class. It is used to retrieve the
#     image name (executable path) of the process specified.

#     .. Note:
#         The returned value is the NT object path and not the Win32/DosDevice
#         path that is typically used.

#     Args:
#         process_id: The identifier of the process to get the image name of.

#     Returns:
#         str: The process image name as an NT path.

#     .. _NtQuerySystemInformation:
#         https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
#     """
#     # While this structure is not documented it is used by psutil to retrieve
#     # this information as the Win32 function has weird limits and is slow.
#     # Fingers crossed nothing major breaks in future versions.
#     process_info = SYSTEM_PROCESS_ID_INFORMATION()
#     process_info.ProcessId = process_id
#     process_info.ImageName = UNICODE_STRING()
#     process_info.ImageName.Length = 0

#     buffer_length = MAX_PATH
#     while True:
#         buffer = create_unicode_buffer(buffer_length)
#         process_info.ImageName.MaximumLength = buffer_length * 2
#         process_info.ImageName.Buffer = addressof(buffer)

#         status = NtQuerySystemInformation(
#             SystemProcessIdInformation,
#             byref(process_info),
#             sizeof(process_info),
#             None,
#         )
#         if status == STATUS_INFO_LENGTH_MISMATCH and buffer_length < 0xFFFF:
#             if process_info.ImageName.MaximumLength > buffer_length:
#                 buffer_length = process_info.ImageName.MaximumLength // 2

#             else:
#                 buffer_length *= 2

#         elif status:
#             raise WinError(code=RtlNtStatusToDosError(status))

#         else:
#             return str(buffer[: (process_info.ImageName.Length // 2)])


def open_process(
    desired_access: int,
    inherit_handle: bool,
    process_id: int,
) -> HANDLE:
    """Wrapper for Win32 OpenProcess.

    A Python wrapper for the Win32 `OpenProcess`_ function. This opens a
    process handle for the pid specified and returns that handle for future
    use. The handle being opened should be closed with :meth:`close_handle`
    once it is no longer needed.

    Args:
        desired_access: The access mask to open the process with.
        inherit_handle: Mark the opened handle as inheritable by sub processes.
        process_id: The identifier of the process to be opened.

    Returns:
        HANDLE: The process handle that was opened.

    .. _OpenProcess:
        https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    """
    handle = OpenProcess(desired_access, inherit_handle, process_id)
    if not handle:
        raise ctypes.WinError(code=ctypes.get_last_error())  # type: ignore[attr-defined] # For POSIX

    return t.cast(HANDLE, handle)


__all__ = [
    "PROCESS_QUERY_LIMITED_INFORMATION",
    "close_handle",
    "get_process_times",
    # "nt_query_system_process_id_information",
    "open_process",
]
