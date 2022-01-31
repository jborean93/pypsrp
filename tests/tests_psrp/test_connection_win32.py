import os

import pytest

if os.name == "nt":
    import psrp._connection._win32 as win32


@pytest.mark.skipif(os.name != "nt", reason="Windows only test")
def test_open_process_invalid_pid():
    with pytest.raises(OSError):
        win32.open_process(win32.PROCESS_QUERY_LIMITED_INFORMATION, False, 1)


@pytest.mark.skipif(os.name != "nt", reason="Windows only test")
def test_open_process():
    proc = win32.open_process(win32.PROCESS_QUERY_LIMITED_INFORMATION, False, os.getpid())
    try:
        assert isinstance(proc, int)
        assert proc > 0
    finally:
        win32.close_handle(proc)


@pytest.mark.skipif(os.name != "nt", reason="Windows only test")
def test_get_process_times_invalid_handle():
    proc = win32.open_process(win32.PROCESS_QUERY_LIMITED_INFORMATION, False, os.getpid())
    win32.close_handle(proc)

    with pytest.raises(OSError):
        win32.get_process_times(proc)


@pytest.mark.skipif(os.name != "nt", reason="Windows only test")
def test_get_process_times():
    proc = win32.open_process(win32.PROCESS_QUERY_LIMITED_INFORMATION, False, os.getpid())
    try:
        actual = win32.get_process_times(proc)
        assert len(actual) == 4
        assert isinstance(actual[0], int)
        assert isinstance(actual[1], int)
        assert isinstance(actual[2], int)
        assert isinstance(actual[3], int)
    finally:
        win32.close_handle(proc)
