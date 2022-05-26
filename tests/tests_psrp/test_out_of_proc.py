import re

import pytest

import psrp


def test_cannot_init_async_out_of_proc_connection():
    expected = (
        "Type AsyncOutOfProcConnection cannot be instantiated; it can be used only as "
        "a base class for PSRP out of process connection implementations."
    )
    with pytest.raises(TypeError, match=re.escape(expected)):
        psrp.AsyncOutOfProcConnection(None, None)


def test_cannot_init_sync_out_of_proc_connection():
    expected = (
        "Type SyncOutOfProcConnection cannot be instantiated; it can be used only as "
        "a base class for PSRP out of process connection implementations."
    )
    with pytest.raises(TypeError, match=re.escape(expected)):
        psrp.SyncOutOfProcConnection(None, None)
