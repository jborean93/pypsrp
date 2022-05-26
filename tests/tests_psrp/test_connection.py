import re

import pytest

import psrp


def test_cannot_init_async_connection():
    expected = (
        "Type AsyncConnection cannot be instantiated; it can be used only as "
        "a base class for PSRP connection implementations."
    )
    with pytest.raises(TypeError, match=re.escape(expected)):
        psrp.AsyncConnection(None, None)


def test_cannot_init_sync_connection():
    expected = (
        "Type SyncConnection cannot be instantiated; it can be used only as "
        "a base class for PSRP connection implementations."
    )
    with pytest.raises(TypeError, match=re.escape(expected)):
        psrp.SyncConnection(None, None)
