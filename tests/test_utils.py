import pytest

from six import PY3

from pypsrp._utils import to_bytes, to_string, to_unicode, version_newer


def test_unicode_to_bytes_default():
    expected = b"\x61\x62\x63"
    actual = to_bytes(u"abc")
    assert actual == expected


def test_unicode_to_bytes_diff_encoding():
    expected = b"\x61\x00\x62\x00\x63\x00"
    actual = to_bytes(u"abc", encoding='utf-16-le')
    assert actual == expected


def test_bytes_to_bytes():
    expected = b"\x01\x02\x03\x04"
    actual = to_bytes(b"\x01\x02\x03\x04")
    assert actual == expected


def test_str_to_bytes():
    # Python 3 the default string type is unicode so the expected value will
    # be "abc" in UTF-16 form while Python 2 "abc" is the bytes representation
    # already
    if PY3:
        expected = b"\x61\x00\x62\x00\x63\x00"
    else:
        expected = b"\x61\x62\x63"
    actual = to_bytes("abc", encoding='utf-16-le')
    assert actual == expected


def test_unicode_to_unicode():
    expected = u"abc"
    actual = to_unicode(u"abc")
    assert actual == expected


def test_byte_to_unicode():
    expected = u"abc"
    actual = to_unicode(b"\x61\x62\x63")
    assert actual == expected


def test_byte_to_unicode_diff_encoding():
    expected = u"abc"
    actual = to_unicode(b"\x61\x00\x62\x00\x63\x00", encoding='utf-16-le')
    assert actual == expected


def test_str_to_unicode():
    if PY3:
        expected = u"a\x00b\x00c\x00"
    else:
        expected = u"abc"
    actual = to_unicode("a\x00b\x00c\x00", encoding='utf-16-le')
    assert actual == expected


def test_to_str():
    if PY3:
        assert str(to_string).startswith("<function to_unicode")
    else:
        assert to_string.func_name == "to_bytes"


@pytest.mark.parametrize('version, reference_version, expected',
                         [
                             ["2.2", "2.3", False],
                             ["2.3", "2.3", True],
                             ["2.4", "2.3", True],
                             ["3", "2.3", True],
                             ["3.0", "2.3", True],
                             ["1", "2.3", False],
                             ["1.0", "2.3", False],
                             ["2.3.0", "2.3", True],
                             ["2.3.1", "2.3", True],
                             ["2.3", "2.3.0", True],
                             ["2.3", "2.3.1", False],
                         ])
def test_version_newer(version, reference_version, expected):
    assert version_newer(version, reference_version) == expected
