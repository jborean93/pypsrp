import pytest

from pypsrp._utils import to_bytes, to_string, to_unicode, \
    version_equal_or_newer, get_hostname


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
    expected = b"\x61\x00\x62\x00\x63\x00"
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
    expected = u"a\x00b\x00c\x00"
    actual = to_unicode("a\x00b\x00c\x00", encoding='utf-16-le')
    assert actual == expected


def test_to_str():
    assert str(to_string).startswith("<function to_unicode")


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
    assert version_equal_or_newer(version, reference_version) == expected


@pytest.mark.parametrize('url, expected',
                         [
                             # hostname
                             ['http://hostname', 'hostname'],
                             ['https://hostname', 'hostname'],
                             ['http://hostname:1234', 'hostname'],
                             ['https://hostname:1234', 'hostname'],
                             ['http://hostname/path', 'hostname'],
                             ['https://hostname/path', 'hostname'],
                             ['http://hostname:1234/path', 'hostname'],
                             ['https://hostname:1234/path', 'hostname'],

                             # fqdn
                             ['http://hostname.domain.com', 'hostname.domain.com'],
                             ['https://hostname.domain.com', 'hostname.domain.com'],
                             ['http://hostname.domain.com:1234', 'hostname.domain.com'],
                             ['https://hostname.domain.com:1234', 'hostname.domain.com'],
                             ['http://hostname.domain.com/path', 'hostname.domain.com'],
                             ['https://hostname.domain.com/path', 'hostname.domain.com'],
                             ['http://hostname.domain.com:1234/path', 'hostname.domain.com'],
                             ['https://hostname.domain.com:1234/path', 'hostname.domain.com'],

                             # ip address
                             ['http://1.2.3.4', '1.2.3.4'],
                             ['https://1.2.3.4', '1.2.3.4'],
                             ['http://1.2.3.4:1234', '1.2.3.4'],
                             ['https://1.2.3.4:1234', '1.2.3.4'],
                             ['http://1.2.3.4/path', '1.2.3.4'],
                             ['https://1.2.3.4/path', '1.2.3.4'],
                             ['http://1.2.3.4:1234/path', '1.2.3.4'],
                             ['https://1.2.3.4:1234/path', '1.2.3.4'],
                         ])
def test_get_hostname(url, expected):
    assert expected == get_hostname(url)
