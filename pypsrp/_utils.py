# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from six import PY3, text_type, binary_type

try:
    from urlparse import urlparse
except ImportError:  # pragma: no cover
    from urllib.parse import urlparse


def to_bytes(obj, encoding='utf-8'):
    """
    Makes sure the string is encoded as a byte string.

    :param obj: Python 2 string, Python 3 byte string, Unicode string to encode
    :param encoding: The encoding to use
    :return: The byte string that was encoded
    """
    if isinstance(obj, binary_type):
        return obj

    return obj.encode(encoding)


def to_unicode(obj, encoding='utf-8'):
    """
    Makes sure the string is unicode string.

    :param obj: Python 2 string, Python 3 byte string, Unicode string to decode
    :param encoding: The encoding to use
    :return: THe unicode string the was decoded
    """
    if isinstance(obj, text_type):
        return obj

    return obj.decode(encoding)

"""
Python 2 and 3 handle native strings differently, 2 is like a byte string while
3 uses unicode as the native string. The function to_string is used to easily
convert an existing string like object to the native version that is required
"""
if PY3:  # pragma: no cover
    to_string = to_unicode
else:  # pragma: no cover
    to_string = to_bytes


def version_equal_or_newer(version, reference_version):
    """
    Compares the 2 version strings and returns a bool that states whether
    version is newer than or equal to the reference version.

    This is quite strict and splits the string by . and compares the int
    values in them

    :param version: The version string to compare
    :param reference_version: The version string to check version against
    :return: True if version is newer than or equal to reference_version
    """
    version_parts = version.split(".")
    reference_version_parts = reference_version.split(".")

    # pad the version parts by 0 so the comparisons after won't fail with an
    # index error
    if len(version_parts) < len(reference_version_parts):
        diff = len(reference_version_parts) - len(version_parts)
        version_parts.extend(["0"] * diff)
    if len(reference_version_parts) < len(version_parts):
        diff = len(version_parts) - len(reference_version_parts)
        reference_version_parts.extend(["0"] * diff)

    newer = True
    for idx, version in enumerate(version_parts):
        reference_version = int(reference_version_parts[idx])
        if int(version) < reference_version:
            newer = False
            break
        elif int(version) > reference_version:
            break

    return newer


def get_hostname(url):
    return urlparse(url).hostname
