import re

from six import PY3, text_type, binary_type


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
if PY3:
    to_string = to_unicode
else:
    to_string = to_bytes
