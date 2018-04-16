import pytest

from pypsrp.serializer import Serializer


class TestSerializer(object):

    def test_serialize_string(self):
        serializer = Serializer()

        string_value = u"0123456789abcdefghijklmnopqrstuvwxyz_"
        expected_serial = string_value
        actual_serial = serializer._serialize_string(string_value)
        assert actual_serial == expected_serial
        actual_deserial = serializer._deserialize_string(actual_serial)
        assert actual_deserial == string_value

        # _ is escaped when it preceeds an x
        string_value = u"actual_x000A_string\nnewline"
        expected_serial = u"actual_x005F_x000A_string_x000A_newline"
        actual_serial = serializer._serialize_string(string_value)
        assert actual_serial == expected_serial
        actual_deserial = serializer._deserialize_string(actual_serial)
        assert actual_deserial == string_value

        # surrogate pair
        string_value = u"treble clef %s" % \
                       b"\xd8\x34\xdd\x1e".decode('utf-16-be')
        expected_serial = u"treble clef _xD834__xDD1E_"
        actual_serial = serializer._serialize_string(string_value)
        assert actual_serial == expected_serial
        actual_deserial = serializer._deserialize_string(actual_serial)
        assert actual_deserial == string_value
