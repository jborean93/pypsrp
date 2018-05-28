import pytest

from pypsrp.serializer import Serializer


class TestSerializer(object):

    @pytest.mark.parametrize('input_val, expected', [
        ["0123456789abcdefghijklmnopqrstuvwxyz_",
         "0123456789abcdefghijklmnopqrstuvwxyz_"],
        ["actual_x000A_string\nnewline",
         "actual_x005F_x000A_string_x000A_newline"],
        ["treble clef %s" % b"\xd8\x34\xdd\x1e".decode('utf-16-be'),
         "treble clef _xD834__xDD1E_"],
    ])
    def test_serialize_string(self, input_val, expected):
        serializer = Serializer()

        actual_serial = serializer._serialize_string(input_val)
        assert actual_serial == expected
        actual_deserial = serializer._deserialize_string(actual_serial)
        assert actual_deserial == input_val
