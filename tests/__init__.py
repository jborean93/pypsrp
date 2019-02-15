import sys

if sys.version_info[0] == 2 and sys.version_info[1] < 7:  # pragma: no cover
    # xmldiff is not compatible with Python 2.6. We just need to rely on a
    # simple string difference
    xml_diff = None
else:  # pragma: no cover
    from xmldiff import main as xml_diff


def assert_xml_diff(actual, expected, msg=None):
    # Only use xmldiff if it has been imported and both the xml messages
    # contain data
    if xml_diff and actual and expected:
        diff = xml_diff.diff_texts(actual, expected)
        assert len(diff) == 0, msg
    else:
        assert actual == expected, msg
