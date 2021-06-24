from xmldiff import main as xml_diff


def assert_xml_diff(actual, expected, msg=None):
    # Only use xmldiff if it has been imported and both the xml messages
    # contain data
    if actual and expected:
        diff = xml_diff.diff_texts(actual, expected)
        assert len(diff) == 0, msg
    else:
        assert actual == expected, msg
