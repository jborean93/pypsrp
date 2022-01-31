import psrp


def test_wsman_http_error() -> None:
    e = psrp.WSManHTTPError("msg", 500)
    assert isinstance(e, psrp.WSManHTTPError)
    assert not isinstance(e, psrp.WSManAuthenticationError)
    assert str(e) == "msg"
    assert e.http_code == 500


def test_wsman_http_as_auth_error() -> None:
    e = psrp.WSManHTTPError("msg", 401)
    assert isinstance(e, psrp.WSManHTTPError)
    assert isinstance(e, psrp.WSManAuthenticationError)
    assert str(e) == "msg"
    assert e.http_code == 401
