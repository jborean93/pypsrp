import base64
import uuid

from psrp._winrs import WinRS
from psrp._wsman import NAMESPACES, CreateEvent, SendEvent, WSMan


def test_winrs_environment() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, environment={"AAA": "bbb", "ccc": "DDD"})
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    actual = create_event.body.find("rsp:Shell/rsp:Environment", NAMESPACES)
    assert actual is not None
    assert len(actual) == 2
    assert actual[0].tag == f'{{{NAMESPACES["rsp"]}}}Variable'
    assert actual[0].attrib == {"Name": "AAA"}
    assert actual[0].text == "bbb"
    assert actual[1].tag == f'{{{NAMESPACES["rsp"]}}}Variable'
    assert actual[1].attrib == {"Name": "ccc"}
    assert actual[1].text == "DDD"


def test_winrs_idle_timeout() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, idle_time_out=10)
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    actual = create_event.body.find("rsp:Shell/rsp:IdleTimeOut", NAMESPACES)
    assert actual is not None
    assert actual.text == "PT10S"


def test_winrs_lifetime() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, lifetime=10)
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    actual = create_event.body.find("rsp:Shell/rsp:Lifetime", NAMESPACES)
    assert actual is not None
    assert actual.text == "PT10S"


def test_winrs_name() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, name="My Name")
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    actual = create_event.body.find("rsp:Shell/rsp:Name", NAMESPACES)
    assert actual is not None
    assert actual.text == "My Name"


def test_winrs_working_directory() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, working_directory="C:\\Windows")
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    actual = create_event.body.find("rsp:Shell/rsp:WorkingDirectory", NAMESPACES)
    assert actual is not None
    assert actual.text == "C:\\Windows"


def test_winrs_no_profile() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, no_profile=True)
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    options = create_event.header.find("wsman:OptionSet", NAMESPACES)
    assert options is not None
    assert len(options) == 1
    assert options[0].attrib == {"Name": "WINRS_NOPROFILE"}
    assert options[0].text == "True"


def test_winrs_codepage() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman, codepage=65001)
    mid = winrs.open()

    create_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert create_event.message_id == uuid.UUID(mid)
    assert isinstance(create_event, CreateEvent)

    options = create_event.header.find("wsman:OptionSet", NAMESPACES)
    assert options is not None
    assert len(options) == 1
    assert options[0].attrib == {"Name": "WINRS_CODEPAGE"}
    assert options[0].text == "65001"


def test_winrs_send_end() -> None:
    client_wsman = WSMan("client")
    server_wsman = WSMan("server")
    winrs = WinRS(client_wsman)
    mid = winrs.send("stdin", b"data", end=True)

    send_event = server_wsman.receive_data(winrs.data_to_send() or b"")
    assert send_event.message_id == uuid.UUID(mid)
    assert isinstance(send_event, SendEvent)

    stream = send_event.body.find("rsp:Send/rsp:Stream", NAMESPACES)
    assert stream is not None
    assert stream.attrib == {"Name": "stdin", "End": "True"}
    assert stream.text == base64.b64encode(b"data").decode()
