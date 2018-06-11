import pytest

from pypsrp.exceptions import AuthenticationError, FragmentError, \
    InvalidPipelineStateError, InvalidPSRPOperation, \
    InvalidRunspacePoolStateError, SerializationError, WinRMError, \
    WinRMTransportError, WSManFaultError


def test_winrm_error():
    with pytest.raises(WinRMError) as exc:
        raise WinRMError("error msg")
    assert str(exc.value) == "error msg"


def test_authentication_error():
    with pytest.raises(AuthenticationError) as exc:
        raise AuthenticationError("auth error")
    assert str(exc.value) == "auth error"


def test_winrm_transport_error():
    with pytest.raises(WinRMTransportError) as exc:
        raise WinRMTransportError("proto", 1234, "response")
    assert str(exc.value) == "Bad PROTO response returned from the server. " \
                             "Code: 1234, Content: 'response'"
    assert exc.value.protocol == "proto"
    assert exc.value.code == 1234
    assert exc.value.response_text == "response"


def test_wsman_fault_error():
    with pytest.raises(WSManFaultError) as exc:
        raise WSManFaultError(1234, "machine", "reason", "provider", "path",
                              "fault")
    assert str(exc.value) == "Received a WSManFault message. (Code: 1234, " \
                             "Machine: machine, Reason: reason, " \
                             "Provider: provider, Provider Path: path, " \
                             "Provider Fault: fault)"
    assert exc.value.code == 1234
    assert exc.value.machine == "machine"
    assert exc.value.reason == "reason"
    assert exc.value.provider == "provider"
    assert exc.value.provider_path == "path"
    assert exc.value.provider_fault == "fault"


def test_wsman_fault_error_empty():
    with pytest.raises(WSManFaultError) as exc:
        raise WSManFaultError(None, None, None, None, None, None)
    assert str(exc.value) == "Received a WSManFault message. (No details " \
                             "returned by the server)"


def test_invalid_runspace_pool_state_error():
    with pytest.raises(InvalidRunspacePoolStateError) as exc:
        raise InvalidRunspacePoolStateError(0, [1, 2], "do action")
    assert str(exc.value) == "Cannot 'do action' on the current state " \
                             "'BeforeOpen', expecting state(s): " \
                             "'Opening, Opened'"


def test_invalid_pipeline_state_error():
    with pytest.raises(InvalidPipelineStateError) as exc:
        raise InvalidPipelineStateError(0, 1, "do action")
    assert str(exc.value) == "Cannot 'do action' on the current state " \
                             "'NotStarted', expecting state(s): 'Running'"


def test_invalid_psrp_operation():
    with pytest.raises(InvalidPSRPOperation) as exc:
        raise InvalidPSRPOperation("invalid psrp operation")
    assert str(exc.value) == "invalid psrp operation"


def test_fragment_error():
    with pytest.raises(FragmentError) as exc:
        raise FragmentError("fragment error")
    assert str(exc.value) == "fragment error"


def test_serialization_error():
    with pytest.raises(SerializationError) as exc:
        raise SerializationError("serialization error")
    assert str(exc.value) == "serialization error"
