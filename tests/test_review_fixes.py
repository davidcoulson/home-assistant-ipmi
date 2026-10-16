"""Offline regressions for the verified review findings."""

from unittest.mock import MagicMock, patch

import pytest

import test_util

# Reuse the existing minimal HA stubs.


@pytest.fixture
def harness():
    helper = test_util.TestIpmiServerLogic()
    helper._stub_deps.__wrapped__(helper)
    return helper


def test_secret_headers_and_no_redirects(harness):
    srv = harness._make_server(kg_key="kg-secret")
    response = MagicMock()
    response.json.return_value = {"success": True}
    with patch.object(harness._server_mod.requests, "get", return_value=response) as get:
        srv.get_from_addon(None)
    kwargs = get.call_args.kwargs
    assert "password" not in kwargs["params"]
    assert "kg_key" not in kwargs["params"]
    assert kwargs["headers"] == {
        "X-Ipmi-Password": "secret", "X-Ipmi-Kg-Key": "kg-secret"
    }
    assert kwargs["allow_redirects"] is False


def test_explicit_legacy_query_mode(harness):
    srv = harness._make_server(legacy_addon_query_auth=True, kg_key="kg-secret")
    response = MagicMock()
    response.json.return_value = {"success": True}
    with patch.object(harness._server_mod.requests, "get", return_value=response) as get:
        srv.get_from_addon(None)
    assert get.call_args.kwargs["params"]["password"] == "secret"
    assert get.call_args.kwargs["params"]["kg_key"] == "kg-secret"
    assert get.call_args.kwargs["headers"] == {}


def test_remote_http_warning(harness, caplog):
    srv = harness._make_server(ipmi_server_host="http://addon.example")
    with patch.object(harness._server_mod.requests, "get", return_value=MagicMock()):
        srv.get_from_addon(None)
        srv.get_from_addon(None)
    assert caplog.text.count("Remote addon uses plain HTTP") == 1
