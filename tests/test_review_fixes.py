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


def load_definitions(filename, names, namespace):
    """Execute actual definitions with small HA fakes, without importing HA."""
    import ast

    tree = ast.parse((test_util.IPMI_DIR / filename).read_text())
    nodes = [node for node in tree.body if getattr(node, "name", None) in names]
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(module, filename, "exec", flags=__import__('__future__').annotations.compiler_flag), namespace)
    return namespace


@pytest.mark.parametrize("secret", ['p@ss word+%&"', 'päss word', 'a/b?c'])
def test_encoded_redaction(secret):
    from urllib.parse import quote, quote_plus

    for encoded in (secret, quote(secret, safe=""), quote_plus(secret)):
        assert test_util.util.redact_connection_secrets(encoded, secret) == "***"


def test_transport_logs_and_command_errors_hide_secrets(harness, caplog):
    srv = harness._make_server(ipmi_server_host="https://u:proxysecret@addon.example")
    with patch.object(harness._server_mod.requests, "get", side_effect=RuntimeError("URL secret proxysecret")):
        assert srv.get_from_addon(None) is None
    assert "proxysecret" not in caplog.text
    assert "URL secret" not in caplog.text
    with patch.object(srv, "get_from_addon", return_value={"success": False, "output": "literal-secret"}):
        with pytest.raises(RuntimeError) as exc:
            srv.send_command("-P literal-secret bmc info", False)
    assert "literal-secret" not in str(exc.value)


def test_poll_message_redacted(harness, caplog):
    srv = harness._make_server(backend_preference="addon", password="p@ss word")
    with patch.object(srv, "_probe_addon_meta"), patch.object(srv, "get_from_addon", return_value={"success": False, "message": "bad p%40ss+word"}):
        srv.update()
    assert "p%40ss+word" not in caplog.text


def test_diagnostics_redacts_sensitive_fields(harness):
    import ast
    import asyncio
    from types import SimpleNamespace

    def redact(value, keys):
        if isinstance(value, dict):
            return {key: "REDACTED" if key in keys else redact(item, keys) for key, item in value.items()}
        return value

    source = ast.parse((test_util.IPMI_DIR / "diagnostics.py").read_text())
    assignment = next(node for node in source.body if isinstance(node, ast.Assign))
    namespace = {"CONF_PASSWORD": "password", "CONF_KG_KEY": "kg_key"}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), "diagnostics.py", "exec"), namespace)
    srv = harness._make_server()
    srv._last_rmcp_error = "secret"
    entry = SimpleNamespace(entry_id="e", title="lab", data={"ipmi_server_host": "https://u:pw@addon", "addon_extra_params": "-P other"}, options={"addon_extra_params": "-P option"})
    namespace.update(async_redact_data=redact, get_ipmi_server=lambda *args: {"data": srv, "coordinator": SimpleNamespace(last_update_success=True, update_interval=None)}, IPMI_DATA="data", COORDINATOR="coordinator", DEFAULT_BACKEND_PREFERENCE="auto")
    load_definitions("diagnostics.py", ["async_get_config_entry_diagnostics"], namespace)
    result = asyncio.run(namespace["async_get_config_entry_diagnostics"](None, entry))
    assert result["connection"]["addon_url"] == "REDACTED"
    assert result["connection"]["last_rmcp_error"] == "REDACTED"
    assert result["entry"]["data"]["ipmi_server_host"] == "REDACTED"
    assert result["entry"]["data"]["addon_extra_params"] == "REDACTED"
    assert result["entry"]["options"]["addon_extra_params"] == "REDACTED"
