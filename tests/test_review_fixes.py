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


@pytest.mark.parametrize("secure", [{"addon_interface": "lanplus"}, {"kg_key": "key"}])
def test_strict_rmcp_policy(harness, secure):
    srv = harness._make_server(allow_legacy_rmcp=False, **secure)
    assert not srv._should_try_rmcp()
    with patch.object(srv, "_probe_addon_meta"), patch.object(srv, "get_from_addon", return_value=None), patch.object(srv, "get_from_rmcp") as rmcp:
        srv.update()
    rmcp.assert_not_called()
    with pytest.raises(harness._server_mod.IpmiChassisCommandError, match="policy"):
        srv.connect()


def test_default_rmcp_policy_warns_on_downgrade(harness, caplog):
    srv = harness._make_server(addon_interface="lanplus")
    srv._rmcp_ipmi = MagicMock()
    assert srv._should_try_rmcp()
    srv.connect()
    assert "legacy IPMI 1.5" in caplog.text


def test_meta_timeout_tuple_and_redirects(harness):
    srv = harness._make_server()
    response = MagicMock(status_code=404)
    with patch.object(harness._server_mod.requests, "get", return_value=response) as get:
        srv._probe_addon_meta()
    assert get.call_args.kwargs["timeout"] == (5, 10)
    assert get.call_args.kwargs["allow_redirects"] is False


def test_poll_uses_remaining_budget_and_skips_late_fallback(harness):
    srv = harness._make_server()
    clock = [100.0]

    def slow_addon(*args):
        assert srv._http_timeout() == (5, 50)
        clock[0] += 56
        return None

    with patch.object(harness._server_mod.time, "monotonic", side_effect=lambda: clock[0]), patch.object(srv, "_probe_addon_meta"), patch.object(srv, "get_from_addon", side_effect=slow_addon), patch.object(srv, "get_from_rmcp") as rmcp:
        with pytest.raises(TimeoutError, match="deadline"):
            srv.update()
    rmcp.assert_not_called()
    assert srv._update_lock.acquire(blocking=False)
    srv._update_lock.release()


def test_surviving_worker_prevents_overlapping_poll(harness):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    srv = harness._make_server()
    started, release = Event(), Event()

    def blocked_poll():
        started.set()
        assert release.wait(5)

    with patch.object(srv, "_update_unlocked", side_effect=blocked_poll) as poll:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(srv.update)
            try:
                assert started.wait(5)
                assert not future.cancel()
                with pytest.raises(RuntimeError, match="still in flight"):
                    srv.update()
                assert poll.call_count == 1
            finally:
                release.set()
            future.result(timeout=5)


@pytest.mark.parametrize("action", ["power_reset", "power_cycle", "power_off", "soft_shutdown"])
@pytest.mark.parametrize("failure", ["read_timeout", "connection_reset", "bad_json", "failure_payload"])
def test_ambiguous_chassis_outcome_never_replays(harness, action, failure):
    srv = harness._make_server()
    requests = harness._server_mod.requests
    response = MagicMock(status_code=200)
    response.json.return_value = {"success": False}
    effect = None
    if failure == "read_timeout":
        effect = requests.ReadTimeout("lost reply")
    elif failure == "connection_reset":
        effect = requests.ConnectionError("reset after submission")
    elif failure == "bad_json":
        response.json.side_effect = ValueError("invalid JSON")
    with patch.object(requests, "get", return_value=response, side_effect=effect), patch.object(srv, "run_rmcp_command") as rmcp:
        with pytest.raises(harness._server_mod.IpmiChassisCommandError, match="outcome unknown"):
            getattr(srv, action)()
    rmcp.assert_not_called()


@pytest.mark.parametrize("failure", ["connect_timeout", "connection_refused", "route_rejected"])
def test_pre_execution_chassis_failure_allows_fallback(harness, failure):
    from urllib3.exceptions import MaxRetryError, NewConnectionError

    srv = harness._make_server()
    requests = harness._server_mod.requests
    response = MagicMock(status_code=404)
    effect = None
    if failure == "connect_timeout":
        effect = requests.ConnectTimeout()
    elif failure == "connection_refused":
        effect = requests.ConnectionError(MaxRetryError(None, "/", NewConnectionError(None, "refused")))
    with patch.object(requests, "get", return_value=response, side_effect=effect), patch.object(srv, "run_rmcp_command") as rmcp:
        srv.power_reset()
    rmcp.assert_called_once()
