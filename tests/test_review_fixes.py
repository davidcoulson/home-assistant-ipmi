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
    with patch.object(
        harness._server_mod.requests, "get", return_value=response
    ) as get:
        srv.get_from_addon(None)
    kwargs = get.call_args.kwargs
    assert "password" not in kwargs["params"]
    assert "kg_key" not in kwargs["params"]
    assert kwargs["headers"] == {
        "X-Ipmi-Password": "secret",
        "X-Ipmi-Kg-Key": "kg-secret",
    }
    assert kwargs["allow_redirects"] is False


def test_explicit_legacy_query_mode(harness):
    srv = harness._make_server(legacy_addon_query_auth=True, kg_key="kg-secret")
    response = MagicMock()
    response.json.return_value = {"success": True}
    with patch.object(
        harness._server_mod.requests, "get", return_value=response
    ) as get:
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
    exec(
        compile(
            module,
            filename,
            "exec",
            flags=__import__("__future__").annotations.compiler_flag,
        ),
        namespace,
    )
    return namespace


@pytest.mark.parametrize("secret", ['p@ss word+%&"', "päss word", "a/b?c"])
def test_encoded_redaction(secret):
    from urllib.parse import quote, quote_plus

    for encoded in (secret, quote(secret), quote(secret, safe=""), quote_plus(secret)):
        assert test_util.util.redact_connection_secrets(encoded, secret) == "***"


def test_transport_logs_and_command_errors_hide_secrets(harness, caplog):
    srv = harness._make_server(ipmi_server_host="https://u:proxysecret@addon.example")
    with patch.object(
        harness._server_mod.requests,
        "get",
        side_effect=RuntimeError("URL secret proxysecret"),
    ):
        assert srv.get_from_addon(None) is None
    assert "proxysecret" not in caplog.text
    assert "URL secret" not in caplog.text
    with patch.object(
        srv,
        "get_from_addon",
        return_value={"success": False, "output": "literal-secret"},
    ):
        with pytest.raises(RuntimeError) as exc:
            srv.send_command("-P literal-secret bmc info", False)
    assert "literal-secret" not in str(exc.value)


def test_poll_message_redacted(harness, caplog):
    srv = harness._make_server(backend_preference="addon", password="p@ss word")
    with patch.object(srv, "_probe_addon_meta"), patch.object(
        srv,
        "get_from_addon",
        return_value={"success": False, "message": "bad p%40ss+word"},
    ):
        srv.update()
    assert "p%40ss+word" not in caplog.text


def test_diagnostics_redacts_sensitive_fields(harness):
    import ast
    import asyncio
    from types import SimpleNamespace

    def redact(value, keys):
        if isinstance(value, dict):
            return {
                key: "REDACTED" if key in keys else redact(item, keys)
                for key, item in value.items()
            }
        return value

    source = ast.parse((test_util.IPMI_DIR / "diagnostics.py").read_text())
    assignment = next(node for node in source.body if isinstance(node, ast.Assign))
    namespace = {"CONF_PASSWORD": "password", "CONF_KG_KEY": "kg_key"}
    exec(
        compile(
            ast.Module(body=[assignment], type_ignores=[]), "diagnostics.py", "exec"
        ),
        namespace,
    )
    srv = harness._make_server()
    srv._last_rmcp_error = "secret"
    entry = SimpleNamespace(
        entry_id="e",
        title="lab",
        data={
            "ipmi_server_host": "https://u:pw@addon",
            "addon_extra_params": "-P other",
        },
        options={"addon_extra_params": "-P option"},
    )
    namespace.update(
        async_redact_data=redact,
        get_ipmi_server=lambda *args: {
            "data": srv,
            "coordinator": SimpleNamespace(
                last_update_success=True, update_interval=None
            ),
        },
        IPMI_DATA="data",
        COORDINATOR="coordinator",
        DEFAULT_BACKEND_PREFERENCE="auto",
    )
    load_definitions(
        "diagnostics.py", ["async_get_config_entry_diagnostics"], namespace
    )
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
    with patch.object(srv, "_probe_addon_meta"), patch.object(
        srv, "get_from_addon", return_value=None
    ), patch.object(srv, "get_from_rmcp") as rmcp:
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
    with patch.object(
        harness._server_mod.requests, "get", return_value=response
    ) as get:
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

    with patch.object(
        harness._server_mod.time, "monotonic", side_effect=lambda: clock[0]
    ), patch.object(srv, "_probe_addon_meta"), patch.object(
        srv, "get_from_addon", side_effect=slow_addon
    ), patch.object(
        srv, "get_from_rmcp"
    ) as rmcp:
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


@pytest.mark.parametrize(
    "action", ["power_reset", "power_cycle", "power_off", "soft_shutdown"]
)
@pytest.mark.parametrize(
    "failure",
    ["read_timeout", "connection_reset", "bad_json", "failure_payload", "null_json"],
)
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
    elif failure == "null_json":
        response.json.return_value = None
    with patch.object(
        requests, "get", return_value=response, side_effect=effect
    ), patch.object(srv, "run_rmcp_command") as rmcp:
        with pytest.raises(
            harness._server_mod.IpmiChassisCommandError, match="outcome unknown"
        ):
            getattr(srv, action)()
    rmcp.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["connect_timeout", "connection_refused", "route_rejected"]
)
def test_pre_execution_chassis_failure_allows_fallback(harness, failure):
    from urllib3.exceptions import MaxRetryError, NewConnectionError

    srv = harness._make_server()
    requests = harness._server_mod.requests
    response = MagicMock(status_code=404)
    effect = None
    if failure == "connect_timeout":
        effect = requests.ConnectTimeout()
    elif failure == "connection_refused":
        effect = requests.ConnectionError(
            MaxRetryError(None, "/", NewConnectionError(None, "refused"))
        )
    with patch.object(
        requests, "get", return_value=response, side_effect=effect
    ), patch.object(srv, "run_rmcp_command") as rmcp:
        srv.power_reset()
    rmcp.assert_called_once()


@pytest.fixture
def sensor_classes():
    from types import SimpleNamespace

    class CoordinatorEntity:
        def __class_getitem__(cls, item):
            return cls

        @property
        def available(self):
            return self.coordinator.last_update_success

        def _handle_coordinator_update(self):
            pass

        async def async_added_to_hass(self):
            pass

    class SensorEntity:
        pass

    namespace = {
        "CoordinatorEntity": CoordinatorEntity,
        "DataUpdateCoordinator": dict,
        "SensorEntity": SensorEntity,
        "RestoreSensor": SensorEntity,
        "callback": lambda function: function,
        "KEY_STATUS": "status",
        "dt_util": SimpleNamespace(),
        "integrate_power_left_riemann": test_util.util.integrate_power_left_riemann,
        "math": __import__("math"),
    }
    return load_definitions("sensor.py", ["IpmiSensor", "IpmiEnergySensor"], namespace)


@pytest.mark.parametrize("key", ["status", "cpu_temp"])
def test_sensor_unavailable_on_coordinator_failure(sensor_classes, key):
    from types import SimpleNamespace

    sensor = object.__new__(sensor_classes["IpmiSensor"])
    sensor.entity_description = SimpleNamespace(key=key)
    sensor.coordinator = SimpleNamespace(
        last_update_success=True, data=SimpleNamespace(states={"cpu_temp": 30})
    )
    assert sensor.available
    sensor.coordinator.last_update_success = False
    assert not sensor.available


@pytest.fixture
def energy_sensor(sensor_classes):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    sensor = object.__new__(sensor_classes["IpmiEnergySensor"])
    sensor.coordinator = SimpleNamespace(
        last_update_success=True, data=SimpleNamespace(states={"power": 1000})
    )
    sensor._power_sensor_key = "power"
    sensor._energy_kwh = 2.0
    sensor._last_power_w = 1000
    sensor._last_integration_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sensor._energy_monitoring_enabled = lambda: True
    sensor._source_power_entity_enabled = lambda: True
    clock = [sensor._last_integration_time]
    sensor_classes["dt_util"].utcnow = lambda: clock[0]
    return sensor, clock


@pytest.mark.parametrize(
    "failure", ["coordinator", "missing", None, "N/A", "nan", "inf", {}, "disabled"]
)
def test_energy_breaks_interval_on_bad_observation(energy_sensor, failure):
    from datetime import timedelta

    sensor, clock = energy_sensor
    if failure == "coordinator":
        sensor.coordinator.last_update_success = False
    elif failure == "missing":
        sensor.coordinator.data.states = {}
    elif failure == "disabled":
        sensor._source_power_entity_enabled = lambda: False
    else:
        sensor.coordinator.data.states["power"] = failure
    assert not sensor.available
    clock[0] += timedelta(hours=1)
    sensor._handle_coordinator_update()
    assert sensor._last_power_w is None
    assert sensor._energy_kwh == 2.0
    sensor.coordinator.last_update_success = True
    sensor.coordinator.data.states = {"power": 1000}
    sensor._source_power_entity_enabled = lambda: True
    clock[0] += timedelta(hours=1)
    sensor._handle_coordinator_update()
    assert sensor._energy_kwh == 2.0
    clock[0] += timedelta(hours=1)
    sensor._handle_coordinator_update()
    assert sensor._energy_kwh == 3.0


@pytest.mark.parametrize(
    "restored,expected",
    [(None, 0), ("N/A", 0), ("nan", 0), ("inf", 0), (-1, 0), ("12.5", 12.5)],
)
def test_energy_restore_validates_total(energy_sensor, restored, expected):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    sensor, _ = energy_sensor
    sensor._energy_kwh = 0
    sensor.async_get_last_sensor_data = AsyncMock(
        return_value=SimpleNamespace(native_value=restored)
    )
    asyncio.run(sensor.async_added_to_hass())
    assert sensor._energy_kwh == expected


@pytest.mark.parametrize("field", ["host", "port", "username", "password"])
@pytest.mark.parametrize(
    "value",
    [
        "correct horse",
        'p"word',
        "p'word",
        "p\tword",
        "p\nword",
        "p -H attacker.invalid",
    ],
)
def test_unsafe_command_field_rejected_before_request(harness, field, value):
    srv = harness._make_server(**{field: value})
    with patch.object(srv, "get_from_addon") as addon:
        with pytest.raises(ValueError, match="whitespace or quotes"):
            srv.send_command(f"-P ${field}$ bmc info", False)
        assert srv.send_command(f"-P ${field}$ bmc info", True) == ""
    addon.assert_not_called()


def test_substitution_is_single_pass():
    assert (
        test_util.util.substitute_command_fields(
            "-U $username$", {"username": "$password$"}
        )
        == "-U $password$"
    )


def test_accepted_substitution_matches_addon_csv_parser():
    import json
    import shutil
    import subprocess

    if not shutil.which("php"):
        pytest.skip("PHP is needed to verify the external addon parser")
    fields = {
        "host": "bmc.example",
        "port": "623",
        "username": "a$word",
        "password": "p\\word+%&é",
    }
    cmd = test_util.util.substitute_command_fields(
        "-H $host$ -p $port$ -U $username$ -P $password$ bmc info", fields
    )
    # Execute only the documented parser, never an IPMI process.
    result = subprocess.run(
        [
            "php",
            "-r",
            """echo json_encode(str_getcsv($argv[1], ' ', '"', ''));""",
            "--",
            cmd,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout) == [
        "-H",
        fields["host"],
        "-p",
        "623",
        "-U",
        fields["username"],
        "-P",
        fields["password"],
        "bmc",
        "info",
    ]


def test_reconfigure_schema_omits_alias(harness):
    from types import SimpleNamespace
    import voluptuous as vol

    namespace = dict(vars(__import__("const")))
    namespace.update(
        vol=vol,
        cv=SimpleNamespace(string=str),
        CONF_ALIAS="alias",
        CONF_HOST="host",
        CONF_PORT="port",
        CONF_USERNAME="username",
        CONF_PASSWORD="password",
        CONF_ADVANCED="advanced",
        _PORT_SELECTOR=int,
        _PASSWORD_SELECTOR=str,
        _BOOLEAN_SELECTOR=bool,
    )
    load_definitions("config_flow.py", ["_basic_schema"], namespace)
    schema = namespace["_basic_schema"](
        None, {"alias": "original"}, include_alias=False
    )
    assert "alias" not in [key.schema for key in schema.schema]
    with pytest.raises(vol.Invalid):
        schema({"host": "bmc.example", "port": 623, "alias": "changed"})
    create_schema = namespace["_basic_schema"](None)
    assert "alias" in [key.schema for key in create_schema.schema]


def load_flow_methods(names, namespace):
    import ast
    import __future__

    tree = ast.parse((test_util.IPMI_DIR / "config_flow.py").read_text())
    flow = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "IpmiConfigFlow"
    )
    nodes = [node for node in flow.body if getattr(node, "name", None) in names]
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]),
            "config_flow.py",
            "exec",
            flags=__future__.annotations.compiler_flag,
        ),
        namespace,
    )
    return namespace


def test_reconfigure_preserves_alias_on_input_and_write():
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    entry = SimpleNamespace(
        entry_id="entry",
        data={"alias": "original", "host": "bmc.example"},
        options={},
        unique_id="original",
    )
    namespace = {
        "CONF_ALIAS": "alias",
        "CONF_ADVANCED": "advanced",
        "_coerce_bool": lambda data, key, default: data.get(key, default),
        "_normalize_flow_options": lambda data: data,
        "_entry_data_from_config": dict,
        "format_entry_unique_id": test_util.util.format_entry_unique_id,
        "_format_host_port_alias": lambda data: data["alias"],
    }
    load_flow_methods(["async_step_reconfigure", "_async_apply_reconfigure"], namespace)
    flow = SimpleNamespace(
        _get_reconfigure_entry=lambda: entry,
        _merge_advanced_defaults=lambda: None,
        _async_finish_reconfigure=AsyncMock(),
        _async_current_entries=lambda: [entry],
        async_update_and_abort=lambda entry, **kwargs: kwargs,
    )
    asyncio.run(
        namespace["async_step_reconfigure"](
            flow, {"alias": "changed", "host": "new.example"}
        )
    )
    assert flow.ipmi_config["alias"] == "original"
    # Also guard the final write, even if another step changed the pending data.
    flow.ipmi_config["alias"] = "changed"
    result = asyncio.run(namespace["_async_apply_reconfigure"](flow, entry))
    assert result["data"]["alias"] == "original"
    assert result["unique_id"] == "original"
    assert result["data"]["host"] == "new.example"


def test_unknown_outcome_traceback_omits_request_secrets(harness):
    import traceback

    srv = harness._make_server()
    with patch.object(
        harness._server_mod.requests,
        "get",
        side_effect=harness._server_mod.requests.ReadTimeout(
            "https://addon/?password=secret"
        ),
    ):
        with pytest.raises(harness._server_mod.IpmiChassisCommandError) as exc:
            srv.power_reset()
    assert "password=secret" not in "".join(traceback.format_exception(exc.value))


def test_transport_settings_survive_flow_storage(harness):
    import ast

    namespace = dict(vars(__import__("const")))
    namespace.update(
        CONF_ADVANCED="advanced",
        _normalize_flow_options=test_util.util.normalize_options,
        effective_sensor_types=test_util.util.effective_sensor_types,
    )
    tree = ast.parse((test_util.IPMI_DIR / "config_flow.py").read_text())
    option_keys = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            getattr(target, "id", None) == "_OPTION_KEYS" for target in node.targets
        )
    )
    exec(
        compile(
            ast.Module(body=[option_keys], type_ignores=[]), "config_flow.py", "exec"
        ),
        namespace,
    )
    load_definitions(
        "config_flow.py",
        ["_entry_data_from_config", "_entry_options_from_config", "_advanced_defaults"],
        namespace,
    )
    config = {
        "allow_legacy_rmcp": False,
        "legacy_addon_query_auth": True,
        "alias": "lab",
    }
    data = namespace["_entry_data_from_config"](config)
    options = namespace["_entry_options_from_config"](config)
    assert options["allow_legacy_rmcp"] is False
    assert "allow_legacy_rmcp" not in data
    assert data["legacy_addon_query_auth"] is True
    srv = harness._make_server(**{**data, **options})
    assert srv._legacy_addon_query_auth is True
    assert srv._allow_legacy_rmcp is False
    defaults = namespace["_advanced_defaults"]()
    assert defaults["allow_legacy_rmcp"] is True
    assert defaults["legacy_addon_query_auth"] is False


@pytest.mark.parametrize("outcome", ["success", "empty", "error"])
def test_validation_closes_temporary_server(harness, outcome):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    namespace = dict(vars(__import__("const")))
    namespace.update({name: name.removeprefix("CONF_").lower() for name in (
        "CONF_HOST", "CONF_PORT", "CONF_ALIAS", "CONF_USERNAME", "CONF_PASSWORD"
    )})
    server = MagicMock(_device_info=object() if outcome == "success" else None)
    if outcome == "error":
        server.update.side_effect = RuntimeError("poll failed")

    async def executor(function):
        return function()

    namespace.update(
        IpmiServer=lambda *args: server,
        _validate_kg_key=lambda key: key,
        effective_sensor_types=test_util.util.effective_sensor_types,
        CannotConnect=RuntimeError,
    )
    load_definitions("config_flow.py", ["validate_input"], namespace)
    hass = SimpleNamespace(async_add_executor_job=AsyncMock(side_effect=executor))
    if outcome == "success":
        assert asyncio.run(namespace["validate_input"](hass, {}))["device_info"]
    else:
        with pytest.raises(RuntimeError):
            asyncio.run(namespace["validate_input"](hass, {}))
    server.close.assert_called_once_with()
    assert hass.async_add_executor_job.call_args.args == (server.close,)


def test_failed_open_closes_partial_connection(harness):
    srv = harness._make_server()
    ipmi = MagicMock()
    ipmi.open.side_effect = RuntimeError("partial open")
    with patch.object(harness._server_mod.pyipmi, "create_connection", return_value=ipmi):
        with pytest.raises(RuntimeError, match="partial open"):
            srv.connect()
    ipmi.close.assert_called_once_with()
    assert srv._rmcp_ipmi is None


def test_failed_first_refresh_closes_server(harness):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    namespace = dict(vars(__import__("const")))
    namespace.update({name: name.removeprefix("CONF_").lower() for name in (
        "CONF_HOST", "CONF_PORT", "CONF_ALIAS", "CONF_USERNAME", "CONF_PASSWORD",
        "CONF_RESOURCES", "CONF_SCAN_INTERVAL"
    )})
    server = MagicMock()
    coordinator = SimpleNamespace(
        async_config_entry_first_refresh=AsyncMock(side_effect=RuntimeError("refresh failed"))
    )

    async def executor(function):
        return function()

    namespace.update(
        IpmiData=dict, _ensure_entry_unique_id=lambda *args: None,
        _normalize_options=dict, effective_sensor_types=test_util.util.effective_sensor_types,
        IpmiServer=lambda *args: server, IpmiCoordinator=lambda *args: coordinator,
    )
    load_definitions("__init__.py", ["async_setup_entry"], namespace)
    hass = SimpleNamespace(data={}, async_add_executor_job=AsyncMock(side_effect=executor))
    entry = SimpleNamespace(data={}, options={}, entry_id="entry")
    with pytest.raises(RuntimeError, match="refresh failed"):
        asyncio.run(namespace["async_setup_entry"](hass, entry))
    server.close.assert_called_once_with()


def test_close_waits_for_surviving_poll(harness):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    srv = harness._make_server()
    started, release, closing = Event(), Event(), Event()
    ipmi = MagicMock()

    def poll():
        started.set()
        assert release.wait(5)
        srv._rmcp_ipmi = ipmi

    def close():
        closing.set()
        srv.close()

    with patch.object(srv, "_update_unlocked", side_effect=poll):
        with ThreadPoolExecutor(max_workers=2) as executor:
            worker = executor.submit(srv.update)
            try:
                assert started.wait(5)
                cleanup = executor.submit(close)
                assert closing.wait(5)
                assert not cleanup.done()
            finally:
                release.set()
            worker.result(timeout=5)
            cleanup.result(timeout=5)
    ipmi.close.assert_called_once_with()
    assert srv._rmcp_ipmi is None


@pytest.mark.parametrize("payload", [[], ["success"], "false", None, 42])
def test_invalid_addon_envelope_falls_back(harness, payload):
    srv = harness._make_server()
    response = MagicMock(status_code=200)
    response.json.return_value = payload
    with patch.object(harness._server_mod.requests, "get", return_value=response), patch.object(
        srv, "_probe_addon_meta"
    ), patch.object(srv, "get_from_rmcp", return_value={"power_on": True}) as rmcp:
        srv.update()
    rmcp.assert_called_once_with()
    assert srv.last_backend == "rmcp"


@pytest.mark.parametrize("success", [False, "false", "true", 1, None])
def test_addon_success_requires_boolean_true(harness, success):
    srv = harness._make_server()
    assert not test_util.util.addon_action_succeeded({"success": success})
    with patch.object(srv, "_probe_addon_meta"), patch.object(
        srv, "get_from_addon", return_value={"success": success}
    ), patch.object(srv, "get_from_rmcp", return_value={"power_on": False}) as rmcp:
        srv.update()
    rmcp.assert_called_once_with()


@pytest.mark.parametrize("power,expected", [(True, True), (False, False), (None, None), ("false", None), (1, None)])
def test_addon_power_requires_boolean(harness, power, expected):
    srv = harness._make_server()
    payload = {"success": True}
    if power is not None:
        payload["power_on"] = power
    with patch.object(srv, "_probe_addon_meta"), patch.object(srv, "get_from_addon", return_value=payload):
        srv.update()
    assert srv.device_info.power_on is expected


@pytest.mark.parametrize("value", ["N/A", {}, [], "nan", "inf", None])
def test_numeric_sensor_invalid_value_is_unknown(sensor_classes, value):
    from types import SimpleNamespace

    sensor = object.__new__(sensor_classes["IpmiSensor"])
    sensor.entity_description = SimpleNamespace(key="temperature")
    sensor.coordinator = SimpleNamespace(data=SimpleNamespace(states={"temperature": value}))
    assert sensor.native_value is None


def test_state_sensor_missing_power_is_unknown(sensor_classes):
    from types import SimpleNamespace

    sensor = object.__new__(sensor_classes["IpmiSensor"])
    sensor.entity_description = SimpleNamespace(key="status")
    sensor.coordinator = SimpleNamespace(data=SimpleNamespace(power_on=None))
    assert sensor.native_value is None


@pytest.mark.parametrize("filename,classname,base", [
    ("binary_sensor.py", "IpmiPowerBinarySensor", "BinarySensorEntity"),
    ("switch.py", "IpmiSwitch", "SwitchEntity"),
])
def test_power_entities_preserve_unknown(sensor_classes, filename, classname, base):
    from types import SimpleNamespace

    namespace = dict(sensor_classes)
    namespace[base] = type(base, (), {})
    load_definitions(filename, [classname], namespace)
    entity = object.__new__(namespace[classname])
    entity.coordinator = SimpleNamespace(data=SimpleNamespace(power_on=None))
    entity._pending_off_until = None
    assert entity.is_on is None


@pytest.mark.parametrize("backend", ["addon", "rmcp"])
def test_reauth_validates_options_and_uses_update_listener(backend):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    entry = SimpleNamespace(
        data={"password": "old", "backend_preference": "auto"},
        options={"backend_preference": backend, "sensor_types": [], "create_energy_sensors": False},
    )
    namespace = {}
    load_flow_methods(["async_step_reauth_confirm"], namespace)
    update = MagicMock(return_value={"type": "abort"})
    flow = SimpleNamespace(
        _get_reauth_entry=lambda: entry,
        _async_validate_or_error=AsyncMock(return_value=({}, {})),
        async_update_and_abort=update,
    )
    result = asyncio.run(namespace["async_step_reauth_confirm"](flow, {"password": "new"}))
    flow._async_validate_or_error.assert_awaited_once_with({
        "password": "new", "backend_preference": backend,
        "sensor_types": [], "create_energy_sensors": False,
    })
    update.assert_called_once_with(entry, data_updates={"password": "new"}, reason="reauth_successful")
    assert result == {"type": "abort"}


def test_auth_evidence_survives_failed_fallback_and_resets_on_success(harness):
    srv = harness._make_server()

    def failed_rmcp():
        srv._last_rmcp_error = "TimeoutError: timed out"
        return None

    with patch.object(srv, "_probe_addon_meta"), patch.object(
        srv, "get_from_addon", return_value={"success": False, "message": "invalid password"}
    ), patch.object(srv, "get_from_rmcp", side_effect=failed_rmcp):
        srv.update()
    assert srv.auth_failed
    with patch.object(srv, "_probe_addon_meta"), patch.object(srv, "get_from_addon", return_value=None), patch.object(
        srv, "get_from_rmcp", side_effect=failed_rmcp
    ):
        srv.update()
    assert srv.auth_failed
    with patch.object(srv, "_probe_addon_meta"), patch.object(srv, "get_from_addon", return_value={"success": True}):
        srv.update()
    assert not srv.auth_failed


def test_discovery_uses_current_snapshot_before_coordinator_publication(harness):
    from types import SimpleNamespace

    srv = harness._make_server(sensor_types=["temperature"])
    coordinator = SimpleNamespace(data=SimpleNamespace(sensors={}, states={}))
    entry = SimpleNamespace(options={"sensor_types": ["temperature"], "create_energy_sensors": False})
    namespace = dict(vars(__import__("const")))
    namespace.update(
        callback=lambda fn: fn,
        as_str_list=test_util.util.as_str_list,
        energy_sensors_enabled=test_util.util.energy_sensors_enabled,
        _DYNAMIC_SENSOR_SPECS={"temperature": {}},
        _LOGGER=MagicMock(),
        SensorEntityDescription=lambda **kwargs: SimpleNamespace(**kwargs),
        IpmiSensor=lambda coordinator, description, *args: description.key,
    )
    load_definitions("sensor.py", ["create_entity_sensors"], namespace)
    added = []
    runtime = {namespace["COORDINATOR"]: coordinator, namespace["IPMI_DATA"]: srv}

    def dispatch(*args):
        assert coordinator.data.sensors == {}
        namespace["create_entity_sensors"](
            runtime, "entry1", lambda entities, *args: added.extend(entities), entry
        )

    with patch.object(srv, "_probe_addon_meta"), patch.object(
        srv, "get_from_addon", return_value={
            "success": True, "power_on": True,
            "sensors": {"temperature": {"new_temp": "New Temp"}},
            "states": {"new_temp": 30},
        }
    ), patch.object(harness._server_mod, "dispatcher_send", side_effect=dispatch):
        srv.update()
        assert added == ["new_temp"]
        srv.update()
    assert added == ["new_temp"]


@pytest.mark.parametrize("failure", [ValueError("bad conversion"), TimeoutError("sensor timeout")])
def test_rmcp_isolates_bad_sensor_and_skips_disabled_category(harness, failure):
    from types import SimpleNamespace

    srv = harness._make_server(sensor_types=["temperature"])
    ipmi = MagicMock()
    ipmi.get_chassis_status.return_value.power_on = True
    full = harness._server_mod.pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD

    def sensor(name, number, category):
        return SimpleNamespace(
            type=full, device_id_string=name, number=number, sensor_type_code=category,
            units_2=None, convert_sensor_raw_to_value=lambda value: value,
        )

    bad = sensor("Bad Temp", 1, 1)
    good = sensor("Good Temp", 2, 1)
    excluded = sensor("Voltage", 3, 2)
    ipmi.sdr_repository_entries.return_value = [bad, good, excluded]

    def reading(number):
        if number == 1:
            raise failure
        if number == 3:
            pytest.fail("Disabled voltage sensor must not be read")
        return 30, []

    ipmi.get_sensor_reading.side_effect = reading
    with patch.object(srv, "_connect_unlocked", return_value=ipmi), patch.object(
        srv, "_invalidate_rmcp_session_unlocked"
    ) as invalidate:
        result = srv._get_from_rmcp_full()
    assert result["power_on"] is True
    assert result["states"] == {"bad_temp": None, "good_temp": 30}
    assert result["sensors"]["voltage"] == {}
    invalidate.assert_not_called()


def test_rmcp_repository_failure_still_invalidates_session(harness):
    srv = harness._make_server(sensor_types=["temperature"])
    ipmi = MagicMock()
    ipmi.sdr_repository_entries.side_effect = RuntimeError("repository unavailable")
    with patch.object(srv, "_connect_unlocked", return_value=ipmi), patch.object(
        srv, "_invalidate_rmcp_session_unlocked"
    ) as invalidate:
        assert srv._get_from_rmcp_full() is None
    invalidate.assert_called_once_with()


@pytest.fixture
def device_actions():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    namespace = dict(vars(__import__("const")))
    namespace.update(
        CONF_TYPE="type", CONF_DEVICE_ID="device_id", CONF_DOMAIN="domain",
        HomeAssistantError=type("HomeAssistantError", (Exception,), {}),
        dr=SimpleNamespace(async_get=lambda hass: hass.registry),
        async_run_chassis_command=AsyncMock(),
    )
    load_definitions("helpers.py", ["get_ipmi_server"], namespace)
    load_definitions("device_action.py", [
        "_get_entry_id_from_device_id", "async_get_actions", "async_call_action_from_config"
    ], namespace)
    return namespace


def action_hass(data, entry_ids=("other", "ipmi")):
    from types import SimpleNamespace

    entries = {"other": SimpleNamespace(domain="other"), "ipmi": SimpleNamespace(domain="ipmi")}
    return SimpleNamespace(
        data=data,
        registry=SimpleNamespace(async_get=lambda device: SimpleNamespace(config_entries=entry_ids)),
        config_entries=SimpleNamespace(async_get_entry=entries.get),
    )


@pytest.mark.parametrize("runtime", [{}, {"ipmi": {}}, {"ipmi": {"servers": {}}}])
def test_unloaded_device_actions_are_controlled(device_actions, runtime):
    import asyncio

    hass = action_hass(runtime)
    assert asyncio.run(device_actions["async_get_actions"](hass, "device")) == []
    with pytest.raises(device_actions["HomeAssistantError"], match="unavailable"):
        asyncio.run(device_actions["async_call_action_from_config"](
            hass, {"type": "power_on", "device_id": "device"}, {}, None
        ))


@pytest.mark.parametrize("entry_ids", [(), ("missing",), ("other",)])
def test_device_without_ipmi_entry(device_actions, entry_ids):
    import asyncio

    hass = action_hass({}, entry_ids)
    assert asyncio.run(device_actions["async_get_actions"](hass, "device")) == []
    with pytest.raises(device_actions["HomeAssistantError"], match="No IPMI config entry"):
        asyncio.run(device_actions["async_call_action_from_config"](
            hass, {"type": "power_on", "device_id": "device"}, {}, None
        ))


def test_merged_device_uses_ipmi_entry(device_actions):
    import asyncio
    from types import SimpleNamespace

    command = MagicMock()
    runtime = {
        device_actions["IPMI_DATA"]: SimpleNamespace(power_on=command),
        device_actions["USER_AVAILABLE_COMMANDS"]: {"power_on"},
    }
    hass = action_hass({"ipmi": {"servers": {"ipmi": runtime}}})
    assert device_actions["_get_entry_id_from_device_id"](hass, "device") == "ipmi"
    assert asyncio.run(device_actions["async_get_actions"](hass, "device")) == [
        {"type": "power_on", "domain": "ipmi", "device_id": "device"}
    ]
    asyncio.run(device_actions["async_call_action_from_config"](
        hass, {"type": "power_on", "device_id": "device"}, {}, None
    ))
    device_actions["async_run_chassis_command"].assert_awaited_once_with(hass, command)


def test_missing_device_has_no_actions(device_actions):
    import asyncio

    hass = action_hass({})
    hass.registry.async_get = lambda device: None
    assert asyncio.run(device_actions["async_get_actions"](hass, "missing")) == []
