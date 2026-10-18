"""Offline, standard-library tests; no real launchctl or network operations."""

import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/orca-relay-macos-bridge-watchdog.py"
SPEC = importlib.util.spec_from_file_location("macos_bridge_watchdog", SCRIPT)
watchdog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watchdog)


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {
            "ORCA_RELAY_URL": "ws://relay.example.test:8080/ws",
            "ORCA_RUNTIME_WS_URL": "ws://127.0.0.1:6768/ws",
            "ORCA_RELAY_SERVER_ID": "runtime-example",
            "ORCA_RELAY_TOKEN": "private-test-token",
        }
        self.config_path = self.root / "bridge.json"
        self.write_config()
        self.state_dir = self.root / "watchdog-state"
        self.argv = ["--config", str(self.config_path), "--state-dir", str(self.state_dir),
                     "--label", "example.orca-relay.bridge"]
        # Any unexpected production call fails the test before it can execute.
        self.http = mock.patch.object(watchdog.http.client, "HTTPConnection",
                                      side_effect=AssertionError("unexpected HTTP"))
        self.https = mock.patch.object(watchdog.http.client, "HTTPSConnection",
                                       side_effect=AssertionError("unexpected HTTPS"))
        self.subprocess = mock.patch.object(watchdog.subprocess, "run",
                                            side_effect=AssertionError("unexpected subprocess"))
        self.http.start()
        self.https.start()
        self.subprocess.start()
        self.addCleanup(self.http.stop)
        self.addCleanup(self.https.stop)
        self.addCleanup(self.subprocess.stop)

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config))
        self.config_path.chmod(0o600)

    def run_tick(self, *, state=("stopped", None), probe=("missing", 503), now=100.0,
                 extra=(), kick=True):
        output = io.StringIO()
        with mock.patch.object(watchdog, "launch_state", return_value=state) as lifecycle, \
                mock.patch.object(watchdog, "probe_route", return_value=probe) as route, \
                mock.patch.object(watchdog, "kickstart", return_value=kick) as start, \
                mock.patch.object(watchdog.time, "time", return_value=now), redirect_stdout(output):
            result = watchdog.main(self.argv + list(extra))
        return result, json.loads(output.getvalue()), lifecycle, route, start

    def read_state(self):
        return json.loads((self.state_dir / "state.json").read_text())

    def launch_dump(self, fields, label="example.bridge"):
        return (watchdog.service_target(label) + " = {\n"
                + "".join("\t" + line + "\n" for line in fields.splitlines()) + "}\n")

    def test_three_consecutive_missing_ticks_start_once_then_reset(self):
        for now, count in [(100, 1), (110, 2)]:
            result, record, lifecycle, route, start = self.run_tick(now=now)
            self.assertEqual(result, 0)
            self.assertEqual(record["event"], "route_missing")
            self.assertEqual(self.read_state()["missing_count"], count)
            route.assert_called_once()
            start.assert_not_called()
            lifecycle.assert_called_once()
        result, record, lifecycle, route, start = self.run_tick(now=120)
        self.assertEqual(result, 0)
        self.assertEqual(record["event"], "bridge_kickstarted")
        self.assertEqual(route.call_count, 2)  # Fresh final 503 before lifecycle recheck.
        self.assertEqual(lifecycle.call_count, 2)
        start.assert_called_once_with("example.orca-relay.bridge")
        self.assertEqual(self.read_state()["missing_count"], 0)
        self.run_tick(now=130)
        self.assertEqual(self.read_state()["missing_count"], 1)

    def test_owner_101_resets_streak_and_never_starts(self):
        self.run_tick(now=100)
        result, record, _, _, start = self.run_tick(probe=("occupied", 101), now=110)
        self.assertEqual(result, 0)
        self.assertEqual(record["event"], "owner_present")
        self.assertEqual(record["http_status"], 101)
        self.assertEqual(self.read_state()["missing_count"], 0)
        start.assert_not_called()

    def test_unknown_and_401_break_consecutive_streak(self):
        for status in [None, 401, 400, 302, 404, 500]:
            with self.subTest(status=status):
                self.run_tick(now=100)
                _, record, _, _, start = self.run_tick(probe=("unknown", status), now=110)
                self.assertEqual(record["event"], "probe_unknown")
                self.assertEqual(self.read_state()["missing_count"], 0)
                start.assert_not_called()

    def test_running_does_not_load_config_probe_or_restart(self):
        self.run_tick()
        self.config_path.unlink()
        _, record, _, route, start = self.run_tick(state=("running", 123))
        self.assertEqual(record["event"], "bridge_running")
        self.assertEqual(record["pid"], 123)
        self.assertEqual(self.read_state()["missing_count"], 0)
        route.assert_not_called()
        start.assert_not_called()

    def test_unloaded_and_unknown_never_probe_or_bootstrap(self):
        for state in ["unloaded", "unknown"]:
            self.run_tick()
            _, _, _, route, start = self.run_tick(state=(state, None))
            route.assert_not_called()
            start.assert_not_called()
            self.assertEqual(self.read_state()["missing_count"], 0)

    def test_final_new_probe_can_prevent_kickstart(self):
        for outcome in [("occupied", 101), ("unknown", 401), ("unknown", None)]:
            with self.subTest(outcome=outcome):
                self.run_tick(now=100)
                self.run_tick(now=110)
                with mock.patch.object(watchdog, "launch_state", return_value=("stopped", None)), \
                        mock.patch.object(watchdog, "probe_route", side_effect=[("missing", 503), outcome]), \
                        mock.patch.object(watchdog, "kickstart") as start, \
                        mock.patch.object(watchdog.time, "time", return_value=120), redirect_stdout(io.StringIO()):
                    self.assertEqual(watchdog.main(self.argv), 0)
                start.assert_not_called()
                self.assertEqual(self.read_state()["missing_count"], 0)

    def test_final_local_running_or_unloaded_prevents_start(self):
        for final in [("running", 321), ("unloaded", None), ("unknown", None)]:
            with self.subTest(final=final):
                self.run_tick(now=100)
                self.run_tick(now=110)
                with mock.patch.object(watchdog, "launch_state", side_effect=[("stopped", None), final]), \
                        mock.patch.object(watchdog, "probe_route", return_value=("missing", 503)), \
                        mock.patch.object(watchdog, "kickstart") as start, \
                        mock.patch.object(watchdog.time, "time", return_value=120), redirect_stdout(io.StringIO()):
                    self.assertEqual(watchdog.main(self.argv), 0)
                start.assert_not_called()
                self.assertEqual(self.read_state()["missing_count"], 0)

    def test_failed_kickstart_also_resets_streak(self):
        self.run_tick(now=100)
        self.run_tick(now=110)
        result, record, _, _, start = self.run_tick(now=120, kick=False)
        self.assertEqual(result, 1)
        self.assertEqual(record["event"], "kickstart_failed")
        start.assert_called_once()
        self.assertEqual(self.read_state()["missing_count"], 0)

    def test_sleep_or_clock_rollback_expires_streak(self):
        for now in [171, 99]:
            with self.subTest(now=now):
                self.run_tick(now=100)
                self.run_tick(now=110)
                _, record, _, _, start = self.run_tick(now=now)
                self.assertEqual(record["event"], "route_missing")
                self.assertEqual(self.read_state()["missing_count"], 1)
                start.assert_not_called()
                self.run_tick(probe=("unknown", None), now=now)

    def test_changed_config_or_label_resets_scope(self):
        self.run_tick(now=100)
        self.run_tick(now=110)
        self.config["ORCA_RELAY_SERVER_ID"] = "other-runtime"
        self.write_config()
        self.run_tick(now=120)
        self.assertEqual(self.read_state()["missing_count"], 1)
        self.run_tick(now=130, extra=["--label", "example.other.bridge"])
        self.assertEqual(self.read_state()["missing_count"], 1)

    def test_concurrent_tick_sees_flock_and_does_nothing(self):
        store = watchdog.StateStore(str(self.state_dir))
        self.addCleanup(store.close)
        with store.locked():
            _, record, lifecycle, route, start = self.run_tick()
        self.assertEqual(record["event"], "lock_busy")
        lifecycle.assert_not_called()
        route.assert_not_called()
        start.assert_not_called()

    def test_state_is_atomic_private_and_contains_no_credentials(self):
        self.run_tick()
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)
        for path in self.state_dir.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(".tmp", path.name)
        state = (self.state_dir / "state.json").read_text()
        for value in self.config.values():
            self.assertNotIn(value, state)
        with mock.patch.object(watchdog.os, "replace", side_effect=OSError("private-test-token")):
            result, record, _, _, start = self.run_tick(now=110)
        self.assertEqual(result, 1)
        self.assertEqual(record["event"], "tick_failed")
        self.assertEqual(self.read_state()["missing_count"], 1)
        self.assertFalse(list(self.state_dir.glob("*.tmp")))
        start.assert_not_called()

    def test_unsafe_directory_config_state_and_lock_are_rejected(self):
        self.state_dir.mkdir(mode=0o755)
        self.state_dir.chmod(0o755)
        self.assertEqual(self.run_tick()[0], 1)
        self.state_dir.chmod(0o700)
        self.config_path.chmod(0o644)
        self.assertEqual(self.run_tick()[1]["event"], "config_invalid")
        self.config_path.chmod(0o600)
        state_path = self.state_dir / "state.json"
        state_path.unlink()
        state_path.symlink_to(self.config_path)
        self.assertEqual(self.run_tick()[0], 1)
        self.assertEqual(json.loads(self.config_path.read_text()), self.config)
        state_path.unlink()
        lock_path = self.state_dir / "watchdog.lock"
        lock_path.unlink()
        lock_path.symlink_to(self.config_path)
        _, _, lifecycle, _, _ = self.run_tick()
        lifecycle.assert_not_called()

    def test_symlink_directory_and_config_are_rejected(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        self.state_dir.symlink_to(actual, target_is_directory=True)
        self.assertEqual(self.run_tick()[0], 1)
        self.state_dir.unlink()
        real = self.root / "real.json"
        self.config_path.rename(real)
        self.config_path.symlink_to(real)
        self.assertEqual(self.run_tick()[1]["event"], "config_invalid")

    def test_wrong_owner_and_hardlinks_are_rejected(self):
        info = self.config_path.stat()
        fake = mock.Mock(st_uid=os.getuid() + 1, st_mode=info.st_mode, st_nlink=1)
        with mock.patch.object(watchdog.os, "fstat", return_value=fake):
            with self.assertRaises(watchdog.PrivateDataError):
                watchdog.load_config(str(self.config_path))
        os.link(self.config_path, self.root / "hardlink")
        with self.assertRaises(watchdog.PrivateDataError):
            watchdog.load_config(str(self.config_path))

    def test_invalid_config_breaks_streak_without_leaking_values(self):
        self.run_tick()
        self.config["ORCA_RELAY_TOKEN"] = "private-test-token\r\nInjected: value"
        self.write_config()
        result, record, _, route, start = self.run_tick()
        self.assertEqual(result, 1)
        self.assertEqual(record["event"], "config_invalid")
        self.assertEqual(self.read_state()["missing_count"], 0)
        self.assertNotIn("private-test-token", json.dumps(record))
        route.assert_not_called()
        start.assert_not_called()

    def test_bad_state_and_arguments_fail_closed(self):
        self.run_tick()
        (self.state_dir / "state.json").write_text("private-test-token")
        result, record, _, route, start = self.run_tick()
        self.assertEqual(result, 1)
        self.assertEqual(record["event"], "tick_failed")
        route.assert_not_called()
        start.assert_not_called()
        for extra in [["--probe-timeout", "nan"], ["--missing-threshold", "0"],
                      ["--label", "invalid/private-test-token"], ["--unknown", "private-test-token"]]:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(watchdog.main(self.argv + extra), 1)
            self.assertEqual(json.loads(output.getvalue())["event"], "tick_failed")
            self.assertNotIn("private-test-token", output.getvalue())

    def test_launchctl_only_uses_absolute_command_and_no_kill_flag(self):
        for text, expected in [("state = running\npid = 42\n", ("running", 42)),
                               ("state = active\npid = 42\n", ("running", 42)),
                               ("state = not running\n", ("stopped", None)),
                               ("state = exited\n", ("stopped", None)),
                               ("state = spawn scheduled\n", ("unknown", None)),
                               ("state = running\n", ("unknown", None)),
                               ("state = not running\npid = 42\n", ("unknown", None))]:
            with mock.patch.object(watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, self.launch_dump(text))) as run:
                self.assertEqual(watchdog.launch_state("example.bridge"), expected)
            self.assertEqual(run.call_args.args[0], ["/bin/launchctl", "print", watchdog.service_target("example.bridge")])
            self.assertNotIn("shell", run.call_args.kwargs)
        with mock.patch.object(watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 113, "")):
            self.assertEqual(watchdog.launch_state("example.bridge"), ("unloaded", None))
        with mock.patch.object(watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(watchdog.kickstart("example.bridge"))
        self.assertEqual(run.call_args.args[0], ["/bin/launchctl", "kickstart", watchdog.service_target("example.bridge")])
        self.assertNotIn("-k", run.call_args.args[0])

    def test_launchctl_real_service_envelope_ignores_nested_fields(self):
        nested = ("resource coalition = {\n\tid = 100\n\tstate = active\n\tpid = 900\n}\n"
                  "jetsam coalition = {\n\tid = 101\n\tstate = active\n}\n")
        for root, expected in [
                ("state = running\nruns = 4\npid = 42\nlast exit code = 0\n", ("running", 42)),
                ("state = active\nruns = 4\npid = 42\n", ("running", 42)),
                ("state = not running\nruns = 4\nlast exit code = 0\n", ("stopped", None)),
                ("state = exited\nruns = 4\n", ("stopped", None))]:
            with self.subTest(root=root):
                result = subprocess.CompletedProcess([], 0, self.launch_dump(root + nested))
                with mock.patch.object(watchdog.subprocess, "run", return_value=result):
                    self.assertEqual(watchdog.launch_state("example.bridge"), expected)
        with mock.patch.object(watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 113, "")):
            self.assertEqual(watchdog.launch_state("example.bridge"), ("unloaded", None))

    def test_launchctl_malformed_or_duplicate_root_fields_are_unknown(self):
        valid = self.launch_dump("state = running\npid = 42")
        cases = [
            self.launch_dump("state = running\nstate = active\npid = 42"),
            self.launch_dump("state = running\npid = 42\npid = 42"),
            self.launch_dump("state = not running\npid = 42"),
            self.launch_dump("state = not running\npid = 0"),
            self.launch_dump("state = not running\npid = malformed"),
            self.launch_dump("resource coalition = {\n\tstate = active\n\tpid = 42\n}"),
            self.launch_dump("state = running\npid = 42", label="example.wrong.bridge"),
            valid.rstrip()[:-1],
            valid + self.launch_dump("state = not running", label="example.other.bridge"),
            "state = running\npid = 42\n",  # Unwrapped output is not real launchctl output.
            valid.replace("\tstate", "    state").replace("\tpid", "    pid"),
        ]
        for text in cases:
            with self.subTest(text=text):
                with mock.patch.object(watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, text)):
                    self.assertEqual(watchdog.launch_state("example.bridge"), ("unknown", None))

    def test_real_shaped_running_tick_skips_probe_and_start(self):
        text = self.launch_dump(
            "state = running\nruns = 4\npid = 42\nlast exit code = 0\n"
            "resource coalition = {\n\tstate = active\n}\n"
            "jetsam coalition = {\n\tstate = active\n}\n",
            label="example.orca-relay.bridge")
        output = io.StringIO()
        with mock.patch.object(watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, text)) as command, \
                mock.patch.object(watchdog, "probe_route") as probe, \
                mock.patch.object(watchdog, "kickstart") as start, redirect_stdout(output):
            self.assertEqual(watchdog.main(self.argv), 0)
        self.assertEqual(json.loads(output.getvalue())["event"], "bridge_running")
        self.assertEqual(command.call_count, 1)
        probe.assert_not_called()
        start.assert_not_called()
        self.assertEqual(self.read_state()["missing_count"], 0)

    def test_http_probe_headers_unique_query_and_no_application_frames(self):
        self.config["ORCA_RELAY_URL"] += "?role=server&clientId=other&serverId=other&v=9"
        connection = mock.Mock()
        response = mock.Mock(status=101)
        connection.getresponse.return_value = response

        def headers(name, default=""):
            key = connection.request.call_args.kwargs["headers"]["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + watchdog.WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
            return {"Upgrade": "websocket", "Connection": "keep-alive, Upgrade",
                    "Sec-WebSocket-Accept": accept}.get(name, default)

        response.getheader.side_effect = headers
        with mock.patch.object(watchdog.http.client, "HTTPConnection", return_value=connection):
            for _ in range(2):
                self.assertEqual(watchdog.probe_route(self.config, 1.25), ("occupied", 101))
        queries = []
        for call in connection.request.call_args_list:
            self.assertEqual(call.args[0], "GET")
            query = parse_qs(urlsplit(call.args[1]).query)
            self.assertEqual(query["role"], ["client"])
            self.assertEqual(query["v"], ["1"])
            self.assertEqual(query["serverId"], ["runtime-example"])
            self.assertEqual(len(query["clientId"]), 1)
            self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer private-test-token")
            queries.append(query)
        self.assertNotEqual(queries[0]["clientId"], queries[1]["clientId"])
        for call in connection.sock.sendall.call_args_list:
            close = call.args[0]
            self.assertEqual(close[:2], b"\x88\x82")
            self.assertEqual(len(close), 8)
            self.assertEqual(bytes(close[6 + i] ^ close[2 + i] for i in range(2)), b"\x03\xe8")
        response.read.assert_not_called()
        self.assertEqual(response.close.call_count, 2)
        self.assertEqual(connection.close.call_count, 2)

    def test_http_statuses_tls_verification_and_network_errors_are_unknown(self):
        for status in [503, 401, 302, 500, 101]:
            with self.subTest(status=status):
                connection = mock.Mock()
                response = mock.Mock(status=status)
                response.getheader.return_value = "invalid-upgrade"
                connection.getresponse.return_value = response
                with mock.patch.object(watchdog.http.client, "HTTPConnection", return_value=connection):
                    expected = "missing" if status == 503 else "unknown"
                    self.assertEqual(watchdog.probe_route(self.config, 1), (expected, status))
                connection.sock.sendall.assert_not_called()
                response.read.assert_not_called()
                connection.close.assert_called_once()
        connection = mock.Mock()
        connection.getresponse.side_effect = OSError("private-test-token relay.example.test")
        self.config["ORCA_RELAY_URL"] = "wss://relay.example.test/ws"
        with mock.patch.object(watchdog.http.client, "HTTPSConnection", return_value=connection) as https:
            self.assertEqual(watchdog.probe_route(self.config, 2), ("unknown", None))
        context = https.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, watchdog.ssl.CERT_REQUIRED)
        connection.close.assert_called_once()

    def test_probe_wall_clock_jump_rollback_and_deadline_are_unknown(self):
        connection = mock.Mock()
        connection.getresponse.return_value = mock.Mock(status=503)
        for wall_times in [[100, 200], [100, 99]]:
            with mock.patch.object(watchdog.http.client, "HTTPConnection", return_value=connection), \
                    mock.patch.object(watchdog.time, "time", side_effect=wall_times):
                self.assertEqual(watchdog.probe_route(self.config, 1), ("unknown", 503))
        with mock.patch.object(watchdog, "_handshake_route", side_effect=TimeoutError()):
            self.assertEqual(watchdog.probe_route(self.config, 1), ("unknown", None))
        self.assertEqual(watchdog.signal.getitimer(watchdog.signal.ITIMER_REAL), (0.0, 0.0))

    def test_alarm_has_errno_for_python39_socket_readinto(self):
        with self.assertRaises(TimeoutError) as raised:
            watchdog._probe_alarm(0, None)
        self.assertEqual(raised.exception.args[0], watchdog.errno.ETIMEDOUT)
        connection = mock.Mock()
        connection.getresponse.side_effect = lambda: watchdog._probe_alarm(0, None)
        with mock.patch.object(watchdog.http.client, "HTTPConnection", return_value=connection):
            self.assertEqual(watchdog.probe_route(self.config, 1), ("unknown", None))
        connection.close.assert_called_once()

    def test_non_ascii_upgrade_is_unknown_and_breaks_streak(self):
        connection = mock.Mock()
        response = mock.Mock(status=101)
        response.getheader.side_effect = lambda name, default="": {
            "Upgrade": "websocket", "Connection": "Upgrade",
            "Sec-WebSocket-Accept": "\u00e9",
        }.get(name, default)
        connection.getresponse.return_value = response
        self.run_tick(now=100)
        self.run_tick(now=110)
        with mock.patch.object(watchdog.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(watchdog, "launch_state", return_value=("stopped", None)), \
                mock.patch.object(watchdog, "kickstart") as start, \
                mock.patch.object(watchdog.time, "time", return_value=120), redirect_stdout(io.StringIO()):
            self.assertEqual(watchdog.main(self.argv), 0)
        start.assert_not_called()
        self.assertEqual(self.read_state()["missing_count"], 0)
        self.run_tick(now=130)
        self.assertEqual(self.read_state()["missing_count"], 1)

    def test_quiet_running_suppresses_only_healthy_record(self):
        output = io.StringIO()
        with mock.patch.object(watchdog, "launch_state", return_value=("running", 42)), redirect_stdout(output):
            self.assertEqual(watchdog.main(self.argv + ["--quiet-running"]), 0)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.run_tick(extra=["--quiet-running"])[1]["event"], "route_missing")


if __name__ == "__main__":
    unittest.main()
