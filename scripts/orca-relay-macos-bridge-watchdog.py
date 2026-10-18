#!/usr/bin/env python3
"""Run one conservative recovery tick for an already loaded Mac bridge agent.

Schedule ticks with launchd. Probe the relay itself (or its SSH local forward),
not a public proxy: only that relay's 503 means the selected route is absent.
A live local bridge or a successful client WebSocket upgrade prevents recovery.
This helper never bootstraps agents, replaces running processes, sends adapter
frames, or restarts Orca, SSH, proxies or remote services.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit
import uuid


LAUNCHCTL = "/bin/launchctl"
MISSING_MAX_AGE = 60.0
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CONFIG_KEYS = {
    "ORCA_RELAY_URL", "ORCA_RUNTIME_WS_URL", "ORCA_RELAY_SERVER_ID", "ORCA_RELAY_TOKEN",
}


class PrivateDataError(Exception):
    """Private input or state failed validation; never include its contents."""


class LockBusy(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error can echo user-supplied values.
        raise PrivateDataError()


def diagnostic(event, threshold, *, http_status=None, missing_count=0, pid=None):
    record = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "threshold": threshold,
        "missing_count": missing_count,
    }
    if http_status is not None:
        record["http_status"] = http_status
    if pid is not None:
        record["pid"] = pid
    print(json.dumps(record, sort_keys=True), flush=True)


def _check_private_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise PrivateDataError()


def _open_private_file(name, flags=os.O_RDONLY, *, dir_fd=None):
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 0o600, dir_fd=dir_fd)
    try:
        _check_private_file(fd)
    except Exception:
        os.close(fd)
        raise
    return fd


def _read_json(fd, limit):
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        text = stream.read(limit + 1)
    if len(text) > limit:
        raise PrivateDataError()
    return json.loads(text)


def load_config(path):
    if not Path(path).is_absolute():
        raise PrivateDataError()
    try:
        config = _read_json(_open_private_file(path), 65536)
        if not isinstance(config, dict) or set(config) != CONFIG_KEYS:
            raise PrivateDataError()
        if any(not isinstance(value, str) or not value
               or any(ord(char) < 32 or ord(char) == 127 for char in value)
               for value in config.values()):
            raise PrivateDataError()
        endpoint = urlsplit(config["ORCA_RELAY_URL"])
        if (endpoint.scheme not in {"ws", "wss"} or not endpoint.hostname
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.fragment or not endpoint.path
                or endpoint.port == 0):
            raise PrivateDataError()
        # http.client encodes headers as Latin-1. Reject rather than print failures.
        config["ORCA_RELAY_TOKEN"].encode("latin-1")
        return config
    except (OSError, ValueError, UnicodeError) as exc:
        raise PrivateDataError() from exc


class StateStore:
    def __init__(self, path):
        if not Path(path).is_absolute():
            raise PrivateDataError()
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(self.fd)
            if (info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise PrivateDataError()
        except Exception:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    @contextmanager
    def locked(self):
        fd = _open_private_file("watchdog.lock", os.O_RDWR | os.O_CREAT, dir_fd=self.fd)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LockBusy() from exc
            yield
        finally:
            os.close(fd)

    def read_streak(self, scope, now):
        try:
            fd = _open_private_file("state.json", dir_fd=self.fd)
        except FileNotFoundError:
            return 0, None
        try:
            state = _read_json(fd, 4096)
            if not isinstance(state, dict) or set(state) != {
                    "version", "scope", "missing_count", "last_missing"}:
                raise PrivateDataError()
            count, last = state["missing_count"], state["last_missing"]
            if (state["version"] != 1 or type(count) is not int or not 0 <= count <= 1000000
                    or (state["scope"] is not None and not isinstance(state["scope"], str))
                    or (count and (type(last) not in {float, int} or not math.isfinite(last)))):
                raise PrivateDataError()
            if (not count or state["scope"] != scope or last > now
                    or now - last > MISSING_MAX_AGE):
                return 0, None
            return count, last
        except (ValueError, UnicodeError) as exc:
            raise PrivateDataError() from exc

    def write(self, scope=None, missing_count=0, last_missing=None):
        # Validate an existing destination before replacing it, including on reset.
        try:
            existing = _open_private_file("state.json", dir_fd=self.fd)
        except FileNotFoundError:
            pass
        else:
            os.close(existing)
        data = json.dumps({"version": 1, "scope": scope,
                           "missing_count": missing_count, "last_missing": last_missing}) + "\n"
        temporary = ".state-" + uuid.uuid4().hex + ".tmp"
        try:
            fd = _open_private_file(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                    dir_fd=self.fd)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, "state.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass


def service_target(label):
    return "gui/{}/{}".format(os.getuid(), label)


def launch_state(label):
    """Return (running|stopped|unloaded|unknown, pid), without relaying output."""
    try:
        result = subprocess.run([LAUNCHCTL, "print", service_target(label)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, timeout=2, check=False)
        if result.returncode:
            return "unloaded", None
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if (len(lines) < 3 or lines[0] != service_target(label) + " = {"
                or lines[-1] != "}" or any(not line.startswith("\t") for line in lines[1:-1])):
            return "unknown", None
        # launchctl's service fields have exactly one TAB. Resource/ jetsam
        # coalitions have their own nested state and pid; never use those here.
        fields = [re.fullmatch(r"\t(state|pid) = ([^\r\n]*)", line)
                  for line in lines[1:-1]]
        states = [field.group(2).strip() for field in fields if field and field.group(1) == "state"]
        pids = [field.group(2).strip() for field in fields if field and field.group(1) == "pid"]
        if len(states) != 1 or len(pids) > 1:
            return "unknown", None
        pid = int(pids[0]) if pids else None
        if states[0].strip() in {"running", "active"} and pid and pid > 0:
            return "running", pid
        if states[0].strip() in {"not running", "exited"} and not pids:
            return "stopped", None
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return "unknown", None


def kickstart(label):
    try:
        result = subprocess.run([LAUNCHCTL, "kickstart", service_target(label)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=3, check=False)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _handshake_route(config, timeout):
    """Handshake only: never send an adapter Open or application message."""
    connection = None
    response = None
    status = None
    try:
        endpoint = urlsplit(config["ORCA_RELAY_URL"])
        query = urlencode({"role": "client", "serverId": config["ORCA_RELAY_SERVER_ID"],
                           "clientId": "bridge-watchdog-" + uuid.uuid4().hex, "v": "1"})
        target = endpoint.path + "?" + query
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        if endpoint.scheme == "wss":
            connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port,
                                                     timeout=timeout, context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=timeout)
        connection.request("GET", target, headers={
            "Authorization": "Bearer " + config["ORCA_RELAY_TOKEN"],
            "Upgrade": "websocket", "Connection": "Upgrade",
            "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13",
        })
        response = connection.getresponse()
        status = response.status
        if status == 503:
            return "missing", status
        if status == 101:
            expected = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
            if (response.getheader("Upgrade", "").strip().lower() == "websocket"
                    and "upgrade" in response.getheader("Connection", "").lower().replace(" ", "").split(",")
                    and hmac.compare_digest(response.getheader("Sec-WebSocket-Accept", "").strip(), expected)):
                # A standard masked Close(1000), never an adapter or Orca frame.
                # The socket already has the bounded probe timeout.
                mask = os.urandom(4)
                payload = b"\x03\xe8"
                close = b"\x88\x82" + mask + bytes(
                    value ^ mask[index % 4] for index, value in enumerate(payload))
                try:
                    if connection.sock is not None:
                        connection.sock.sendall(close)
                except OSError:
                    pass  # Occupancy is already established; still close locally.
                return "occupied", status
        return "unknown", status
    except (OSError, ValueError, TypeError, UnicodeError, http.client.HTTPException):
        return "unknown", status
    finally:
        # Closing the upgraded socket removes this unique temporary relay client.
        # Do not read bodies, send application data or open a local runtime session.
        if response is not None:
            try:
                response.close()
            except OSError:
                pass
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


def _fresh_sample(start_wall, start_mono, max_age):
    wall_age, mono_age = time.time() - start_wall, time.monotonic() - start_mono
    return (math.isfinite(wall_age) and math.isfinite(mono_age)
            and 0 <= wall_age <= max_age and 0 <= mono_age <= max_age
            and abs(wall_age - mono_age) <= 1.0)


def _probe_alarm(signum, frame):
    # Python 3.9 socket.SocketIO.readinto inspects OSError.args[0].
    raise TimeoutError(errno.ETIMEDOUT, "probe deadline")


@contextmanager
def _probe_deadline(timeout):
    # This single-tick CLI runs on the main thread. A real-time deadline also
    # bounds slowly trickled HTTP headers instead of resetting for every recv.
    # Do not take over a timer installed by an embedding caller.
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ValueError()
    previous = signal.signal(signal.SIGALRM, _probe_alarm)
    try:
        signal.setitimer(signal.ITIMER_REAL, timeout)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def probe_route(config, timeout):
    wall, mono = time.time(), time.monotonic()
    try:
        with _probe_deadline(timeout):
            outcome, status = _handshake_route(config, timeout)
    except (OSError, ValueError):
        return "unknown", None
    if not _fresh_sample(wall, mono, timeout + 1.0):
        return "unknown", status
    return outcome, status


def _tick_locked(args, store, now):
    tick_mono = time.monotonic()
    state, pid = launch_state(args.label)
    if state != "stopped":
        store.write()
        if state != "running" or not args.quiet_running:
            diagnostic({"running": "bridge_running", "unloaded": "bridge_not_loaded"}.get(
                state, "launchctl_unknown"), args.missing_threshold, pid=pid)
        return 0
    try:
        config = load_config(args.config)
    except PrivateDataError:
        store.write()
        diagnostic("config_invalid", args.missing_threshold)
        return 1
    scope = hashlib.sha256(json.dumps([args.label, config], sort_keys=True).encode("utf-8")).hexdigest()
    count, previous_missing = store.read_streak(scope, now)
    # Keep the old streak only in memory until a fresh 503 is established. An
    # exception or interrupted probe must not leave an old near-threshold streak.
    store.write(scope)
    outcome, status = probe_route(config, args.probe_timeout)
    if outcome != "missing":
        store.write(scope)
        diagnostic("owner_present" if outcome == "occupied" else "probe_unknown",
                   args.missing_threshold, http_status=status)
        return 0
    # Re-read after the probe: a sleep before or during it cannot preserve an
    # otherwise expired pre-probe streak.
    now_after_probe = time.time()
    if (previous_missing is None or now_after_probe < previous_missing
            or now_after_probe - previous_missing > MISSING_MAX_AGE):
        count = 0
    if not _fresh_sample(now, tick_mono, args.probe_timeout + 3.0):
        store.write(scope)
        diagnostic("probe_unknown", args.missing_threshold, http_status=status)
        return 0
    count += 1
    if count < args.missing_threshold:
        store.write(scope, count, now_after_probe)
        diagnostic("route_missing", args.missing_threshold, http_status=status, missing_count=count)
        return 0
    # Discard the streak before final checks, including if the process is interrupted.
    store.write(scope)
    outcome, status = probe_route(config, args.probe_timeout)
    if outcome != "missing":
        diagnostic("owner_present" if outcome == "occupied" else "probe_unknown",
                   args.missing_threshold, http_status=status)
        return 0
    # Recheck local lifecycle immediately before attempting a start. Never use -k:
    # launchctl must not kill a process that starts concurrently after this check.
    state, pid = launch_state(args.label)
    if not _fresh_sample(now, tick_mono, 2 * args.probe_timeout + 6.0):
        diagnostic("probe_unknown", args.missing_threshold, http_status=status)
        return 0
    if state != "stopped":
        diagnostic("recheck_prevented_start", args.missing_threshold, http_status=status, pid=pid)
        return 0
    started = kickstart(args.label)
    diagnostic("bridge_kickstarted" if started else "kickstart_failed",
               args.missing_threshold, http_status=status)
    return 0 if started else 1


def main(argv=None):
    threshold = 3
    store = None
    try:
        parser = SafeArgumentParser(description=__doc__)
        parser.add_argument("--config", required=True)
        parser.add_argument("--state-dir", required=True)
        parser.add_argument("--label", required=True)
        parser.add_argument("--missing-threshold", type=int, default=3)
        parser.add_argument("--probe-timeout", type=float, default=3.0)
        parser.add_argument("--quiet-running", action="store_true")
        args = parser.parse_args(argv)
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", args.label)
                or not 1 <= args.missing_threshold <= 1000000
                or not math.isfinite(args.probe_timeout) or not 0 < args.probe_timeout <= 30):
            raise PrivateDataError()
        threshold = args.missing_threshold
        store = StateStore(args.state_dir)
        with store.locked():
            return _tick_locked(args, store, time.time())
    except LockBusy:
        diagnostic("lock_busy", threshold)
        return 0
    except Exception:
        # Never emit exception text: it may contain endpoints, headers or secrets.
        diagnostic("tick_failed", threshold)
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    sys.exit(main())
