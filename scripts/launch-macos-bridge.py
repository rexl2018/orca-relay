#!/usr/bin/env python3
"""Exec a self-built bridge with configuration from a private JSON file.

No shell evaluation, downloads, runtime restarts or credential output.
Suitable for a user LaunchAgent; supervise SSH and Orca separately.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    config_path = Path(args.config)
    binary = Path(args.binary)
    required = {
        "ORCA_RELAY_URL",
        "ORCA_RUNTIME_WS_URL",
        "ORCA_RELAY_SERVER_ID",
        "ORCA_RELAY_TOKEN",
    }
    try:
        info = config_path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("configuration must be owned by the user and private")
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("configuration must be a regular file")
        config = json.loads(config_path.read_text())
        if not isinstance(config, dict) or set(config) != required:
            raise ValueError("configuration keys do not match bridge settings")
        if any(not isinstance(value, str) or not value or "\x00" in value for value in config.values()):
            raise ValueError("configuration contains an invalid value")
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("bridge binary must be an executable absolute path")
    except (OSError, ValueError):
        print("bridge launcher: invalid private configuration or binary", file=sys.stderr)
        return 1
    os.environ.update(config)
    os.execv(str(binary), [str(binary)])


if __name__ == "__main__":
    raise SystemExit(main())
