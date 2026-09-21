"""Shared helpers: configuration from env/CLI, logging, job state files.

Every value can come from a CLI flag or from a CI/CD variable. CLI flags win.
Variable names are the same ones used in the GitLab templates (yaml/).
"""
from __future__ import annotations

import json
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
SACLIENT_TOOL_TYPE = "Win" if IS_WINDOWS else ("Mac" if IS_MAC else "Linux")
PRESENCE_PLATFORM = "win_x64" if IS_WINDOWS else ("osx_x64" if IS_MAC else "linux_x64")
APPSCAN_EXE = "appscan.bat" if IS_WINDOWS else "appscan.sh"
if IS_WINDOWS:
    os.system("")  # enable ANSI colours in the Windows console

# ---------------------------------------------------------------- logging
_COLORS = {"INFO": "", "OK": "\033[32m", "WARN": "\033[33m", "ERR": "\033[31m", "GATE": "\033[35m"}


def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = _COLORS.get(level, "")
    reset = "\033[0m" if color else ""
    print(f"{color}[{ts}] [{level}] {msg}{reset}", flush=True)


def die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    log(msg, "ERR")
    sys.exit(code)


# ---------------------------------------------------------------- env helpers
def env(name: str, default: str | None = None, *aliases: str) -> str | None:
    """Return the first non-empty env var among name + aliases."""
    for n in (name, *aliases):
        v = os.environ.get(n)
        if v is not None and v != "":
            return v
    return default


def env_bool(name: str, default: bool = False, *aliases: str) -> bool:
    v = env(name, None, *aliases)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def env_int(name: str, default: int, *aliases: str) -> int:
    v = env(name, None, *aliases)
    try:
        return int(v) if v is not None else default
    except ValueError:
        return default


def normalize_host(url: str) -> str:
    """'https://host/', 'host:8443/' -> 'https://host:8443' (no trailing slash)."""
    u = url.strip().rstrip("/")
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u


# ---------------------------------------------------------------- job state
# Small JSON file shared between pipeline steps (scan -> report -> gate) so
# each subcommand can run as a separate `script:` line, like the bash edition.
STATE_FILE = Path(env("APPSCAN_STATE_FILE", ".appscan360-state.json"))


def state_load() -> dict:
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            log(f"State file {STATE_FILE} is corrupt, ignoring", "WARN")
    return {}


def state_save(**kv) -> dict:
    st = state_load()
    st.update({k: v for k, v in kv.items() if v is not None})
    STATE_FILE.write_text(json.dumps(st, indent=2))
    return st


def state_get(key: str, cli_value=None, required: bool = True):
    if cli_value:
        return cli_value
    v = state_load().get(key)
    if v is None and required:
        die(f"'{key}' not given and not found in {STATE_FILE}. Run the scan step first or pass --{key.replace('_', '-')}.")
    return v


def scan_name_default() -> str:
    proj = env("CI_PROJECT_NAME", "local")
    job = env("CI_JOB_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{proj}-{job}"
