from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


@dataclass
class CmdResult:
    cmd: Sequence[str]
    rc: int
    stdout: str
    stderr: str
    elapsed: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


KNOWN_TOOLS: dict[str, str] = {
    "nmap": "nmap",
    "nxc": "nxc",
    "netexec": "netexec",
    "smbclient": "smbclient",
    "rpcclient": "rpcclient",
    "ldapsearch": "ldapsearch",
    "nbtscan": "nbtscan",
    "enum4linux": "enum4linux",
    "enum4linux-ng": "enum4linux-ng",
    "smbmap": "smbmap",
    "bloodhound-python": "bloodhound-python",
    "certipy": "certipy-ad",
    "GetNPUsers": "impacket-GetNPUsers",
    "GetUserSPNs": "impacket-GetUserSPNs",
    "secretsdump": "impacket-secretsdump",
    "lookupsid": "impacket-lookupsid",
    "psexec": "impacket-psexec",
    "wmiexec": "impacket-wmiexec",
    "getTGT": "impacket-getTGT",
    "getST": "impacket-getST",
    "GetADUsers": "impacket-GetADUsers",
    "GetADComputers": "impacket-GetADComputers",
    "addcomputer": "impacket-addcomputer",
    "atexec": "impacket-atexec",
    "smbexec": "impacket-smbexec",
    "dcomexec": "impacket-dcomexec",
    "mssqlclient": "impacket-mssqlclient",
    "ntpdate": "ntpdate",
    "rdate": "rdate",
    "dig": "dig",
    "host": "host",
    "gpp-decrypt": "gpp-decrypt",
}


def detect_tools() -> dict[str, str | None]:
    return {key: shutil.which(binary) for key, binary in KNOWN_TOOLS.items()}


def has(name: str) -> bool:
    return shutil.which(KNOWN_TOOLS.get(name, name)) is not None


def resolve(name: str) -> str | None:
    return shutil.which(KNOWN_TOOLS.get(name, name))


async def run(
    cmd: Sequence[str],
    *,
    timeout: float = 60.0,
    stdin_data: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> CmdResult:
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError:
        return CmdResult(
            cmd=cmd, rc=127, stdout="",
            stderr=f"binary not found: {cmd[0]}",
            elapsed=0.0,
        )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
        return CmdResult(
            cmd=cmd,
            rc=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            elapsed=time.monotonic() - start,
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            stdout_b, stderr_b = await proc.communicate()
        except Exception:
            stdout_b, stderr_b = b"", b""
        return CmdResult(
            cmd=cmd,
            rc=-9,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            elapsed=time.monotonic() - start,
            timed_out=True,
        )


_OPSEC_PROFILES: dict[str, dict[str, object]] = {
    "quiet":  {"concurrency": 4,  "timeout": 90.0,  "nmap_t": "-T2", "kerb_pool": 5},
    "normal": {"concurrency": 8,  "timeout": 60.0,  "nmap_t": "-T4", "kerb_pool": 20},
    "loud":   {"concurrency": 32, "timeout": 30.0,  "nmap_t": "-T5", "kerb_pool": 60},
}

_active_profile = _OPSEC_PROFILES["normal"].copy()


def set_opsec(profile: str) -> None:
    if profile not in _OPSEC_PROFILES:
        raise ValueError(f"unknown opsec profile: {profile}")
    global _active_profile
    _active_profile = _OPSEC_PROFILES[profile].copy()


def opsec(key: str, default=None):
    return _active_profile.get(key, default)


def opsec_int(key: str, default: int) -> int:
    value = _active_profile.get(key, default)
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def opsec_str(key: str, default: str) -> str:
    value = _active_profile.get(key, default)
    return str(value) if value is not None else default


async def run_many(
    commands: Iterable[Sequence[str]],
    *,
    timeout: float = 60.0,
    concurrency: int = 8,
) -> list[CmdResult]:
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(cmd: Sequence[str]) -> CmdResult:
        async with sem:
            return await run(cmd, timeout=timeout)

    return await asyncio.gather(*(_bounded(c) for c in commands))
