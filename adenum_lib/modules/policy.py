from __future__ import annotations

import re

from .. import runner, ui
from ..state import Findings


_POLICY_LINES = [
    ("Minimum password length", "min_len"),
    ("Password Complexity", "complexity"),
    ("Maximum password age", "max_age"),
    ("Minimum password age", "min_age"),
    ("Password history length", "history"),
    ("Lockout Threshold", "lockout_threshold"),
    ("Lockout Duration", "lockout_duration"),
    ("Lockout Observation", "lockout_window"),
]


async def policy_via_nxc_anon(findings: Findings) -> None:
    if not runner.has("nxc"):
        return
    ui.explain(
        "nxc smb --pass-pol pulls password complexity / lockout config. "
        "Important for safe spraying (lockout threshold = max attempts before account locks)."
    )
    cmd = [
        runner.resolve("nxc") or "nxc", "smb", findings.target.ip,
        "-u", "", "-p", "", "--pass-pol",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=30)
    if "STATUS_LOGON_FAILURE" in result.combined or "ACCESS_DENIED" in result.combined:
        ui.explain("anon password-policy blocked (modern default).")
        return
    parsed = _parse_policy(result.combined)
    if parsed:
        findings.password_policy.update(parsed)
        ui.kv_block("password policy (anonymous)", parsed)


async def policy_via_rpc_anon(findings: Findings) -> None:
    if not runner.has("rpcclient"):
        return
    cmd = [
        runner.resolve("rpcclient") or "rpcclient",
        "-U", "", "-N", findings.target.ip,
    ]
    result = await runner.run(cmd, timeout=15, stdin_data="getdompwinfo\nexit\n")
    parsed = _parse_policy(result.stdout)
    if parsed and not findings.password_policy:
        findings.password_policy.update(parsed)
        ui.kv_block("password policy (rpc anon)", parsed)


def _parse_policy(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        clean = line.strip()
        for needle, key in _POLICY_LINES:
            if needle.lower() in clean.lower():
                match = re.search(r"[:\-]\s*([^\n]+)$", clean)
                if match:
                    out[key] = match.group(1).strip()
                break
        if "min_password_length" in clean.lower():
            match = re.search(r":\s*(\d+)", clean)
            if match:
                out["min_len"] = match.group(1)
        if "password_properties" in clean.lower():
            match = re.search(r":\s*(0x\S+)", clean)
            if match:
                out["pw_properties"] = match.group(1)
    return out


async def run_policy(findings: Findings) -> None:
    if findings.password_policy:
        return
    ui.section("password policy")
    await policy_via_nxc_anon(findings)
    if not findings.password_policy:
        await policy_via_rpc_anon(findings)
    if not findings.password_policy:
        ui.explain("password policy not retrievable anonymously.")
