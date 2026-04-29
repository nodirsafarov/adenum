from __future__ import annotations

from .. import runner, ui
from ..state import Findings


async def discover_mssql(findings: Findings) -> bool:
    if 1433 in findings.target.open_ports:
        return True
    if not runner.has("nxc"):
        return False
    cmd = [runner.resolve("nxc") or "nxc", "mssql", findings.target.ip]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=20)
    if "MSSQL" in result.combined and "open" not in result.stderr.lower():
        findings.target.open_ports.add(1433)
        ui.good("MSSQL service detected on 1433")
        return True
    return False


async def mssql_anon(findings: Findings) -> None:
    if not runner.has("nxc"):
        return
    ui.section("mssql: anonymous probe")
    ui.explain(
        "MSSQL allows Windows Auth + SQL Auth. nxc tries empty/null logins, "
        "instance discovery, and version detection. SQL svc accounts often "
        "have admin rights (xp_cmdshell -> RCE)."
    )
    cmd = [runner.resolve("nxc") or "nxc", "mssql", findings.target.ip,
           "-u", "", "-p", ""]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=30)
    if "MSSQL" in result.combined:
        for line in result.stdout.splitlines():
            if line.strip().startswith("MSSQL"):
                ui.info(f"  {line.strip()[:160]}")


async def mssql_authed(findings: Findings, user: str,
                     password: str | None, ntlm_hash: str | None) -> None:
    if not runner.has("nxc"):
        return
    ui.section("mssql: authenticated checks")
    ui.explain(
        "If MSSQL svc account = sysadmin, xp_cmdshell gives SYSTEM RCE. "
        "If on AD, EXECUTE AS LOGIN can chain via linked-server hops."
    )
    cmd = [runner.resolve("nxc") or "nxc", "mssql", findings.target.ip,
           "-u", user]
    if ntlm_hash:
        cmd += ["-H", ntlm_hash]
    elif password is not None:
        cmd += ["-p", password]
    if findings.target.domain:
        cmd += ["-d", findings.target.domain]
    ui.cmd(cmd + ["[--local-auth/--exec-method]"])

    probes = [cmd + ["-q", "SELECT @@version"], cmd + ["-q", "EXEC sp_linkedservers"]]
    for probe in probes:
        ui.cmd(probe[:8] + ["[...]"])
        result = await runner.run(probe, timeout=30)
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("[") and "MSSQL" in stripped:
                ui.info(f"  {stripped[:160]}")
        if "Pwn3d!" in result.combined:
            ui.crit("MSSQL credential = sysadmin (xp_cmdshell -> RCE)")
            findings.notes.append(f"MSSQL sysadmin: {user}")
            findings.vulns.append("[HIGH] MSSQL account is sysadmin")


async def mssql_spray(findings: Findings, users: list[str], passwords: list[str]) -> None:
    if not runner.has("nxc") or not users or not passwords:
        return
    ui.section("mssql: password spray")
    ui.explain(
        "MSSQL has its own auth pool (no AD lockout for SQL Auth). "
        "Common targets: sa, sql_admin, sqlservice, dbo."
    )
    found: list[tuple[str, str]] = []
    for password in passwords:
        cmd = [runner.resolve("nxc") or "nxc", "mssql", findings.target.ip,
               "-u", users[0] if len(users) == 1 else "\n".join(users),
               "-p", password, "--continue-on-success", "--local-auth"]
        result = await runner.run(cmd, timeout=120)
        for line in result.stdout.splitlines():
            if "[+]" in line and ":" in line:
                ui.crit(f"MSSQL: {line.strip()[:160]}")
    return None


async def run_mssql(findings: Findings, *, user: str | None = None,
                   password: str | None = None, ntlm_hash: str | None = None) -> None:
    if not await discover_mssql(findings):
        return
    if user and (password or ntlm_hash):
        await mssql_authed(findings, user, password, ntlm_hash)
    else:
        await mssql_anon(findings)
