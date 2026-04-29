from __future__ import annotations

from .. import runner, ui
from ..state import Findings


async def winrm_check(findings: Findings, user: str | None = None,
                     password: str | None = None,
                     ntlm_hash: str | None = None) -> None:
    if 5985 not in findings.target.open_ports and 5986 not in findings.target.open_ports:
        return
    if not runner.has("nxc"):
        return
    ui.section("winrm: PSRemoting access check")
    ui.explain(
        "WinRM (5985 HTTP / 5986 HTTPS) lets local admins / Remote Management "
        "Users run PowerShell remotely. evil-winrm = full shell. nxc winrm "
        "Pwn3d! flag confirms admin shell access."
    )
    cmd = [runner.resolve("nxc") or "nxc", "winrm", findings.target.ip]
    if user:
        cmd += ["-u", user]
        if ntlm_hash:
            cmd += ["-H", ntlm_hash]
        elif password is not None:
            cmd += ["-p", password]
    if findings.target.domain:
        cmd += ["-d", findings.target.domain]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=30)
    if "Pwn3d!" in result.combined:
        ui.crit("WinRM: Pwn3d! - full PowerShell shell available")
        findings.notes.append(f"WinRM admin: {user}")
        ui.next_step(
            f"evil-winrm -i {findings.target.ip} -u {user} "
            f"{'-H ' + ntlm_hash if ntlm_hash else '-p ' + (password or '')}",
            "evil-winrm gives an interactive PSRemoting shell. "
            "Try `whoami /priv` and `Get-LocalGroupMember Administrators`."
        )
    elif "STATUS_LOGON_FAILURE" in result.combined:
        ui.warn("WinRM: auth failed")
    else:
        ui.explain("WinRM reachable but no Pwn3d! flag.")
