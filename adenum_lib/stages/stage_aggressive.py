from __future__ import annotations

from pathlib import Path

from .. import ui
from ..modules import advanced, exec as exec_mod, exploits, mssql, spray, winrm
from ..state import Findings


async def run(
    findings: Findings, *,
    user: str | None = None,
    password: str | None = None,
    ntlm_hash: str | None = None,
    spray_password: str | None = None,
    spray_list: Path | None = None,
    users_path: Path | None = None,
    enable_destructive: bool = False,
) -> None:
    ui.banner(
        88, findings.target.ip,
        {"mode": "AGGRESSIVE",
         "destructive": "yes (--exploit)" if enable_destructive else "no (read-only)",
         "auth": "creds" if user else "anon"},
    )

    creds_pair = None
    if user and (password or ntlm_hash):
        creds_pair = (user, password or ntlm_hash or "")

    await exploits.run_exploit_checks(findings, with_creds=creds_pair)

    await mssql.run_mssql(findings, user=user, password=password, ntlm_hash=ntlm_hash)

    if user and (password or ntlm_hash):
        await winrm.winrm_check(findings, user, password, ntlm_hash)

    await advanced.run_advanced(
        findings, user=user, password=password, ntlm_hash=ntlm_hash,
    )

    if user and (password or ntlm_hash):
        await exec_mod.multi_exec(
            findings, user=user, password=password, ntlm_hash=ntlm_hash,
        )

    if spray_password or spray_list or users_path:
        await spray.run_spray(
            findings,
            users_path=users_path,
            passwords_path=spray_list,
            single_password=spray_password,
        )

    if enable_destructive and user and (password or ntlm_hash):
        await exploits.run_destructive_exploits(
            findings, user=user, password=password, ntlm_hash=ntlm_hash,
        )

    print_summary(findings)
    from .. import creds_store
    creds_store.summary(findings)


def print_summary(findings: Findings) -> None:
    ui.section("aggressive summary")
    ui.kv_block("collected", {
        "users": len(findings.users),
        "computers": len(findings.computers),
        "vulns": len(findings.vulns),
        "cleartext creds": len(findings.cleartext_creds),
        "AS-REP hashes": len(findings.asrep_hashes),
        "Kerberoast hashes": len(findings.kerberoast_hashes),
        "NT hashes": len(findings.nt_hashes),
    })
    if findings.vulns:
        ui.kv_block("[red]vulnerabilities[/red]", {
            "items": findings.vulns[:15],
        })
    if findings.cleartext_creds:
        ui.kv_block("[red]captured creds[/red]", {
            "creds": [f"{u}:{p}" for u, p in findings.cleartext_creds[:8]],
        })
