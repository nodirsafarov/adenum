from __future__ import annotations

from pathlib import Path

from .. import ui
from ..modules import dns_recon, policy, userenum
from ..state import Findings


async def run(findings: Findings, *, users_path: Path | None = None,
              wordlist: Path | None = None) -> Path | None:
    ui.banner(1, findings.target.ip,
              {"domain": findings.target.domain or "?",
               "goal": "users / groups / computers / pwpolicy"})

    if not findings.target.domain:
        ui.bad("stage 1 requires a domain. Use -d <domain> or run stage 0 first.")
        return None

    await dns_recon.run_dns(findings)
    await policy.run_policy(findings)
    written = await userenum.run_userenum(findings, wordlist=wordlist)

    print_summary(findings)
    suggest_next(findings, users_path or written)
    return written


def print_summary(findings: Findings) -> None:
    ui.section("stage 1 findings")
    ui.kv_block("collected", {
        "users": f"{len(findings.users)} ({', '.join(sorted(findings.users)[:8])}...)" if findings.users else None,
        "computers": f"{len(findings.computers)}" if findings.computers else None,
        "groups": f"{len(findings.groups)}" if findings.groups else None,
        "shares": [s["name"] for s in findings.shares] if findings.shares else None,
        "domain SID": next(
            (note.split(" = ")[1] for note in findings.notes if note.startswith("Domain SID")),
            None,
        ),
    })
    if findings.password_policy:
        ui.kv_block("password policy", findings.password_policy)
    if findings.vulns:
        ui.kv_block("[red]potential issues[/red]", {"vulns": findings.vulns})


def suggest_next(findings: Findings, users_path: Path | None) -> None:
    target = findings.target
    if not findings.users:
        ui.warn(
            "no users harvested. Try authenticated probes if you have any creds, "
            "or supply --users with a custom wordlist."
        )
        return
    if not users_path:
        return
    cmd = (
        f"adenum.py {target.ip} --domain {target.domain} "
        f"--users {users_path}"
    )
    why = (
        "stage 2 will request AS-REPs for each user (no preauth = free hash). "
        "Requires <5min clock skew with the DC - sync if needed: "
        f"sudo rdate -n {target.ip}"
    )
    ui.next_step(cmd, why)

