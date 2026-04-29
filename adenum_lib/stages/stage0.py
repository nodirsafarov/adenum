from __future__ import annotations

from .. import ui
from ..modules import recon, smb, ldap, rpc
from ..state import Findings


async def run(findings: Findings) -> None:
    ui.banner(0, findings.target.ip, {"goal": "discover domain, host, OS"})
    await recon.run_recon(findings)
    await smb.run_smb(findings)
    await ldap.run_ldap_stage0(findings)
    await rpc.run_rpc_stage0(findings)
    print_summary(findings)
    suggest_next(findings)


def print_summary(findings: Findings) -> None:
    ui.section("stage 0 findings")
    target = findings.target
    ui.kv_block("target", {
        "ip": target.ip,
        "hostname": target.hostname,
        "FQDN": target.fqdn,
        "domain": target.domain,
        "domain DN": target.domain_dn,
        "forest": target.forest,
        "NetBIOS domain": target.netbios_domain,
        "NetBIOS name": target.netbios_name,
        "OS": target.os,
        "is DC?": target.is_dc,
        "SMB signing": target.smb_signing_required,
        "open ports": sorted(target.open_ports),
        "time skew": (
            f"{target.time_skew_seconds:+.0f}s"
            if target.time_skew_seconds is not None else None
        ),
        "domain FL": target.functional_levels.get("domain"),
        "forest FL": target.functional_levels.get("forest"),
    })
    if findings.users:
        ui.kv_block("leaked from stage 0",
                    {"users": sorted(findings.users)[:30],
                     "groups": sorted(findings.groups)[:30],
                     "computers": sorted(findings.computers)[:30],
                     "shares": [s["name"] for s in findings.shares]})
    if findings.vulns:
        ui.kv_block("[red]potential issues[/red]", {"vulns": findings.vulns})


def suggest_next(findings: Findings) -> None:
    target = findings.target
    if not target.domain:
        ui.warn(
            "no domain discovered. Possible causes: "
            "(1) target is not a DC, (2) all probes blocked. "
            "Try authenticated probes if you have any creds."
        )
        return
    cmd = f"adenum.py {target.ip} --domain {target.domain}"
    why = (
        "stage 1 will run authenticated-style enumeration: "
        "user/group/computer enumeration via LDAP and RID brute, "
        "password policy, and domain-aware probes."
    )
    if target.fqdn and target.hostname:
        why += (
            f"\nTip: add '{target.ip}  {target.fqdn} {target.hostname}' to /etc/hosts "
            "so Kerberos works in stage 2/3."
        )
    ui.next_step(cmd, why)
