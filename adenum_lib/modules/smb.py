from __future__ import annotations

import asyncio

from .. import runner, ui
from ..parsers import parse_nxc_smb_header, parse_smbclient_shares
from ..state import Findings


async def nxc_smb_info(findings: Findings, creds: dict | None = None) -> None:
    if not runner.has("nxc"):
        ui.warn("nxc (netexec) not installed - skipping SMB info probe.")
        return
    ui.explain(
        "nxc smb prints OS, hostname, NetBIOS name, domain, signing flag and SMBv1 "
        "in a single line - the fastest way to confirm the target is AD."
    )
    cmd = [runner.resolve("nxc") or "nxc", "smb", findings.target.ip]
    if creds:
        cmd += ["-u", creds["user"], "-p", creds["password"]]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=30)
    info = parse_nxc_smb_header(result.combined)
    if not info:
        ui.warn("nxc returned no parseable SMB header")
        if result.combined.strip():
            ui.explain(result.combined.splitlines()[0][:160])
        return
    target = findings.target
    target.os = target.os or info["os"].strip()
    target.hostname = target.hostname or info["name"]
    target.netbios_name = target.netbios_name or info["name"]
    target.netbios_domain = target.netbios_domain or info["domain"].split(".")[0].upper()
    if info["domain"] and "." in info["domain"]:
        target.domain = target.domain or info["domain"].lower()
        target.fqdn = target.fqdn or f"{info['name']}.{info['domain']}".lower()
    elif info["domain"] and not target.domain:
        target.domain = info["domain"].lower()
    target.smb_signing_required = info["signing"]
    ui.good(f"OS:        {target.os}")
    ui.good(f"hostname:  {target.hostname}")
    ui.good(f"domain:    {target.domain or info['domain']}")
    ui.good(f"signing:   {info['signing']}  smbv1: {info['smbv1']}")
    if not info["signing"]:
        findings.vulns.append("SMB signing not required - relay attacks possible")
        ui.warn("SMB signing NOT required -> ntlmrelayx is viable")


async def smbclient_list_shares(findings: Findings) -> None:
    if not runner.has("smbclient"):
        return
    ui.explain(
        "smbclient -N lists shares anonymously. NETLOGON/SYSVOL exposure leaks "
        "GPP cpasswords; non-default Disk shares often hold secrets."
    )
    cmd = [
        runner.resolve("smbclient") or "smbclient",
        "-N", "-L", f"//{findings.target.ip}",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=20)
    if "NT_STATUS_ACCESS_DENIED" in result.combined:
        ui.warn("anonymous share listing denied (expected on hardened DCs).")
        return
    shares = parse_smbclient_shares(result.stdout)
    if not shares:
        return
    findings.shares = shares
    ui.table(
        "shares (anonymous)",
        ["name", "type", "comment"],
        [(share["name"], share["type"], share["comment"]) for share in shares],
    )
    interesting = [s for s in shares if s["name"].upper() not in {"ADMIN$", "C$", "IPC$", "PRINT$"}]
    if interesting:
        findings.notes.append(
            f"non-default shares: {', '.join(s['name'] for s in interesting)}"
        )


async def enum4linux_ng_quick(findings: Findings) -> None:
    if not runner.has("enum4linux-ng"):
        return
    ui.explain(
        "enum4linux-ng -A runs SMB/RPC/LDAP probes (sessions, OS, password policy, "
        "users via RID, groups, shares) - exhaustive but a bit noisy."
    )
    cmd = [
        runner.resolve("enum4linux-ng") or "enum4linux-ng",
        "-A", "-oJ", "-", findings.target.ip,
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=180)
    if not result.combined.strip():
        return
    parsed_users = 0
    for line in result.combined.splitlines():
        clean = line.strip()
        if clean.startswith("user:") and "username:" in clean.lower():
            continue
        if "[+] User" in clean and "(" in clean:
            name = clean.split("(")[-1].split(")")[0].split("\\")[-1]
            findings.add_user(name)
            parsed_users += 1
        elif "Group:" in clean and "(" in clean:
            name = clean.split("(")[-1].split(")")[0]
            findings.add_group(name)
    if parsed_users:
        ui.good(f"enum4linux-ng harvested {parsed_users} user(s)")


async def run_smb(findings: Findings, creds: dict | None = None) -> None:
    ui.section("smb: host info + shares")
    await asyncio.gather(
        nxc_smb_info(findings, creds=creds),
        smbclient_list_shares(findings),
    )
