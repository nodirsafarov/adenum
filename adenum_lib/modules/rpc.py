from __future__ import annotations

import asyncio

from .. import runner, ui
from ..parsers import parse_rpc_lsaquery, parse_rpc_srvinfo
from ..state import Findings


_NULL_SCRIPT = (
    "lsaquery\n"
    "srvinfo\n"
    "enumdomusers\n"
    "enumdomgroups\n"
    "querydominfo\n"
    "getdompwinfo\n"
    "exit\n"
)


async def null_session_probe(findings: Findings) -> None:
    if not runner.has("rpcclient"):
        return
    ui.explain(
        "rpcclient -U '' -N tries a NULL session (anonymous SMB IPC$). "
        "On legacy Win2003/2008 DCs this still leaks domain SID, users and groups."
    )
    cmd = [
        runner.resolve("rpcclient") or "rpcclient",
        "-U", "", "-N", findings.target.ip,
    ]
    ui.cmd(cmd + ["<<< null-script"])
    result = await runner.run(cmd, timeout=30, stdin_data=_NULL_SCRIPT)

    if "NT_STATUS_ACCESS_DENIED" in result.combined or "LOGON_FAILURE" in result.combined:
        ui.explain("null sessions denied (modern default).")
        return

    target = findings.target
    lsa = parse_rpc_lsaquery(result.stdout)
    if lsa:
        if lsa.get("netbios_domain"):
            target.netbios_domain = target.netbios_domain or lsa["netbios_domain"]
            ui.good(f"NetBIOS domain (rpc): {target.netbios_domain}")
        if lsa.get("domain_sid"):
            findings.notes.append(f"Domain SID = {lsa['domain_sid']}")
            ui.good(f"Domain SID: {lsa['domain_sid']}")

    srv = parse_rpc_srvinfo(result.stdout)
    if srv.get("netbios_name"):
        target.netbios_name = target.netbios_name or srv["netbios_name"]
        ui.good(f"NetBIOS host (rpc): {target.netbios_name}")
    if srv.get("os_version"):
        target.os = target.os or f"Windows {srv['os_version']}"

    user_count = 0
    group_count = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("user:[") and "rid:[" in line:
            name = line.split("user:[", 1)[1].split("]", 1)[0]
            findings.add_user(name)
            user_count += 1
        elif line.startswith("group:[") and "rid:[" in line:
            name = line.split("group:[", 1)[1].split("]", 1)[0]
            findings.add_group(name)
            group_count += 1
    if user_count:
        ui.good(f"null session leaked {user_count} user(s)")
    if group_count:
        ui.good(f"null session leaked {group_count} group(s)")


async def lookupsid_rid_brute(findings: Findings, max_rid: int = 5000) -> None:
    if not runner.has("lookupsid") or 445 not in findings.target.open_ports:
        return
    ui.explain(
        "impacket-lookupsid asks the LSA RPC for SID->name mappings. "
        "Even when null sessions block enumdomusers, RID brute often works "
        "(NULL session vs guest account, depends on LSA config)."
    )
    cmd = [
        runner.resolve("lookupsid") or "impacket-lookupsid",
        f"@{findings.target.ip}", str(max_rid),
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=120)
    from ..parsers import parse_lookupsid

    entries = parse_lookupsid(result.stdout)
    if not entries:
        ui.explain("RID brute returned no entries (auth required).")
        return
    users = 0
    computers = 0
    for rid, info in entries.items():
        findings.sids[info["name"]] = f"rid={rid}"
        if info["type"].lower().startswith("user"):
            if info["name"].endswith("$"):
                findings.add_computer(info["name"].rstrip("$"))
                computers += 1
            else:
                findings.add_user(info["name"])
                users += 1
        elif info["type"].lower().startswith("group"):
            findings.add_group(info["name"])
    if users or computers:
        ui.good(f"RID brute -> {users} user(s), {computers} computer(s)")


async def run_rpc_stage0(findings: Findings) -> None:
    ui.section("rpc: null session + RID brute")
    await asyncio.gather(
        null_session_probe(findings),
        lookupsid_rid_brute(findings),
    )
