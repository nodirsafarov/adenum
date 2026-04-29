from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone

from .. import runner, ui
from ..parsers import parse_nmap_grepable
from ..state import Findings


AD_PORTS = "53,88,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389"


async def reverse_dns(findings: Findings) -> None:
    ip = findings.target.ip
    ui.explain("reverse DNS often discloses the AD hostname (PTR record).")
    try:
        host, _, _ = await asyncio.get_running_loop().run_in_executor(
            None, socket.gethostbyaddr, ip
        )
    except (socket.herror, socket.gaierror):
        ui.explain("no PTR record - normal in lab DNS configurations.")
        return
    if host:
        ui.good(f"PTR: {ip} -> {host}")
        findings.target.fqdn = findings.target.fqdn or host
        findings.target.hostname = findings.target.hostname or host.split(".")[0]
        if "." in host and not findings.target.domain:
            findings.target.domain = host.split(".", 1)[1]


async def nmap_quick(findings: Findings) -> None:
    if not runner.has("nmap"):
        ui.warn("nmap not installed - skipping port scan.")
        return
    ui.explain(
        "nmap -Pn --open -p <AD ports> -sV: probes the standard AD/Windows surface "
        "(Kerberos 88, LDAP 389/636, SMB 445, GC 3268, WinRM 5985, etc)."
    )
    timing_flag = runner.opsec_str("nmap_t", "-T4")
    cmd = [
        runner.resolve("nmap") or "nmap",
        "-Pn", "--open", "-p", AD_PORTS, "-sV", timing_flag,
        "-oG", "-", findings.target.ip,
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=180)
    if not result.ok:
        ui.warn(f"nmap exit={result.rc} (continuing anyway)")
    rows = parse_nmap_grepable(result.stdout)
    open_ports = [row for row in rows if row["state"] == "open"]
    for row in open_ports:
        findings.target.open_ports.add(row["port"])
        if row["service"]:
            findings.target.services[row["port"]] = (
                f"{row['service']} {row['version']}".strip()
            )
    if open_ports:
        ui.good(f"open AD ports: {sorted(p for p in findings.target.open_ports)}")
        ui.table(
            "AD-relevant ports",
            ["port", "service", "version"],
            [
                (str(row["port"]), row["service"], row["version"])
                for row in sorted(open_ports, key=lambda r: r["port"])
            ],
        )
        if 88 in findings.target.open_ports:
            findings.target.is_dc = True
            ui.good("Kerberos (88) reachable -> target is a Domain Controller")
            ui.explain("DCs always expose Kerberos. Workstations don't.")
    else:
        ui.warn("no AD ports open via nmap. Wrong host or filtered firewall?")


async def time_skew(findings: Findings) -> None:
    if 389 not in findings.target.open_ports:
        return
    ui.explain(
        "Kerberos requires <5 min skew between client and KDC. "
        "We pull AD's currentTime from rootDSE to set host clock if needed."
    )
    cmd = [
        runner.resolve("ldapsearch") or "ldapsearch",
        "-x", "-LLL", "-H", f"ldap://{findings.target.ip}",
        "-s", "base", "-b", "", "currentTime",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=15)
    for line in result.stdout.splitlines():
        if line.lower().startswith("currenttime:"):
            timestamp = line.split(":", 1)[1].strip()
            try:
                ad_time = datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue
            local_now = datetime.now(timezone.utc)
            skew = (ad_time - local_now).total_seconds()
            findings.target.time_skew_seconds = skew
            if abs(skew) > 60:
                ui.warn(
                    f"DC clock skew = {skew:+.0f}s (>60s). "
                    f"Kerberos will fail. Run: sudo rdate -n {findings.target.ip}"
                )
            else:
                ui.good(f"DC clock skew = {skew:+.0f}s (within Kerberos tolerance)")
            return


async def run_recon(findings: Findings) -> None:
    ui.section("recon: ports + DNS + time")
    await asyncio.gather(reverse_dns(findings), nmap_quick(findings))
    await time_skew(findings)
