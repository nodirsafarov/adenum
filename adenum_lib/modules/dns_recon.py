from __future__ import annotations

import asyncio

from .. import runner, ui
from ..state import Findings


_AD_SRV_RECORDS = [
    "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp", "_kpasswd._udp",
    "_ldap._tcp", "_ldap._udp", "_gc._tcp", "_kerberos._tcp.dc._msdcs",
    "_ldap._tcp.dc._msdcs", "_ldap._tcp.gc._msdcs",
]


async def _resolve_srv(record: str, domain: str, dns_server: str) -> str | None:
    if not runner.has("dig"):
        return None
    cmd = [
        runner.resolve("dig") or "dig",
        "+short", "+time=3", "+tries=1",
        "@" + dns_server, f"{record}.{domain}", "SRV",
    ]
    result = await runner.run(cmd, timeout=8)
    if result.ok and result.stdout.strip():
        return result.stdout.strip()
    return None


async def srv_records(findings: Findings) -> None:
    if not findings.target.domain or not runner.has("dig"):
        return
    if 53 not in findings.target.open_ports:
        ui.explain("port 53 not detected as open - skipping SRV enum.")
        return
    ui.explain(
        "AD publishes service location via SRV records "
        "(_ldap._tcp, _kerberos._tcp, _gc._tcp). Querying these against the DC "
        "as DNS server reveals every DC, GC and KDC in the forest."
    )
    dns_server = findings.target.ip
    domain = findings.target.domain
    rows: list[tuple[str, str]] = []
    results = await asyncio.gather(
        *(_resolve_srv(record, domain, dns_server) for record in _AD_SRV_RECORDS)
    )
    seen_hosts: set[str] = set()
    for record, output in zip(_AD_SRV_RECORDS, results):
        if not output:
            continue
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4:
                host = parts[3].rstrip(".").lower()
                seen_hosts.add(host)
                rows.append((record, host))
    if rows:
        ui.table("AD SRV records", ["record", "target"], rows[:30])
        for host in sorted(seen_hosts):
            short = host.split(".")[0]
            findings.add_computer(short)
        if seen_hosts:
            findings.notes.append(
                f"forest hosts via SRV: {', '.join(sorted(seen_hosts))}"
            )


async def axfr_attempt(findings: Findings) -> None:
    if not findings.target.domain or not runner.has("dig"):
        return
    if 53 not in findings.target.open_ports:
        return
    ui.explain(
        "Zone transfer (AXFR) was historically open on AD-integrated DNS. "
        "Modern DCs reject it, but it's a 2-second probe worth doing."
    )
    cmd = [
        runner.resolve("dig") or "dig",
        f"@{findings.target.ip}", findings.target.domain, "AXFR",
        "+time=3", "+tries=1",
    ]
    result = await runner.run(cmd, timeout=8)
    if "Transfer failed" in result.combined or "XFR size" not in result.combined:
        ui.explain("AXFR refused (expected on hardened DCs).")
        return
    ui.crit(f"AXFR ALLOWED on {findings.target.domain}")
    findings.vulns.append(f"AXFR allowed for {findings.target.domain}")
    record_count = sum(1 for line in result.stdout.splitlines() if line and not line.startswith(";"))
    ui.good(f"received {record_count} DNS records via zone transfer")


async def run_dns(findings: Findings) -> None:
    ui.section("dns: SRV + AXFR")
    await asyncio.gather(srv_records(findings), axfr_attempt(findings))
