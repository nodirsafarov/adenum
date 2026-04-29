from __future__ import annotations

import asyncio
import json
import os
import urllib.parse
import urllib.request

from .. import runner, ui
from ..state import Findings, loot_dir


_DNS_RECORD_TYPES = ["NS", "MX", "SOA", "TXT", "SPF", "DMARC", "CAA"]
_AD_SRV_RECORDS = [
    "_kerberos._tcp", "_kerberos._udp",
    "_ldap._tcp", "_ldap._udp",
    "_gc._tcp", "_kerberos._tcp.dc._msdcs",
    "_ldap._tcp.dc._msdcs", "_ldap._tcp.gc._msdcs",
    "_kpasswd._tcp", "_kpasswd._udp",
]


async def _dig(name: str, record: str, server: str | None = None) -> str:
    if not runner.has("dig"):
        return ""
    cmd = [runner.resolve("dig") or "dig", "+short", "+time=3", "+tries=1"]
    if server:
        cmd.append(f"@{server}")
    cmd += [name, record]
    result = await runner.run(cmd, timeout=8)
    return result.stdout.strip() if result.ok else ""


async def passive_dns_records(findings: Findings) -> None:
    domain = findings.target.domain
    if not domain or not runner.has("dig"):
        return
    ui.section("passive: DNS recon (public resolvers)")
    ui.explain(
        "Public DNS lookups - no traffic to target. Reveals MX (mail infra), "
        "TXT (SPF, DKIM, verification tokens), NS (authoritative servers)."
    )
    rows: list[tuple[str, str]] = []
    for record in _DNS_RECORD_TYPES:
        if record == "DMARC":
            data = await _dig(f"_dmarc.{domain}", "TXT")
        elif record == "SPF":
            data = await _dig(domain, "TXT")
            data = "\n".join(line for line in data.splitlines() if "spf" in line.lower())
        else:
            data = await _dig(domain, record)
        if data:
            for line in data.splitlines()[:5]:
                rows.append((record, line.strip()))
    if rows:
        ui.table(f"DNS records for {domain}", ["type", "value"], rows[:25])
        findings.notes.append(f"DNS public: {len(rows)} records via {domain}")


async def passive_srv_via_public(findings: Findings) -> None:
    if not findings.target.domain or not runner.has("dig"):
        return
    domain = findings.target.domain
    ui.explain(
        "Some orgs leak _ldap/_kerberos SRV records via public DNS (especially "
        "split-horizon misconfigs). We probe via 1.1.1.1 / 8.8.8.8."
    )
    public_resolvers = ["1.1.1.1", "8.8.8.8"]
    leaked: list[str] = []
    for resolver in public_resolvers:
        for srv in ("_ldap._tcp", "_kerberos._tcp"):
            data = await _dig(f"{srv}.{domain}", "SRV", server=resolver)
            if data:
                for line in data.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        host = parts[3].rstrip(".").lower()
                        leaked.append(f"{srv}.{domain} -> {host} (via {resolver})")
    if leaked:
        for entry in leaked[:10]:
            ui.crit(f"public SRV leak: {entry}")
        findings.vulns.append(
            f"[MEDIUM] AD SRV records leaked via public DNS ({len(leaked)} signals)"
        )


async def passive_crt_sh(findings: Findings) -> None:
    domain = findings.target.domain
    if not domain:
        return
    ui.section(f"passive: crt.sh (Certificate Transparency for {domain})")
    ui.explain(
        "crt.sh aggregates public CT logs. Free, no API key. Reveals every "
        "subdomain that has had a TLS cert issued -> attack surface map."
    )

    def _fetch() -> list[dict]:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "adenum/0.1"})
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception:
            return []

    loop = asyncio.get_running_loop()
    entries = await loop.run_in_executor(None, _fetch)
    if not entries:
        ui.warn("crt.sh returned nothing (network or domain has no public certs).")
        return

    seen: set[str] = set()
    for entry in entries:
        for value in (entry.get("name_value") or "").split("\n"):
            cleaned = value.strip().lower().lstrip("*.")
            if cleaned and cleaned.endswith(domain):
                seen.add(cleaned)

    if not seen:
        ui.explain("crt.sh: no subdomains found.")
        return

    out_dir = loot_dir(findings.target.ip)
    path = out_dir / "subdomains_crtsh.txt"
    path.write_text("\n".join(sorted(seen)) + "\n")
    ui.good(f"crt.sh: {len(seen)} unique (sub)domain(s) -> {path}")
    for name in sorted(seen)[:15]:
        ui.info(f"  {name}")
    if len(seen) > 15:
        ui.explain(f"  ... and {len(seen) - 15} more")
    findings.notes.append(f"crt.sh exposed {len(seen)} subdomains for {domain}")


async def passive_shodan(findings: Findings) -> None:
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        ui.explain("SHODAN_API_KEY not set - skipping Shodan recon.")
        return
    if not findings.target.domain:
        return
    ui.section(f"passive: Shodan ({findings.target.domain})")
    ui.explain(
        "Shodan API: passive Internet-wide port/banner index. Reveals exposed "
        "Exchange/Outlook/Citrix/RDWeb endpoints tied to the domain."
    )

    def _query() -> dict:
        url = (
            f"https://api.shodan.io/shodan/host/search?key={api_key}"
            f"&query={urllib.parse.quote(f'hostname:{findings.target.domain}')}"
        )
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.loads(response.read())
        except Exception:
            return {}

    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, _query)
    matches = data.get("matches") or []
    if not matches:
        ui.explain("Shodan: no matches.")
        return
    rows: list[tuple[str, str, str, str]] = []
    for hit in matches[:25]:
        rows.append((
            hit.get("ip_str", "?"),
            str(hit.get("port", "?")),
            (hit.get("product") or "")[:40],
            (hit.get("hostnames") or [""])[0][:40],
        ))
    ui.table(f"Shodan {findings.target.domain}",
             ["IP", "port", "product", "hostname"], rows)
    findings.notes.append(f"Shodan: {len(matches)} hits for {findings.target.domain}")


async def passive_github(findings: Findings) -> None:
    if not runner.has("gh") or not findings.target.domain:
        return
    ui.section(f"passive: GitHub code search ({findings.target.domain})")
    ui.explain(
        "gh CLI authenticated search across public GitHub for the domain string. "
        "Looks for credential leaks, internal hostnames, scripts referencing AD."
    )
    cmd = [runner.resolve("gh") or "gh", "search", "code",
           findings.target.domain, "--limit", "20", "--json",
           "repository,path,textMatches"]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=30)
    try:
        items = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        items = []
    if not items:
        ui.explain("no GitHub hits.")
        return
    rows: list[tuple[str, str]] = []
    for item in items[:15]:
        repo = item.get("repository", {}).get("nameWithOwner", "?")
        path = item.get("path", "?")
        rows.append((repo, path))
    ui.table("GitHub leaks (manual review needed)", ["repo", "path"], rows)
    findings.notes.append(f"GitHub: {len(items)} hits referencing {findings.target.domain}")


async def run_passive(findings: Findings) -> None:
    if not findings.target.domain:
        ui.warn("passive recon needs --domain.")
        return
    await asyncio.gather(
        passive_dns_records(findings),
        passive_srv_via_public(findings),
        passive_crt_sh(findings),
        passive_shodan(findings),
        passive_github(findings),
    )
