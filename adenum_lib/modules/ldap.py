from __future__ import annotations

from .. import runner, ui
from ..parsers import dn_to_domain, parse_ldap_rootdse
from ..state import Findings


_FUNCTIONAL_LEVELS = {
    "0": "Windows 2000",
    "1": "Windows 2003 interim",
    "2": "Windows 2003",
    "3": "Windows 2008",
    "4": "Windows 2008 R2",
    "5": "Windows 2012",
    "6": "Windows 2012 R2",
    "7": "Windows 2016",
    "10": "Windows 2025+",
}


async def rootdse(findings: Findings) -> None:
    if not runner.has("ldapsearch"):
        ui.warn("ldapsearch missing - apt install ldap-utils")
        return
    ui.explain(
        "rootDSE is an unauthenticated LDAP query. It exposes naming contexts, "
        "domain functional level, dnsHostName, ldapServiceName -> domain + DC FQDN."
    )
    cmd = [
        runner.resolve("ldapsearch") or "ldapsearch",
        "-x", "-LLL", "-H", f"ldap://{findings.target.ip}",
        "-s", "base", "-b", "", "(objectClass=*)",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=20)
    if not result.combined.strip():
        ui.warn("LDAP rootDSE returned nothing - port closed or filtered.")
        return
    if "ldap_sasl_bind" in result.stderr.lower() and not result.stdout.strip():
        ui.warn("anonymous LDAP bind denied")
        return
    fields = parse_ldap_rootdse(result.stdout)
    target = findings.target

    if dnc := fields.get("defaultnamingcontext"):
        target.domain_dn = dnc[0]
        target.domain = target.domain or dn_to_domain(dnc[0])
        ui.good(f"defaultNamingContext: {dnc[0]}  ->  domain: {target.domain}")
    if rdnc := fields.get("rootdomainnamingcontext"):
        target.forest = dn_to_domain(rdnc[0])
        if target.forest and target.forest != target.domain:
            ui.good(f"forest: {target.forest}")
    if ncs := fields.get("namingcontexts"):
        target.naming_contexts = ncs[:]
    if dh := fields.get("dnshostname"):
        target.fqdn = target.fqdn or dh[0].lower()
        target.hostname = target.hostname or dh[0].split(".")[0]
        ui.good(f"dnsHostName: {target.fqdn}")
    if sl := fields.get("ldapservicename"):
        ui.explain(f"ldapServiceName: {sl[0]} (Kerberos realm = right side of @)")
    if df := fields.get("domainfunctionality"):
        target.functional_levels["domain"] = _FUNCTIONAL_LEVELS.get(df[0], df[0])
    if ff := fields.get("forestfunctionality"):
        target.functional_levels["forest"] = _FUNCTIONAL_LEVELS.get(ff[0], ff[0])
    if dc := fields.get("domaincontrollerfunctionality"):
        target.functional_levels["dc"] = _FUNCTIONAL_LEVELS.get(dc[0], dc[0])
    if target.functional_levels:
        for key, value in target.functional_levels.items():
            ui.good(f"{key} functional level: {value}")
    if "supportedsaslmechanisms" in fields:
        ui.explain(f"SASL mechs: {', '.join(fields['supportedsaslmechanisms'])}")


async def anon_query_users(findings: Findings) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    ui.explain(
        "Some legacy domains allow anonymous LDAP read. We try (objectClass=user) "
        "with samAccountName attribute - cheapest user enumeration."
    )
    cmd = [
        runner.resolve("ldapsearch") or "ldapsearch",
        "-x", "-LLL", "-H", f"ldap://{findings.target.ip}",
        "-b", findings.target.domain_dn,
        "(&(objectCategory=person)(objectClass=user))", "samAccountName",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=30)
    if "Operations error" in result.combined or "ldap_search_ext" in result.stderr.lower():
        ui.explain("anonymous LDAP read denied (modern default).")
        return
    found = 0
    for line in result.stdout.splitlines():
        if line.lower().startswith("samaccountname:"):
            name = line.split(":", 1)[1].strip()
            if name and not name.endswith("$"):
                findings.add_user(name)
                found += 1
            elif name.endswith("$"):
                findings.add_computer(name.rstrip("$"))
    if found:
        ui.good(f"anonymous LDAP exposed {found} user(s)")


async def run_ldap_stage0(findings: Findings) -> None:
    ui.section("ldap: rootDSE + anon probe")
    await rootdse(findings)
    await anon_query_users(findings)
