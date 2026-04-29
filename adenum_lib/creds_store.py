from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import ui
from .state import Findings, loot_dir


_HEADER = (
    "# adenum credential vault - one line per credential\n"
    "# Format: <type>:<user>:<credential>[:<extra>]\n"
    "# Types: password / nthash / lmhash / asrep / kerb / ticket\n"
)


def _path(findings: Findings) -> Path:
    return loot_dir(findings.target.ip) / "creds.txt"


def _existing(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def _append(findings: Findings, lines: Iterable[str]) -> int:
    path = _path(findings)
    existing = _existing(path)
    new_lines = [line for line in lines if line not in existing and not line.startswith("#")]
    if not new_lines:
        return 0
    if not path.exists():
        path.write_text(_HEADER)
    with path.open("a") as fh:
        for line in new_lines:
            fh.write(line + "\n")
    return len(new_lines)


def add_password(findings: Findings, user: str, password: str) -> None:
    if not user or password is None:
        return
    line = f"password:{user}:{password}"
    written = _append(findings, [line])
    if written:
        if (user, password) not in findings.cleartext_creds:
            findings.cleartext_creds.append((user, password))
        ui.crit(f"creds: {user}:{password}  ->  saved to creds.txt")


def add_nthash(findings: Findings, user: str, nt_hash: str) -> None:
    if not user or not nt_hash:
        return
    short = nt_hash.split(":")[-1] if ":" in nt_hash else nt_hash
    line = f"nthash:{user}:aad3b435b51404eeaad3b435b51404ee:{short}"
    written = _append(findings, [line])
    if written:
        pair = (user, short)
        if pair not in findings.nt_hashes:
            findings.nt_hashes.append(pair)
        ui.crit(f"creds: {user}::{short[:8]}...  ->  saved to creds.txt")


def add_asrep_hash(findings: Findings, user: str, hash_value: str) -> None:
    if not user or not hash_value:
        return
    line = f"asrep:{user}:{hash_value}"
    written = _append(findings, [line])
    if written and hash_value not in findings.asrep_hashes:
        findings.asrep_hashes.append(hash_value)


def add_kerberoast_hash(findings: Findings, user: str, hash_value: str) -> None:
    if not user or not hash_value:
        return
    line = f"kerb:{user}:{hash_value}"
    written = _append(findings, [line])
    if written and hash_value not in findings.kerberoast_hashes:
        findings.kerberoast_hashes.append(hash_value)


def add_ticket(findings: Findings, user: str, ticket_path: str) -> None:
    if not user or not ticket_path:
        return
    line = f"ticket:{user}:{ticket_path}"
    _append(findings, [line])


def summary(findings: Findings) -> None:
    path = _path(findings)
    if not path.exists():
        return
    raw = path.read_text().splitlines()
    counts = {"password": 0, "nthash": 0, "asrep": 0, "kerb": 0, "ticket": 0}
    for line in raw:
        kind = line.split(":", 1)[0] if ":" in line else ""
        if kind in counts:
            counts[kind] += 1
    if any(counts.values()):
        ui.kv_block(
            f"creds vault ({path})",
            {
                "passwords": counts["password"],
                "NT hashes": counts["nthash"],
                "AS-REP hashes": counts["asrep"],
                "Kerberoast": counts["kerb"],
                "tickets": counts["ticket"],
                "last update": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
            },
        )
