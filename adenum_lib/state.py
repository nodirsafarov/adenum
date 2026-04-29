from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetInfo:
    ip: str
    hostname: str | None = None
    fqdn: str | None = None
    domain: str | None = None
    domain_dn: str | None = None
    forest: str | None = None
    netbios_domain: str | None = None
    netbios_name: str | None = None
    os: str | None = None
    os_build: str | None = None
    smb_signing_required: bool | None = None
    is_dc: bool | None = None
    open_ports: set[int] = field(default_factory=set)
    services: dict[int, str] = field(default_factory=dict)
    time_skew_seconds: float | None = None
    naming_contexts: list[str] = field(default_factory=list)
    functional_levels: dict[str, str] = field(default_factory=dict)


@dataclass
class Findings:
    target: TargetInfo
    users: set[str] = field(default_factory=set)
    computers: set[str] = field(default_factory=set)
    groups: set[str] = field(default_factory=set)
    shares: list[dict] = field(default_factory=list)
    sids: dict[str, str] = field(default_factory=dict)
    asrep_hashes: list[str] = field(default_factory=list)
    kerberoast_hashes: list[str] = field(default_factory=list)
    cleartext_creds: list[tuple[str, str]] = field(default_factory=list)
    nt_hashes: list[tuple[str, str]] = field(default_factory=list)
    password_policy: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)

    def add_user(self, name: str) -> None:
        cleaned = name.strip()
        if cleaned and "$" not in cleaned and "\\" not in cleaned:
            self.users.add(cleaned)

    def add_computer(self, name: str) -> None:
        cleaned = name.strip()
        if cleaned:
            self.computers.add(cleaned if cleaned.endswith("$") else f"{cleaned}$")

    def add_group(self, name: str) -> None:
        cleaned = name.strip()
        if cleaned:
            self.groups.add(cleaned)


def loot_dir(ip: str, base: str | Path = "loot") -> Path:
    path = Path(base) / ip.replace("/", "_")
    path.mkdir(parents=True, exist_ok=True)
    return path


def findings_to_dict(findings: Findings) -> dict:
    target = findings.target
    return {
        "target": {
            "ip": target.ip,
            "hostname": target.hostname,
            "fqdn": target.fqdn,
            "domain": target.domain,
            "domain_dn": target.domain_dn,
            "forest": target.forest,
            "netbios_domain": target.netbios_domain,
            "netbios_name": target.netbios_name,
            "os": target.os,
            "os_build": target.os_build,
            "smb_signing_required": target.smb_signing_required,
            "is_dc": target.is_dc,
            "open_ports": sorted(target.open_ports),
            "services": target.services,
            "time_skew_seconds": target.time_skew_seconds,
            "naming_contexts": target.naming_contexts,
            "functional_levels": target.functional_levels,
        },
        "users": sorted(findings.users),
        "computers": sorted(findings.computers),
        "groups": sorted(findings.groups),
        "shares": findings.shares,
        "sids": findings.sids,
        "asrep_hashes": findings.asrep_hashes,
        "kerberoast_hashes": findings.kerberoast_hashes,
        "cleartext_creds": [list(pair) for pair in findings.cleartext_creds],
        "nt_hashes": [list(pair) for pair in findings.nt_hashes],
        "password_policy": findings.password_policy,
        "notes": findings.notes,
        "warnings": findings.warnings,
        "vulns": findings.vulns,
    }


def findings_from_dict(data: dict) -> Findings:
    target_data = data.get("target", {})
    target = TargetInfo(
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        fqdn=target_data.get("fqdn"),
        domain=target_data.get("domain"),
        domain_dn=target_data.get("domain_dn"),
        forest=target_data.get("forest"),
        netbios_domain=target_data.get("netbios_domain"),
        netbios_name=target_data.get("netbios_name"),
        os=target_data.get("os"),
        os_build=target_data.get("os_build"),
        smb_signing_required=target_data.get("smb_signing_required"),
        is_dc=target_data.get("is_dc"),
        open_ports=set(target_data.get("open_ports") or []),
        services={int(k): v for k, v in (target_data.get("services") or {}).items()},
        time_skew_seconds=target_data.get("time_skew_seconds"),
        naming_contexts=list(target_data.get("naming_contexts") or []),
        functional_levels=dict(target_data.get("functional_levels") or {}),
    )
    findings = Findings(target=target)
    findings.users = set(data.get("users") or [])
    findings.computers = set(data.get("computers") or [])
    findings.groups = set(data.get("groups") or [])
    findings.shares = list(data.get("shares") or [])
    findings.sids = dict(data.get("sids") or {})
    findings.asrep_hashes = list(data.get("asrep_hashes") or [])
    findings.kerberoast_hashes = list(data.get("kerberoast_hashes") or [])
    findings.cleartext_creds = [tuple(pair) for pair in (data.get("cleartext_creds") or [])]
    findings.nt_hashes = [tuple(pair) for pair in (data.get("nt_hashes") or [])]
    findings.password_policy = dict(data.get("password_policy") or {})
    findings.notes = list(data.get("notes") or [])
    findings.warnings = list(data.get("warnings") or [])
    findings.vulns = list(data.get("vulns") or [])
    return findings


def save_state(findings: Findings, path: Path) -> None:
    import json
    path.write_text(json.dumps(findings_to_dict(findings), indent=2, default=str))


def load_state(path: Path) -> Findings:
    import json
    return findings_from_dict(json.loads(path.read_text()))
