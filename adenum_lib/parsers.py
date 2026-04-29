from __future__ import annotations

import re
from typing import Iterable


_NXC_SMB_LINE = re.compile(
    r"""
    ^SMB \s+ (?P<ip>\S+) \s+ \d+ \s+ (?P<host>\S+) \s+
    \[\*\] \s+ (?P<os>[^()]+?) \s+
    \(name: (?P<name>[^)]+) \) \s+
    \(domain: (?P<domain>[^)]+) \) \s+
    \(signing: (?P<signing>True|False) \) \s+
    \(SMBv1: (?P<smbv1>True|False) \)
    """,
    re.VERBOSE | re.IGNORECASE,
)


def parse_nxc_smb_header(text: str) -> dict | None:
    """Parse the host-info header line printed by `nxc smb <ip>`."""
    for line in text.splitlines():
        match = _NXC_SMB_LINE.search(line)
        if match:
            data = match.groupdict()
            data["signing"] = data["signing"] == "True"
            data["smbv1"] = data["smbv1"] == "True"
            return data
    return None


_RID_LINE = re.compile(
    r"S-1-5-21-[\d-]+-(?P<rid>\d+)\s+(?P<domain>[^\\]+)\\(?P<name>\S+)\s+\((?P<type>[^)]+)\)"
)


def parse_lookupsid(text: str) -> dict[int, dict[str, str]]:
    """Parse output of impacket-lookupsid: `S-1-5-21-... 1000 DOMAIN\\name (type)`."""
    out: dict[int, dict[str, str]] = {}
    for line in text.splitlines():
        match = _RID_LINE.search(line)
        if not match:
            continue
        rid = int(match.group("rid"))
        out[rid] = {
            "name": match.group("name"),
            "type": match.group("type"),
            "domain": match.group("domain"),
        }
    return out


def parse_ldap_rootdse(text: str) -> dict[str, list[str]]:
    """Parse `ldapsearch -x -H ldap://<ip> -s base -b "" '(objectClass=*)'` output.

    LDAP attribute lines look like 'name: value'. Multi-valued attrs repeat.
    Continuation lines start with a single space (RFC 2849).
    """
    fields: dict[str, list[str]] = {}
    current_key: str | None = None
    current_val_parts: list[str] = []

    def flush() -> None:
        if current_key is not None:
            fields.setdefault(current_key, []).append("".join(current_val_parts).strip())

    for raw in text.splitlines():
        if raw.startswith(" ") and current_key is not None:
            current_val_parts.append(raw[1:])
            continue
        if ":" in raw and not raw.startswith("#") and not raw.startswith("dn"):
            flush()
            key, _, value = raw.partition(":")
            current_key = key.strip().lower()
            current_val_parts = [value.lstrip()]
            continue
        flush()
        current_key, current_val_parts = None, []

    flush()
    return fields


def dn_to_domain(dn: str) -> str | None:
    parts = [piece[3:] for piece in dn.split(",") if piece.strip().lower().startswith("dc=")]
    return ".".join(parts) if parts else None


_SHARE_LINE = re.compile(r"^\s*(?P<name>\S+)\s+(?P<type>Disk|IPC|Printer)\s*(?P<comment>.*)$", re.I)


def parse_smbclient_shares(text: str) -> list[dict]:
    shares: list[dict] = []
    seen_header = False
    for line in text.splitlines():
        if "Sharename" in line and "Type" in line:
            seen_header = True
            continue
        if not seen_header:
            continue
        if line.strip().startswith("---"):
            continue
        if not line.strip():
            break
        match = _SHARE_LINE.match(line)
        if match:
            shares.append({
                "name": match.group("name"),
                "type": match.group("type"),
                "comment": match.group("comment").strip(),
            })
    return shares


_DOMAIN_NAME = re.compile(r"Domain Name:\s*(?P<name>\S+)", re.I)
_DOMAIN_SID = re.compile(r"Domain Sid:\s*(?P<sid>S-1-5-21-\S+)", re.I)


def parse_rpc_lsaquery(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if match := _DOMAIN_NAME.search(text):
        out["netbios_domain"] = match.group("name").strip()
    if match := _DOMAIN_SID.search(text):
        out["domain_sid"] = match.group("sid").strip()
    return out


_SRVINFO_LINE = re.compile(r"^\s*(?P<name>[A-Z0-9_-]+)\s+(?P<flags>[A-Za-z ]+)\s*$")


def parse_rpc_srvinfo(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "platform_id" in line:
            out["platform_id"] = line.split(":", 1)[1].strip()
        elif "os version" in line:
            out["os_version"] = line.split(":", 1)[1].strip()
        elif "server type" in line:
            out["server_type"] = line.split(":", 1)[1].strip()
        elif "Wk" in line and "Sv" in line:
            match = _SRVINFO_LINE.match(line)
            if match:
                out["netbios_name"] = match.group("name")
                out["server_flags"] = match.group("flags").strip()
    return out


_NMAP_PORT = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|closed|filtered|open\|filtered)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?$"
)


def parse_nmap_grepable(text: str) -> list[dict]:
    """Parse `nmap -oG -` output. Format:
    Host: 1.2.3.4 (host.name)\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http//Apache 2.4//
    """
    rows: list[dict] = []
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        ports_blob = line.split("Ports:", 1)[1].strip()
        for token in ports_blob.split(","):
            token = token.strip().rstrip("/")
            if not token:
                continue
            parts = token.split("/")
            if len(parts) < 5:
                continue
            try:
                rows.append({
                    "port": int(parts[0]),
                    "state": parts[1],
                    "proto": parts[2],
                    "service": parts[4],
                    "version": parts[6] if len(parts) > 6 else "",
                })
            except ValueError:
                continue
    return rows


def parse_nmap_normal(text: str) -> list[dict]:
    rows: list[dict] = []
    in_port_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("PORT") and "STATE" in stripped:
            in_port_table = True
            continue
        if in_port_table:
            if not stripped or stripped.startswith("MAC Address") or stripped.startswith("Service Info"):
                in_port_table = False
                continue
            match = _NMAP_PORT.match(stripped)
            if match:
                row = match.groupdict()
                row["port"] = int(row["port"])
                row["version"] = (row.get("version") or "").strip()
                rows.append(row)
    return rows


_ASREP_HASH = re.compile(r"^\$krb5asrep\$\d+\$\S+", re.MULTILINE)
_KERB_HASH = re.compile(r"^\$krb5tgs\$\d+\$\S+", re.MULTILINE)


def extract_asrep_hashes(text: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("$krb5asrep$"):
            if buf:
                out.append("".join(buf))
            buf = [line]
        elif buf and line.strip() and not line.startswith("[") and ":" not in line[:6]:
            buf.append(line.strip())
        else:
            if buf:
                out.append("".join(buf))
                buf = []
    if buf:
        out.append("".join(buf))
    return [hash_str for hash_str in out if hash_str.startswith("$krb5asrep$")]


def extract_kerberoast_hashes(text: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("$krb5tgs$"):
            if buf:
                out.append("".join(buf))
            buf = [line]
        elif buf and line.strip() and not line.startswith("["):
            buf.append(line.strip())
        else:
            if buf:
                out.append("".join(buf))
                buf = []
    if buf:
        out.append("".join(buf))
    return [hash_str for hash_str in out if hash_str.startswith("$krb5tgs$")]


def dedup(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out
