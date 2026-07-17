from __future__ import annotations

from adenum_lib import parsers


def test_parse_nxc_smb_header_matches_host_info_line():
    # netexec/nxc prints these parenthetical fields with no space after the colon.
    line = (
        "SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 Build 17763 x64 "
        "(name:DC01) (domain:htb.local) (signing:True) (SMBv1:False)"
    )
    result = parsers.parse_nxc_smb_header(line)
    assert result == {
        "ip": "10.10.10.5",
        "host": "DC01",
        "os": "Windows Server 2019 Build 17763 x64",
        "name": "DC01",
        "domain": "htb.local",
        "signing": True,
        "smbv1": False,
    }


def test_parse_nxc_smb_header_returns_none_for_unrelated_text():
    assert parsers.parse_nxc_smb_header("nothing useful here") is None


def test_parse_lookupsid_extracts_rid_entries():
    text = (
        "500: HTB\\Administrator (SidTypeUser)\n"
        "501: HTB\\Guest (SidTypeUser)\n"
        "garbage line without rid\n"
        "513: HTB\\Domain Users (SidTypeGroup)\n"
    )
    result = parsers.parse_lookupsid(text)
    assert result[500] == {"name": "Administrator", "type": "SidTypeUser", "domain": "HTB"}
    assert result[513] == {"name": "Domain Users", "type": "SidTypeGroup", "domain": "HTB"}
    assert len(result) == 3


def test_parse_ldap_rootdse_handles_continuation_lines():
    text = (
        "dn:\n"
        "namingContexts: DC=htb,DC=local\n"
        "namingContexts: CN=Configuration,DC=htb,DC=local\n"
        "supportedLDAPVersion: 3\n"
        " continued\n"
    )
    result = parsers.parse_ldap_rootdse(text)
    assert result["namingcontexts"] == ["DC=htb,DC=local", "CN=Configuration,DC=htb,DC=local"]
    assert result["supportedldapversion"] == ["3continued"]


def test_dn_to_domain_joins_dc_components():
    assert parsers.dn_to_domain("CN=Users,DC=htb,DC=local") == "htb.local"


def test_dn_to_domain_returns_none_without_dc_components():
    assert parsers.dn_to_domain("CN=Users") is None


def test_parse_smbclient_shares_parses_table():
    text = (
        "\tSharename       Type      Comment\n"
        "\t---------       ----      -------\n"
        "\tADMIN$          Disk      Remote Admin\n"
        "\tC$              Disk      Default share\n"
        "\tIPC$            IPC       Remote IPC\n"
        "\n"
    )
    shares = parsers.parse_smbclient_shares(text)
    assert shares == [
        {"name": "ADMIN$", "type": "Disk", "comment": "Remote Admin"},
        {"name": "C$", "type": "Disk", "comment": "Default share"},
        {"name": "IPC$", "type": "IPC", "comment": "Remote IPC"},
    ]


def test_parse_smbclient_shares_empty_before_header():
    assert parsers.parse_smbclient_shares("no header here\nADMIN$  Disk  x\n") == []


def test_parse_rpc_lsaquery_extracts_domain_name_and_sid():
    text = "Domain Name: HTB\nDomain Sid: S-1-5-21-1111111111-2222222222-3333333333\n"
    result = parsers.parse_rpc_lsaquery(text)
    assert result == {
        "netbios_domain": "HTB",
        "domain_sid": "S-1-5-21-1111111111-2222222222-3333333333",
    }


def test_parse_nmap_grepable_extracts_ports():
    line = (
        "Host: 10.10.10.5 (dc01.htb.local)\tPorts: "
        "22/open/tcp//ssh//OpenSSH 8.0//, 445/open/tcp//microsoft-ds//Windows/,"
    )
    rows = parsers.parse_nmap_grepable(line)
    assert {"port": 22, "state": "open", "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.0"} in rows
    assert any(row["port"] == 445 for row in rows)


def test_parse_nmap_normal_extracts_port_table():
    text = (
        "PORT     STATE SERVICE       VERSION\n"
        "22/tcp   open  ssh           OpenSSH 8.0\n"
        "445/tcp  open  microsoft-ds\n"
        "\n"
        "MAC Address: 00:11:22:33:44:55\n"
    )
    rows = parsers.parse_nmap_normal(text)
    assert rows[0] == {
        "port": 22, "proto": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.0",
    }
    assert rows[1]["port"] == 445
    assert rows[1]["version"] == ""


def test_extract_asrep_hashes_pulls_full_hash_lines():
    text = (
        "[*] Getting TGT for user\n"
        "$krb5asrep$23$user@HTB.LOCAL:deadbeef"
        "$aabbccdd\n"
        "[*] done\n"
    )
    hashes = parsers.extract_asrep_hashes(text)
    assert len(hashes) == 1
    assert hashes[0].startswith("$krb5asrep$23$user@HTB.LOCAL:")


def test_extract_kerberoast_hashes_pulls_full_hash_lines():
    text = "$krb5tgs$23$*svc$HTB.LOCAL$HTB.LOCAL/svc*$deadbeefcafebabe\n[*] done\n"
    hashes = parsers.extract_kerberoast_hashes(text)
    assert len(hashes) == 1
    assert hashes[0].startswith("$krb5tgs$23$")


def test_dedup_preserves_order_and_strips_whitespace():
    assert parsers.dedup(["  a ", "b", "a", "", "  ", "c"]) == ["a", "b", "c"]
