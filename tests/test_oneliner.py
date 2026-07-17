from __future__ import annotations

from adenum_lib import oneliner
from adenum_lib.state import Findings, TargetInfo


def test_emit_for_credential_with_password_suggests_winrm_and_secretsdump(capsys):
    target = TargetInfo(ip="10.10.10.5", domain="htb.local", open_ports={5985})
    findings = Findings(target=target)

    oneliner.emit_for_credential(findings, "administrator", password="Passw0rd!")
    out = capsys.readouterr().out

    # Rich wraps the panel to terminal width, so check for tokens rather than
    # full lines that could be split across wrapped rows.
    assert "evil-winrm" in out
    assert "impacket-secretsdump" in out
    assert "bloodhound-python" in out


def test_emit_for_credential_with_hash_uses_dash_h_flag(capsys):
    target = TargetInfo(ip="10.10.10.5", open_ports=set())
    findings = Findings(target=target)
    nt_hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

    oneliner.emit_for_credential(findings, "administrator", nt_hash=nt_hash)
    out = capsys.readouterr().out

    assert "-H" in out
    assert nt_hash.split(":")[-1] in out


def test_emit_for_credential_mssql_command_only_when_port_1433_open(capsys):
    target = TargetInfo(ip="10.10.10.5", open_ports={1433})
    findings = Findings(target=target)

    oneliner.emit_for_credential(findings, "sa", password="secret")
    out = capsys.readouterr().out

    assert "impacket-mssqlclient" in out


def test_emit_for_userlist_noop_without_domain(capsys):
    findings = Findings(target=TargetInfo(ip="10.10.10.5", domain=None))
    oneliner.emit_for_userlist(findings, user_count=5)
    assert capsys.readouterr().out == ""


def test_emit_for_userlist_suggests_asrep_roast_when_domain_known(capsys):
    findings = Findings(target=TargetInfo(ip="10.10.10.5", domain="htb.local"))
    oneliner.emit_for_userlist(findings, user_count=5)
    out = capsys.readouterr().out
    assert "AS-REP roast" in out


def test_emit_for_asrep_noop_when_no_hashes(capsys):
    findings = Findings(target=TargetInfo(ip="10.10.10.5"))
    oneliner.emit_for_asrep(findings, hash_count=0)
    assert capsys.readouterr().out == ""


def test_emit_for_asrep_suggests_hashcat_and_john(capsys):
    findings = Findings(target=TargetInfo(ip="10.10.10.5"))
    oneliner.emit_for_asrep(findings, hash_count=2)
    out = capsys.readouterr().out
    assert "hashcat -m 18200" in out
    assert "john --format=krb5asrep" in out
