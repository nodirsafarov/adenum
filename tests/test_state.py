from __future__ import annotations

from pathlib import Path

from adenum_lib.state import (
    Findings,
    TargetInfo,
    findings_from_dict,
    findings_to_dict,
    load_state,
    loot_dir,
    save_state,
)


def make_findings() -> Findings:
    target = TargetInfo(ip="10.10.10.5", domain="htb.local", open_ports={445, 389})
    findings = Findings(target=target)
    findings.add_user("Administrator")
    findings.add_computer("DC01")
    findings.add_group("Domain Admins")
    findings.asrep_hashes.append("$krb5asrep$23$user@HTB.LOCAL:deadbeef")
    return findings


def test_add_user_rejects_computer_and_group_accounts():
    findings = Findings(target=TargetInfo(ip="10.10.10.5"))
    findings.add_user(" alice ")
    findings.add_user("DC01$")
    findings.add_user("HTB\\bob")
    assert findings.users == {"alice"}


def test_add_computer_appends_dollar_sign_if_missing():
    findings = Findings(target=TargetInfo(ip="10.10.10.5"))
    findings.add_computer("DC01")
    findings.add_computer("DC02$")
    assert findings.computers == {"DC01$", "DC02$"}


def test_add_group_strips_whitespace():
    findings = Findings(target=TargetInfo(ip="10.10.10.5"))
    findings.add_group("  Domain Admins ")
    assert findings.groups == {"Domain Admins"}


def test_findings_roundtrip_through_dict():
    findings = make_findings()
    restored = findings_from_dict(findings_to_dict(findings))

    assert restored.target.ip == findings.target.ip
    assert restored.target.domain == findings.target.domain
    assert restored.target.open_ports == findings.target.open_ports
    assert restored.users == findings.users
    assert restored.computers == findings.computers
    assert restored.groups == findings.groups
    assert restored.asrep_hashes == findings.asrep_hashes


def test_save_and_load_state_roundtrip(tmp_path: Path):
    findings = make_findings()
    path = tmp_path / "state.json"

    save_state(findings, path)
    loaded = load_state(path)

    assert loaded.target.ip == findings.target.ip
    assert loaded.users == findings.users
    assert loaded.asrep_hashes == findings.asrep_hashes


def test_loot_dir_creates_directory_named_after_ip(tmp_path: Path):
    path = loot_dir("10.10.10.5", base=tmp_path)
    assert path.exists()
    assert path.is_dir()
    assert path.name == "10.10.10.5"


def test_loot_dir_sanitizes_slashes_in_ip(tmp_path: Path):
    path = loot_dir("10.10.10.0/24", base=tmp_path)
    assert path.exists()
    assert "/" not in path.name
