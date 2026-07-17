from __future__ import annotations

from adenum_lib import wordlists


def test_merge_userlists_dedupes_case_insensitively_preserving_first_casing():
    result = wordlists.merge_userlists(["Administrator", "guest"], ["ADMINISTRATOR", "krbtgt"])
    assert result == ["Administrator", "guest", "krbtgt"]


def test_merge_userlists_strips_whitespace_and_drops_blanks():
    result = wordlists.merge_userlists([" alice ", "", "  "], ["bob"])
    assert result == ["alice", "bob"]


def test_merge_userlists_handles_no_sources():
    assert wordlists.merge_userlists() == []


def test_common_ad_users_and_passwords_are_nonempty_and_unique():
    assert len(wordlists.COMMON_AD_USERS) == len(set(wordlists.COMMON_AD_USERS))
    assert len(wordlists.COMMON_PASSWORDS) == len(set(wordlists.COMMON_PASSWORDS))
    assert "administrator" in wordlists.COMMON_AD_USERS
