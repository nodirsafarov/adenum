from __future__ import annotations

from .. import ui
from ..modules import passive
from ..state import Findings


async def run(findings: Findings) -> None:
    ui.banner(
        99, findings.target.ip,
        {"mode": "PASSIVE OSINT (no traffic to target)",
         "domain": findings.target.domain or "?"},
    )
    if not findings.target.domain:
        ui.bad("passive mode requires --domain.")
        return
    await passive.run_passive(findings)
    print_summary(findings)


def print_summary(findings: Findings) -> None:
    ui.section("passive findings")
    ui.kv_block("OSINT", {
        "domain": findings.target.domain,
        "subdomains harvested": [
            note for note in findings.notes if "crt.sh" in note or "DNS public" in note
        ],
        "vulns flagged": findings.vulns or None,
    })
