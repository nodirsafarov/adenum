from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys
from pathlib import Path

from . import reporters, ui
from .runner import detect_tools, set_opsec
from .stages import (
    stage0, stage1, stage2, stage3, stage_aggressive, stage_passive,
)
from .state import (
    Findings, TargetInfo, load_state, loot_dir, save_state,
)


_EXAMPLES = """\
quick reference
===============
  Stage 0  - just IP                    discover domain, host, OS
  Stage 1  - +-d DOMAIN                 enumerate users / groups / policy
  Stage 2  - +--users users.txt         AS-REP roast (no preauth hashes)
  Stage 3  - +-u USER -p PASS|-H HASH   BloodHound + secretsdump + ADCS
  Passive  - --passive (no traffic to target, only OSINT)
  Aggressive - --aggressive (vuln checks + delegation/LAPS/GPP/spray)
  Destructive - --aggressive --exploit (actually runs exploits, lab only)

examples
========
  adenum 10.10.10.5 -v
  adenum 10.10.10.5 -d htb.local -v
  adenum 10.10.10.5 -d htb.local --users users.txt -v
  adenum 10.10.10.5 -d htb.local -u admin -p Pass123 -v
  adenum 10.10.10.5 -d htb.local --aggressive --html report.html
  adenum 10.10.10.5 -d htb.local --passive
  adenum 10.10.10.5 -d htb.local --spray-pass Summer2024! --users users.txt
  adenum 10.0.0.0/24                 # CIDR sweep (each IP -> separate loot/)
  adenum -T targets.txt              # one IP per line
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="adenum",
        description="Universal Active Directory recon - staged, parallel, professional.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EXAMPLES,
    )
    parser.add_argument(
        "target", nargs="?",
        help="DC IP, single IP, CIDR (10.0.0.0/24), or omit if using -T",
    )
    parser.add_argument(
        "-T", "--targets", type=Path,
        help="file with one target per line (overrides positional)",
    )

    auth = parser.add_argument_group("AD context (stage trigger)")
    auth.add_argument("-d", "--domain", help="AD domain (htb.local)")
    auth.add_argument("--users", type=Path, help="user list file (stage 2)")
    auth.add_argument("-u", "--user", help="username for stage 3 / aggressive")
    auth.add_argument("-p", "--password", help="cleartext password")
    auth.add_argument("-H", "--hash", dest="ntlm_hash", help="NTLM hash (LM:NT or NT)")

    modes = parser.add_argument_group("modes")
    modes.add_argument("--passive", action="store_true",
                       help="passive OSINT only - no traffic to target")
    modes.add_argument("--aggressive", action="store_true",
                       help="run all aggressive modules (vuln checks, delegation, LAPS, GPP, spray)")
    modes.add_argument("--exploit", action="store_true",
                       help="enable DESTRUCTIVE exploit modules (lab only)")

    spray = parser.add_argument_group("password spraying")
    spray.add_argument("--spray-pass", dest="spray_pass",
                       help="single password to spray against all users")
    spray.add_argument("--spray-list", dest="spray_list", type=Path,
                       help="password list to spray")

    output = parser.add_argument_group("output")
    output.add_argument("--html", type=Path, help="write HTML report to file")
    output.add_argument("--json", type=Path, help="write JSON dump to file")

    state_group = parser.add_argument_group("state persistence")
    state_group.add_argument("--save-state", dest="save_state", type=Path,
                             help="save findings JSON after each stage")
    state_group.add_argument("--resume", type=Path,
                             help="resume from previously saved state.json")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--opsec", choices=["quiet", "normal", "loud"], default="normal",
                      help="quiet=stealthy/slow, normal=default, loud=fast/aggressive")
    misc.add_argument("-v", "--verbose", action="store_true",
                      help="show every command + 'why this matters' notes")
    misc.add_argument("--check-tools", action="store_true",
                      help="print tool detection summary and exit")
    return parser.parse_args(argv)


def expand_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.targets:
        for line in args.targets.read_text().splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                targets.append(clean)
    if args.target:
        if "/" in args.target:
            try:
                network = ipaddress.ip_network(args.target, strict=False)
                targets.extend(str(host) for host in network.hosts())
            except ValueError:
                ui.bad(f"invalid CIDR: {args.target}")
                sys.exit(2)
        else:
            try:
                ipaddress.ip_address(args.target)
                targets.append(args.target)
            except ValueError:
                ui.bad(f"invalid IP: {args.target!r}")
                sys.exit(2)
    if not targets:
        ui.bad("no target specified. Use a positional IP/CIDR or -T <file>.")
        sys.exit(2)
    deduped: list[str] = []
    seen: set[str] = set()
    for entry in targets:
        if entry not in seen:
            seen.add(entry)
            deduped.append(entry)
    return deduped


def show_tools() -> None:
    detected = detect_tools()
    available = sum(1 for value in detected.values() if value)
    ui.info(f"tool detection ({available}/{len(detected)} available)")
    for name in sorted(detected):
        path = detected[name]
        if path:
            ui.good(f"{name:<22} -> {path}")
        else:
            ui.bad(f"{name:<22} -> NOT FOUND")


async def run_one(ip: str, args: argparse.Namespace) -> Findings:
    if args.resume and args.resume.exists():
        findings = load_state(args.resume)
        findings.target.ip = ip
        if args.domain:
            findings.target.domain = args.domain
        ui.good(f"resumed state from {args.resume}")
    else:
        findings = Findings(target=TargetInfo(ip=ip, domain=args.domain))

    save_path = args.save_state

    def _checkpoint(label: str) -> None:
        if save_path:
            save_state(findings, save_path)
            ui.explain(f"checkpoint saved ({label}) -> {save_path}")

    if args.passive:
        if not args.domain:
            ui.bad("--passive requires --domain.")
            return findings
        await stage_passive.run(findings)
        _checkpoint("passive")
    else:
        await stage0.run(findings)
        _checkpoint("stage0")
        if args.domain or findings.target.domain:
            if args.domain and not findings.target.domain:
                findings.target.domain = args.domain
            await stage1.run(findings, users_path=args.users)
            _checkpoint("stage1")
        if args.users:
            await stage2.run(findings, users_path=args.users)
            _checkpoint("stage2")
        if args.user and (args.password or args.ntlm_hash):
            await stage3.run(
                findings, user=args.user,
                password=args.password, ntlm_hash=args.ntlm_hash,
            )
            _checkpoint("stage3")
        if args.aggressive:
            await stage_aggressive.run(
                findings, user=args.user, password=args.password,
                ntlm_hash=args.ntlm_hash,
                spray_password=args.spray_pass, spray_list=args.spray_list,
                users_path=args.users,
                enable_destructive=args.exploit,
            )
            _checkpoint("aggressive")

    return findings


async def amain(args: argparse.Namespace) -> int:
    if args.check_tools:
        show_tools()
        return 0

    ui.show_banner()
    set_opsec(args.opsec)
    if args.opsec != "normal":
        ui.info(f"OPSEC profile: [bold]{args.opsec}[/bold]")
    targets = expand_targets(args)
    if len(targets) > 1:
        ui.info(f"campaign: {len(targets)} target(s) queued")

    for index, ip in enumerate(targets, start=1):
        if len(targets) > 1:
            ui.section(f"target {ip} ({index}/{len(targets)})")
        findings = await run_one(ip, args)

        out_dir = loot_dir(ip)
        if args.html:
            html_path = args.html if len(targets) == 1 else out_dir / args.html.name
            reporters.write_html(findings, html_path)
            ui.good(f"HTML report -> {html_path}")
        if args.json:
            json_path = args.json if len(targets) == 1 else out_dir / args.json.name
            reporters.write_json(findings, json_path)
            ui.good(f"JSON dump -> {json_path}")
    return 0


def main() -> None:
    args = parse_args(sys.argv[1:])
    ui.set_verbose(args.verbose)
    try:
        sys.exit(asyncio.run(amain(args)))
    except KeyboardInterrupt:
        ui.bad("interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
