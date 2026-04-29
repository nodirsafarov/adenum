<div align="center">

```
   █▀▀█ █▀▀▄ █▀▀ █▄░█ █░░█ █▀▄▀█
   █▄▄█ █░░█ █▀▀ █░▀█ █░░█ █░▀░█
   ▀░░▀ ▀▀▀░ ▀▀▀ ▀░░▀ ░▀▀▀ ▀░░░▀
```

**Active Directory Universal Enumerator**

*A staged, parallel, professional-grade AD recon framework.*
*From a bare IP address all the way to BloodHound + DCSync.*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple.svg)](https://www.kali.org/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

</div>

---

## Why adenum?

Pentesting an Active Directory environment usually means juggling **a dozen tools** — `nmap`, `nxc`, `enum4linux-ng`, `kerbrute`, `impacket-GetNPUsers`, `bloodhound-python`, `certipy-ad`, `secretsdump`, and so on. Each has its own flags, output format, and edge cases.

**adenum** wraps all of them into a single, progressive workflow:

| You have… | Run | You get |
|---|---|---|
| Just a DC IP | `adenum 10.10.10.5` | domain, hostname, OS, shares, time skew |
| + a domain | `adenum … -d htb.local` | users, groups, password policy, SRV records |
| + a userlist | `adenum … --users users.txt` | AS-REP roast hashes (hashcat 18200) |
| + valid creds | `adenum … -u admin -p Pass!` | BloodHound ZIP, NTDS.dit, ADCS findings |

Every stage **auto-suggests the next command** with the exact arguments you need.

---

## Features

### Reconnaissance
- **Stage 0 (just IP)** — nmap port scan, reverse DNS, LDAP rootDSE auto-discovery, NTP time skew, SMB host info, anonymous shares, NetBIOS enumeration
- **Stage 1 (with domain)** — RID brute force, native Python kerbrute (AS-REQ probe), anonymous LDAP user query, password policy, AD SRV records, AXFR attempt
- **Stage 2 (with userlist)** — AS-REP roasting (native + impacket fallback), automatic hash extraction in hashcat format
- **Stage 3 (with creds)** — full nxc enum, Kerberoast (TGS-REQ), BloodHound collection, secretsdump (SAM/LSA/NTDS), certipy-ad ESC1–ESC11 detection

### Aggressive checks (read-only by default)
- **NoPac** (CVE-2021-42278/42287) — MachineAccountQuota precondition check (+ active rogue computer creation with `--exploit`)
- **ZeroLogon** (CVE-2020-1472) — NetrServerAuthenticate3 zero-challenge probe (no password reset)
- **PrintNightmare** (CVE-2021-1675/34527) — spooler RPC reachability
- **PetitPotam** (CVE-2021-36942) — EFSRPC/lsarpc pipe exposure check
- **PrinterBug** — MS-RPRN coercion path detection
- **SMB signing relay** — flags hosts where ntlmrelayx is viable

### Cross-protocol pivot points
- **MSSQL** (`nxc mssql` + `impacket-mssqlclient`) — discover SQL servers, anonymous/auth probes, sysadmin detection (xp_cmdshell → RCE), linked-server enumeration
- **WinRM** (`nxc winrm`) — PSRemoting accessibility check, Pwn3d! flag → ready for `evil-winrm`
- **Multi-method execution** — try psexec / wmiexec / atexec / smbexec / dcomexec in parallel; report which RPC paths are open (different methods bypass different AV/EDR signatures)

### Advanced AD attack paths
- **Delegation enum** — unconstrained, constrained, and resource-based (RBCD)
- **LAPS / Windows LAPS** password reads (when DACL allows)
- **gMSA** (`msDS-ManagedPassword`) reads
- **GPP cpassword** hunting in SYSVOL with auto-decryption
- **Pre-Win2k computers** (password = lowercase computer name)
- **Shadow Credentials** (`msDS-KeyCredentialLink`) — certipy integration
- **AdminSDHolder** protected accounts (adminCount=1)
- **AS-REP roastable** + **Kerberoastable** account discovery via LDAP

### Passive OSINT (no traffic to target)
- DNS records — NS, MX, SOA, TXT, SPF, DMARC, CAA
- AD SRV record leak detection via public resolvers
- **crt.sh** Certificate Transparency for subdomain harvest
- **Shodan** API search (optional, requires `SHODAN_API_KEY`)
- **GitHub** code search for credential leaks (optional, via `gh` CLI)

### Operational features
- **Native Python kerbrute** — no Go binary needed; bonus: extracts AS-REP hashes during user enum
- **Lockout-aware password spray** — reads password policy first, refuses to lock accounts
- **OPSEC profiles** — `--opsec quiet|normal|loud` tunes concurrency and nmap timing
- **State persistence** — `--save-state state.json` + `--resume state.json` for long campaigns
- **Multi-target** — single IP, CIDR (`10.0.0.0/24`), or `-T targets.txt`
- **Three output formats** — rich terminal, standalone HTML with Chart.js, strict JSON
- **Educational verbose mode** — `-v` explains *why* each tool is being run

---

## Installation

### Prerequisites

- Linux (tested on **Kali 2024+**, should work on any modern distro)
- Python **3.11 or newer**
- The following tools available on `$PATH` (Kali ships them all):
  - `nxc` (NetExec) or `crackmapexec`
  - `impacket-*` suite (`GetNPUsers`, `GetUserSPNs`, `secretsdump`, `lookupsid`, `getTGT`, `getST`)
  - `ldapsearch` (`ldap-utils`)
  - `smbclient`, `rpcclient` (`samba-common-bin`)
  - `nmap`
  - `bloodhound-python`
  - `certipy-ad`
  - `dig` (`dnsutils`)
  - `gpp-decrypt` (for SYSVOL cpassword decryption)

On Kali these are all pre-installed. On Ubuntu/Debian:

```bash
sudo apt update && sudo apt install -y \
  nmap ldap-utils samba-common-bin dnsutils \
  python3-pip python3-impacket python3-ldap3
pipx install netexec
pipx install bloodhound
pipx install certipy-ad
```

### Install (one command, recommended)

```bash
pipx install git+https://github.com/nodirsafarov/adenum
```

This puts `adenum` on your `$PATH`. From anywhere:

```bash
adenum --check-tools 1.1.1.1
adenum 10.10.10.5
adenum 10.10.10.5 -d htb.local --aggressive --html report.html
```

### Or clone + install locally

```bash
git clone https://github.com/nodirsafarov/adenum
cd adenum
pipx install .
```

### Or run from source (no install)

```bash
git clone https://github.com/nodirsafarov/adenum
cd adenum
pip install -r requirements.txt
./adenum.py --check-tools 1.1.1.1
```

### Verify

```bash
adenum --check-tools 1.1.1.1
```

You should see something like:

```
[*] tool detection (31/32 available)
[+] GetADComputers         -> /usr/bin/impacket-GetADComputers
[+] GetNPUsers             -> /usr/bin/impacket-GetNPUsers
[+] bloodhound-python      -> /usr/bin/bloodhound-python
[+] certipy                -> /usr/bin/certipy-ad
...
```

### Uninstall

```bash
pipx uninstall adenum
```

---

## Quick Start

### Stage 0 — bare IP

```bash
adenum 10.10.10.5 -v
```

Discovers domain, hostname, OS, SMB signing, anonymous shares, NetBIOS, time skew. Auto-suggests the next command if a domain is found.

### Stage 1 — with domain

```bash
adenum 10.10.10.5 -d htb.local -v
```

Enumerates users (RID brute + AS-REQ kerbrute against built-in 80+ common AD names), groups, password policy, and AD SRV records. Saves harvested usernames to `loot/<ip>/users.txt`.

### Stage 2 — with a user list

```bash
adenum 10.10.10.5 -d htb.local --users loot/10.10.10.5/users.txt -v
```

Sends AS-REQs for every user. Captures AS-REP hashes from accounts that don't require preauth. Saves them in hashcat-ready format to `loot/<ip>/asrep_hashes.txt`.

```bash
hashcat -m 18200 loot/10.10.10.5/asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Stage 3 — with credentials

```bash
adenum 10.10.10.5 -d htb.local -u admin -p 'Password1!' -v
# or with NTLM hash:
adenum 10.10.10.5 -d htb.local -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -v
```

Runs nxc full enum, Kerberoasts every SPN-bearing account, collects BloodHound, attempts secretsdump (DCSync if you're DA), and runs `certipy-ad find` for ADCS issues.

### Aggressive — run everything (read-only)

```bash
adenum 10.10.10.5 -d htb.local --aggressive --html report.html
```

Runs all stages above **plus** all vulnerability checks (NoPac, ZeroLogon, PrintNightmare, PetitPotam, PrinterBug), advanced LDAP queries (delegation, LAPS, gMSA, GPP, pre2k, AdminSDHolder), and writes a standalone HTML report.

### Passive — OSINT without touching the target

```bash
adenum 10.10.10.5 -d htb.local --passive
```

Pulls DNS records, queries crt.sh for certificate transparency, optionally Shodan and GitHub. **No packets are sent to the target IP.**

### Multi-target — sweep a subnet

```bash
adenum 10.0.0.0/24
adenum -T targets.txt
```

Each target gets its own `loot/<ip>/` directory.

### State persistence — resume long campaigns

```bash
adenum 10.10.10.5 -d htb.local --aggressive --save-state campaign.json
# (interrupted)
adenum 10.10.10.5 -d htb.local --aggressive --resume campaign.json
```

A checkpoint is written after every stage, so you never have to redo work.

### OPSEC profiles

```bash
adenum 10.10.10.5 -d htb.local --opsec quiet      # IDS-aware, slow
adenum 10.10.10.5 -d htb.local --opsec normal     # default
adenum 10.10.10.5 -d htb.local --opsec loud       # maximum speed (lab only)
```

| Profile | Concurrency | Kerbrute pool | nmap timing |
|---|---|---|---|
| `quiet`  | 4  | 5  | `-T2` |
| `normal` | 8  | 20 | `-T4` |
| `loud`   | 32 | 60 | `-T5` |

---

## Output

### Terminal

Verbose mode (`-v`) is colorized and explains every command. Findings are summarized in panels at the end of each stage.

### HTML report (`--html report.html`)

Single-file standalone HTML with:
- Severity doughnut chart (CRITICAL / HIGH / MEDIUM / LOW)
- Discovery breakdown bar chart
- Vulnerabilities, users, computers, shares, captured hashes
- Suggested next commands

Open `report.html` directly in a browser — all CSS and Chart.js are embedded/CDN.

### JSON (`--json report.json`)

Strict structured dump of everything in `Findings`. Useful for piping into other tools, jq queries, or future re-imports.

### Loot directory layout

```
loot/<target_ip>/
├── users.txt                  # harvested usernames
├── asrep_hashes.txt           # AS-REP roast (hashcat -m 18200)
├── kerberoast_hashes.txt      # Kerberoast (hashcat -m 13100)
├── spray_creds.txt            # cleartext from spray
├── secretsdump.txt            # SAM/LSA/NTDS dump
├── bloodhound/                # BloodHound JSON + ZIP
├── adcs/                      # certipy output
└── sysvol/                    # downloaded GPP XMLs
```

---

## Architecture

```
pyproject.toml                       # pipx-installable, console script: adenum
adenum.py                            # source-mode launcher (./adenum.py)
adenum_lib/
├── cli.py                  # argparse + dispatch (entry point: adenum_lib.cli:main)
├── runner.py               # async subprocess + OPSEC profiles
├── ui.py                   # rich-based educational verbose console
├── state.py                # Findings dataclass + save/load
├── parsers.py              # output parsers (LDAP, nxc, lookupsid, nmap, ASREP)
├── reporters.py            # HTML (Chart.js) + JSON serializers
├── wordlists.py            # built-in common AD usernames + passwords
├── modules/
│   ├── recon.py            # nmap, reverse DNS, LDAP rootDSE, time skew
│   ├── smb.py              # nxc smb info, smbclient -L
│   ├── ldap.py             # rootDSE, anonymous user query
│   ├── rpc.py              # null session, lookupsid RID brute
│   ├── dns_recon.py        # AD SRV, AXFR
│   ├── policy.py           # password policy
│   ├── kerbrute.py         # native Python AS-REQ probe + AS-REP hash
│   ├── userenum.py         # RID brute, kerbrute, anon LDAP
│   ├── authenticated.py    # nxc full, Kerberoast, BloodHound, secretsdump, certipy
│   ├── spray.py            # lockout-aware password spray
│   ├── exploits.py         # NoPac/ZeroLogon/PrintNightmare/PetitPotam/PrinterBug
│   ├── advanced.py         # delegation, LAPS, gMSA, GPP, pre2k, shadow creds
│   ├── mssql.py            # MSSQL discovery + auth + sysadmin checks
│   ├── winrm.py            # PSRemoting accessibility
│   ├── exec.py             # multi-method execution (5 RPC paths in parallel)
│   └── passive.py          # DNS, crt.sh, Shodan, GitHub
└── stages/
    ├── stage0.py           # IP only
    ├── stage1.py           # +domain
    ├── stage2.py           # +userlist
    ├── stage3.py           # +creds
    ├── stage_passive.py
    └── stage_aggressive.py
```

---

## Honest comparison with the giants

> **Is `adenum` better than [Impacket](https://github.com/fortra/impacket) or [NetExec/CrackMapExec](https://github.com/Pennyw0rth/NetExec)?**
>
> **No.** They are mature, comprehensive frameworks battle-tested on thousands of engagements. `adenum` is a **workflow orchestrator** that uses both extensively under the hood.

What `adenum` adds **on top** of them:

| Concern | Impacket | NetExec | adenum |
|---|---|---|---|
| Low-level Kerberos primitives | ✅ canonical | uses Impacket | uses Impacket |
| Multi-protocol (SMB, LDAP, MSSQL, WinRM, SSH, RDP, …) | partial | ✅ canonical | wraps NetExec for AD subset |
| Module count | ~40 scripts | 100+ modules | ~16 focused modules |
| Educational verbose output | minimal | minimal | **explains every command** |
| Progressive stage flow (IP → domain → users → creds) | manual | manual | **built-in** |
| Auto-suggests next command | ❌ | ❌ | ✅ |
| Native AS-REQ probe + AS-REP capture in one pass | two-tool dance | two-tool dance | **single pool** |
| HTML report with charts | ❌ | ❌ (db only) | ✅ |
| State persistence + resume | ❌ | partial (db) | ✅ |
| Lockout-aware spray | partial | ✅ | ✅ |

**Use `adenum` when** you want a fast, guided AD recon flow on a fresh target and care about reporting/learning. **Reach for raw Impacket/NetExec when** you need fine-grained control or you've outgrown `adenum`'s opinionated workflow.

---

## Why a native Python kerbrute?

Most workflows do `kerbrute userenum` (Go binary) for username validation and **then** `impacket-GetNPUsers` to actually grab AS-REP hashes — two separate passes over the same userlist.

`adenum_lib/modules/kerbrute.py` is a self-contained Python implementation:

- Builds a minimal AS-REQ with only `PA-PAC-REQUEST` padata (no timestamp)
- Sends it over TCP/88 with a real socket timeout (impacket's `sendReceive` has none)
- Classifies the KDC response by error code — `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6), `KDC_ERR_PREAUTH_REQUIRED` (25), `KDC_ERR_CLIENT_REVOKED` (18), `KRB_AP_ERR_SKEW` (37), `KDC_ERR_ETYPE_NOSUPP` (14)
- Falls back to AES if the KDC rejects RC4
- **Bonus**: when an AS-REP comes back (no preauth), parses `enc-part` and emits a hashcat-formatted `$krb5asrep$23$user@DOMAIN:...` hash inline — no second tool pass needed

One pool, one userlist, both signals.

---

## Examples

### Full HTB-style workflow

```bash
# 1. fingerprint
adenum 10.10.10.161 -v

# 2. enum with discovered domain
adenum 10.10.10.161 -d htb.local -v

# 3. AS-REP roast harvested users
adenum 10.10.10.161 -d htb.local --users loot/10.10.10.161/users.txt -v
hashcat -m 18200 loot/10.10.10.161/asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# 4. cracked? full authenticated sweep
adenum 10.10.10.161 -d htb.local -u svc-alfresco -p s3rvice --aggressive --html report.html

# 5. import bloodhound ZIP into BloodHound GUI
ls loot/10.10.10.161/bloodhound/*.zip
```

### Password spraying (lockout-aware)

```bash
adenum 10.10.10.5 -d htb.local \
    --users loot/10.10.10.5/users.txt \
    --spray-pass 'Welcome2024!' \
    --aggressive
```

`adenum` reads the discovered `lockout_threshold` first and refuses to spray more passwords than `threshold - 2`.

### Stealthy passive recon for a known domain

```bash
SHODAN_API_KEY=xxx adenum 1.2.3.4 -d corp.example --passive --html osint.html
```

Subdomains via crt.sh, exposed services via Shodan, leaked references on GitHub — all without sending a packet to `1.2.3.4`.

---

## Disclaimer

> **For authorized security testing and educational use only.**
>
> Use `adenum` only against systems you own or for which you have explicit written authorization to test. Unauthorized access to computer systems is a crime in most jurisdictions. The author assumes no liability for misuse.

This is the kind of tool that ends up in CTF write-ups and home-lab tutorials. Keep it that way.

---

## Roadmap

- [x] Native AS-REQ kerbrute with hash extraction
- [x] HTML reports with Chart.js
- [x] State persistence + resume
- [x] Multi-target (CIDR + file)
- [x] OPSEC profiles
- [x] MSSQL / WinRM / multi-method exec
- [x] Active NoPac (`--exploit`)
- [x] `pipx install` installable
- [ ] Active ZeroLogon / PetitPotam destructive paths
- [ ] BloodHound CE post-collection Cypher queries
- [ ] ntlmrelayx orchestration with attacker-side listener
- [ ] Pluggable module system (`entry_points`)
- [ ] pytest suite with mocked subprocesses
- [ ] Docker image

PRs and issues are welcome.

---

## License

[MIT](./LICENSE) — © 2026 Nodir Safarov.

## Author

**Nodir Safarov** — [@nodirsafarov](https://github.com/nodirsafarov)

If `adenum` saves you time on a box, a star on the repo is appreciated. ⭐
