from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from .state import Findings


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>adenum report - {ip}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root {{
    --bg:#0d1117; --fg:#c9d1d9; --accent:#58a6ff; --crit:#f85149;
    --high:#ff8a4c; --med:#d29922; --low:#56d364; --card:#161b22; --border:#30363d;
  }}
  body {{ background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system,Segoe UI,sans-serif; margin:0; padding:0; }}
  header {{ background:linear-gradient(135deg,#0d1117 0%,#161b22 100%); padding:32px 48px; border-bottom:2px solid var(--accent); }}
  header h1 {{ margin:0 0 8px; font-size:32px; color:var(--accent); }}
  header .target {{ font-size:18px; color:var(--fg); margin:4px 0; }}
  header .meta {{ color:#8b949e; font-size:13px; }}
  main {{ padding:24px 48px; max-width:1400px; margin:0 auto; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:20px; margin-bottom:32px; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:20px; }}
  .card h2 {{ margin:0 0 16px; font-size:18px; color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:8px; }}
  .stat {{ display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px dashed var(--border); }}
  .stat:last-child {{ border:none; }}
  .stat .v {{ font-weight:600; color:var(--accent); }}
  .vuln {{ padding:10px; border-radius:4px; margin-bottom:8px; border-left:4px solid var(--med); background:rgba(255,255,255,0.02); }}
  .vuln.CRITICAL {{ border-left-color:var(--crit); }}
  .vuln.HIGH {{ border-left-color:var(--high); }}
  .vuln.MEDIUM {{ border-left-color:var(--med); }}
  .vuln.LOW {{ border-left-color:var(--low); }}
  .vuln .sev {{ display:inline-block; padding:2px 8px; border-radius:4px; font-weight:600; font-size:11px; margin-right:8px; }}
  .vuln.CRITICAL .sev {{ background:var(--crit); color:#000; }}
  .vuln.HIGH .sev {{ background:var(--high); color:#000; }}
  .vuln.MEDIUM .sev {{ background:var(--med); color:#000; }}
  .vuln.LOW .sev {{ background:var(--low); color:#000; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }}
  th {{ color:var(--accent); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }}
  td.mono {{ font-family:ui-monospace,Menlo,monospace; font-size:12px; }}
  .pill {{ display:inline-block; padding:2px 8px; background:var(--bg); border:1px solid var(--border); border-radius:12px; font-size:11px; margin:2px; }}
  .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:32px; }}
  .chart-box {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:20px; height:320px; }}
  .chart-box h2 {{ margin:0 0 12px; font-size:16px; color:var(--accent); }}
  details {{ margin:8px 0; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:4px; }}
  details summary {{ cursor:pointer; font-weight:600; }}
  pre {{ background:#010409; padding:12px; border-radius:4px; overflow-x:auto; font-size:12px; }}
  .next-cmd {{ background:#010409; border-left:3px solid var(--low); padding:12px; margin:8px 0; font-family:ui-monospace,Menlo,monospace; font-size:13px; }}
  footer {{ padding:24px 48px; border-top:1px solid var(--border); color:#8b949e; font-size:12px; text-align:center; }}
</style>
</head>
<body>
<header>
  <h1>adenum report</h1>
  <div class="target">{ip} {fqdn_html}</div>
  <div class="meta">domain: <b>{domain}</b> &middot; OS: {os} &middot; generated: {generated}</div>
</header>
<main>

<div class="grid">
  <div class="card">
    <h2>Target</h2>
    {target_stats}
  </div>
  <div class="card">
    <h2>Inventory</h2>
    {inventory_stats}
  </div>
  <div class="card">
    <h2>Loot</h2>
    {loot_stats}
  </div>
</div>

<div class="charts">
  <div class="chart-box"><h2>Vulnerability severity</h2><canvas id="sev_chart"></canvas></div>
  <div class="chart-box"><h2>Discovery breakdown</h2><canvas id="cat_chart"></canvas></div>
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Vulnerabilities ({vuln_count})</h2>
  {vuln_list}
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Users ({users_count})</h2>
  {users_pills}
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Computers ({computers_count})</h2>
  {computers_pills}
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Shares</h2>
  {shares_table}
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Captured hashes</h2>
  {hashes_section}
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Suggested next commands</h2>
  {next_steps}
</div>

<div class="card" style="margin-bottom:24px;">
  <h2>Notes ({notes_count})</h2>
  <ul>{notes_html}</ul>
</div>

</main>

<footer>generated by adenum.py - {generated}</footer>

<script>
new Chart(document.getElementById('sev_chart'), {{
  type:'doughnut',
  data:{{
    labels:['CRITICAL','HIGH','MEDIUM','LOW'],
    datasets:[{{
      data:{sev_data},
      backgroundColor:['#f85149','#ff8a4c','#d29922','#56d364'],
      borderColor:'#161b22', borderWidth:2
    }}]
  }},
  options:{{plugins:{{legend:{{labels:{{color:'#c9d1d9'}}}}}}}}
}});
new Chart(document.getElementById('cat_chart'), {{
  type:'bar',
  data:{{
    labels:['Users','Computers','Groups','Shares','AS-REP','Kerberoast','Cleartext','NT hash'],
    datasets:[{{
      data:{cat_data},
      backgroundColor:'#58a6ff', borderColor:'#1f6feb', borderWidth:1
    }}]
  }},
  options:{{
    plugins:{{legend:{{display:false}}}},
    scales:{{
      x:{{ticks:{{color:'#8b949e'}},grid:{{color:'#30363d'}}}},
      y:{{ticks:{{color:'#8b949e'}},grid:{{color:'#30363d'}}}}
    }}
  }}
}});
</script>
</body>
</html>
"""


def _stat(label: str, value) -> str:
    if value is None or value == "" or value == [] or value == set():
        return ""
    if isinstance(value, (list, set, tuple)):
        rendered = html.escape(", ".join(str(x) for x in value)[:200])
    else:
        rendered = html.escape(str(value))
    return f'<div class="stat"><span>{html.escape(label)}</span><span class="v">{rendered}</span></div>'


def _vuln_severity(vuln: str) -> str:
    if "[CRITICAL]" in vuln:
        return "CRITICAL"
    if "[HIGH]" in vuln:
        return "HIGH"
    if "[MEDIUM]" in vuln:
        return "MEDIUM"
    return "LOW"


def write_html(findings: Findings, out_path: Path) -> None:
    target = findings.target

    target_stats = "".join([
        _stat("IP", target.ip),
        _stat("Hostname", target.hostname),
        _stat("FQDN", target.fqdn),
        _stat("Domain", target.domain),
        _stat("Forest", target.forest),
        _stat("NetBIOS domain", target.netbios_domain),
        _stat("OS", target.os),
        _stat("Is DC", "yes" if target.is_dc else "no"),
        _stat("SMB signing required", target.smb_signing_required),
        _stat("Open ports", sorted(target.open_ports)),
        _stat("Domain functional level", target.functional_levels.get("domain")),
        _stat("Forest functional level", target.functional_levels.get("forest")),
        _stat("Time skew (s)", target.time_skew_seconds),
    ])

    inventory_stats = "".join([
        _stat("Users discovered", len(findings.users)),
        _stat("Computers discovered", len(findings.computers)),
        _stat("Groups discovered", len(findings.groups)),
        _stat("Shares enumerated", len(findings.shares)),
    ])

    loot_stats = "".join([
        _stat("AS-REP hashes", len(findings.asrep_hashes)),
        _stat("Kerberoast hashes", len(findings.kerberoast_hashes)),
        _stat("Cleartext credentials", len(findings.cleartext_creds)),
        _stat("NT hashes (secretsdump)", len(findings.nt_hashes)),
    ])

    vuln_blocks: list[str] = []
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in findings.vulns:
        severity = _vuln_severity(vuln)
        sev_counts[severity] += 1
        clean_text = vuln.replace(f"[{severity}]", "").strip()
        vuln_blocks.append(
            f'<div class="vuln {severity}"><span class="sev">{severity}</span>{html.escape(clean_text)}</div>'
        )
    vuln_list = "\n".join(vuln_blocks) or '<p>No vulnerabilities recorded.</p>'

    users_pills = "".join(
        f'<span class="pill">{html.escape(name)}</span>'
        for name in sorted(findings.users)[:200]
    ) or '<p>No users discovered.</p>'

    computers_pills = "".join(
        f'<span class="pill">{html.escape(name)}</span>'
        for name in sorted(findings.computers)[:200]
    ) or '<p>No computers discovered.</p>'

    shares_rows = "".join(
        f"<tr><td class='mono'>{html.escape(s['name'])}</td>"
        f"<td>{html.escape(s.get('type', ''))}</td>"
        f"<td>{html.escape(s.get('comment', ''))}</td></tr>"
        for s in findings.shares
    )
    shares_table = (
        f"<table><tr><th>Name</th><th>Type</th><th>Comment</th></tr>{shares_rows}</table>"
        if shares_rows else '<p>No shares enumerated.</p>'
    )

    hashes_section_parts: list[str] = []
    if findings.asrep_hashes:
        hashes_section_parts.append(
            f"<details><summary>{len(findings.asrep_hashes)} AS-REP hashes (mode 18200)</summary>"
            f"<pre>{html.escape(chr(10).join(findings.asrep_hashes[:20]))}</pre></details>"
        )
    if findings.kerberoast_hashes:
        hashes_section_parts.append(
            f"<details><summary>{len(findings.kerberoast_hashes)} Kerberoast hashes (mode 13100)</summary>"
            f"<pre>{html.escape(chr(10).join(findings.kerberoast_hashes[:20]))}</pre></details>"
        )
    if findings.cleartext_creds:
        cleartext_rendered = "\n".join(f"{u}:{p}" for u, p in findings.cleartext_creds)
        hashes_section_parts.append(
            f"<details><summary>{len(findings.cleartext_creds)} cleartext credentials</summary>"
            f"<pre>{html.escape(cleartext_rendered)}</pre></details>"
        )
    if findings.nt_hashes:
        nt_rendered = "\n".join(f"{u}:{h}" for u, h in findings.nt_hashes)
        hashes_section_parts.append(
            f"<details><summary>{len(findings.nt_hashes)} NT hashes (secretsdump)</summary>"
            f"<pre>{html.escape(nt_rendered)}</pre></details>"
        )
    hashes_section = "".join(hashes_section_parts) or '<p>No hashes captured.</p>'

    next_steps_blocks: list[str] = []
    if findings.target.domain and not findings.users:
        next_steps_blocks.append(
            f'<div class="next-cmd">adenum.py {target.ip} -d {target.domain} -v</div>'
        )
    if findings.users and not findings.asrep_hashes:
        next_steps_blocks.append(
            f'<div class="next-cmd">adenum.py {target.ip} -d {target.domain} '
            f'--users loot/{target.ip}/users.txt -v</div>'
        )
    if findings.cleartext_creds:
        for user, password in findings.cleartext_creds[:3]:
            next_steps_blocks.append(
                f'<div class="next-cmd">adenum.py {target.ip} -d {target.domain} '
                f'-u {html.escape(user)} -p {html.escape(password)} -v</div>'
            )
    if findings.asrep_hashes:
        next_steps_blocks.append(
            f'<div class="next-cmd">hashcat -m 18200 loot/{target.ip}/asrep_hashes.txt '
            '/usr/share/wordlists/rockyou.txt</div>'
        )
    if findings.kerberoast_hashes:
        next_steps_blocks.append(
            f'<div class="next-cmd">hashcat -m 13100 loot/{target.ip}/kerberoast_hashes.txt '
            '/usr/share/wordlists/rockyou.txt</div>'
        )
    next_steps = "\n".join(next_steps_blocks) or '<p>No specific suggestions.</p>'

    notes_html = "".join(
        f"<li>{html.escape(note)}</li>" for note in findings.notes[:50]
    ) or "<li>No notes.</li>"

    cat_data = [
        len(findings.users), len(findings.computers), len(findings.groups),
        len(findings.shares), len(findings.asrep_hashes),
        len(findings.kerberoast_hashes), len(findings.cleartext_creds),
        len(findings.nt_hashes),
    ]

    rendered = _HTML_TEMPLATE.format(
        ip=html.escape(target.ip),
        fqdn_html=f"({html.escape(target.fqdn)})" if target.fqdn else "",
        domain=html.escape(target.domain or "?"),
        os=html.escape(target.os or "?"),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"),
        target_stats=target_stats,
        inventory_stats=inventory_stats,
        loot_stats=loot_stats,
        vuln_count=len(findings.vulns),
        vuln_list=vuln_list,
        users_count=len(findings.users),
        users_pills=users_pills,
        computers_count=len(findings.computers),
        computers_pills=computers_pills,
        shares_table=shares_table,
        hashes_section=hashes_section,
        next_steps=next_steps,
        notes_count=len(findings.notes),
        notes_html=notes_html,
        sev_data=json.dumps([
            sev_counts["CRITICAL"], sev_counts["HIGH"],
            sev_counts["MEDIUM"], sev_counts["LOW"],
        ]),
        cat_data=json.dumps(cat_data),
    )

    out_path.write_text(rendered)


def write_json(findings: Findings, out_path: Path) -> None:
    target = findings.target
    payload = {
        "target": {
            "ip": target.ip, "hostname": target.hostname, "fqdn": target.fqdn,
            "domain": target.domain, "forest": target.forest,
            "netbios_domain": target.netbios_domain, "netbios_name": target.netbios_name,
            "os": target.os, "is_dc": target.is_dc,
            "smb_signing_required": target.smb_signing_required,
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
        "password_policy": findings.password_policy,
        "asrep_hashes": findings.asrep_hashes,
        "kerberoast_hashes": findings.kerberoast_hashes,
        "cleartext_creds": [
            {"user": user, "password": password}
            for user, password in findings.cleartext_creds
        ],
        "nt_hashes": [
            {"user": user, "nt_hash": nt_hash}
            for user, nt_hash in findings.nt_hashes
        ],
        "vulns": findings.vulns,
        "notes": findings.notes,
        "warnings": findings.warnings,
        "generated_at": datetime.now().isoformat(),
    }
    out_path.write_text(json.dumps(payload, indent=2, default=str))
