"""Outputs: report.html (tiles, decisions, top deviations, compliance per tier, site, environment and area with the trend, a heat map of
servers by area, exceptions and every finding), review-pack.md (one page for the monthly security and infrastructure review), and the
CSVs: server-compliance, deviations, drift, exceptions-review, findings and actions."""
from __future__ import annotations

import csv
import html
from pathlib import Path

from .checks import CAUSE_LABEL, GROUPS, RED, areas, summary
from .model import FILES, Data

e = html.escape
TODO = "**[TO COMPLETE]**"


def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _d(x) -> str:
    return "" if x is None else x.isoformat()


def _day(x) -> str:
    return "–" if x is None else f"{x:%d %b %Y}"


def _f(x, nd: int = 1) -> str:
    return "" if x is None else f"{x:.{nd}f}"


def _p(x) -> str:
    return "–" if x is None else f"{x:.1f} %"


def _val(r) -> str:
    return r.value.actual if r.value and r.value.source != "missing" else ""


def _src(r) -> str:
    return r.value.source if r.value else "missing"


# ---------------------------------------------------------------- csv

def write_servers(rv: dict, path: Path) -> None:
    _w(path, ["server", "site", "tier", "role", "environment", "owner", "os", "ou", "state", "last_collected", "days_since_collection",
              "applicable", "compliant", "exceptions", "deviations", "not_configured", "compliance_pct", "target_pct", "high_risk",
              "new_drift", "risk_score", "main_cause"],
       [[s.server, s.site, s.tier, s.role, s.environment, s.owner, s.os, s.ou, r["state"], r["collected"].strftime("%Y-%m-%d %H:%M")
         if r["collected"] else "", "" if r["age"] is None else r["age"], r["applicable"], r["compliant"], r["exception"],
         r["deviation"], r["missing"], _f(r["pct"]), _f(r["target"], 0), r["high_risk"], r["new_drift"], _f(r["risk"], 0), r["cause"]]
        for r in rv["servers"] for s in [r["server"]]])


def write_deviations(rv: dict, path: Path) -> None:
    rows = [r for r in rv["results"] if r.status != "compliant"]
    rows.sort(key=lambda r: (not r.rule.high_risk, r.status == "exception", r.server.server, r.rule.id))
    _w(path, ["server", "site", "tier", "environment", "setting_id", "area", "name", "expected", "actual", "source", "gpo", "status",
              "severity", "high_risk", "new_drift", "cause", "exception_ticket", "exception_state", "reference", "owner"],
       [[r.server.server, r.server.site, r.server.tier, r.server.environment, r.rule.id, r.rule.area, r.rule.name, r.rule.expected_text,
         _val(r), _src(r), r.value.gpo if r.value else "", r.status, r.rule.severity, "yes" if r.rule.high_risk else "no",
         "yes" if r.new_drift else "no", r.cause_text, r.exception.ticket if r.exception else "", r.exc_state, r.rule.reference,
         r.server.owner] for r in rows])


def drift_rows(d: Data, rv: dict) -> list[list]:
    out = []
    prev_servers = {srv for (srv, _) in (d.previous or {})}
    for r in rv["results"]:
        if not r.prev_status:
            continue
        cur = _val(r)
        if r.new_drift:
            ch = "new drift"
        elif r.prev_status in ("deviation", "missing") and r.ok:
            ch = "resolved"
        elif r.prev_status != r.status:
            ch = f"{r.prev_status} to {r.status}"
        elif r.prev_value != cur:
            ch = "changed value"
        else:
            continue
        out.append([r.server.server, r.server.site, r.server.tier, r.rule.id, r.rule.name, r.prev_value, cur, r.prev_status, r.status, ch,
                    r.cause_text, "yes" if r.rule.high_risk else "no"])
    if d.previous is not None:
        for s in rv["servers"]:
            if s["reporting"] and s["server"].server not in prev_servers:
                out.append([s["server"].server, s["server"].site, s["server"].tier, "", "", "", "", "", "", "new server", "", ""])
    order = {"new drift": 0, "new server": 2, "resolved": 3}
    out.sort(key=lambda x: (order.get(x[9], 1), x[11] != "yes", x[0], x[3]))
    return out


def write_drift(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["server", "site", "tier", "setting_id", "name", "previous_value", "current_value", "previous_status", "current_status",
              "change", "cause", "high_risk"], drift_rows(d, rv))


def write_exceptions(rv: dict, path: Path) -> None:
    _w(path, ["server", "setting_id", "name", "approved_value", "actual", "reason", "approver", "ticket", "expires", "days_to_expiry",
              "state", "action"],
       [[x.server, x.id, r.name if r else "", x.approved, ex["actual"], x.reason, x.approver, x.ticket, _d(x.expires),
         "" if ex["days"] is None else ex["days"], ex["state"], ex["action"]] for ex in rv["exceptions"]
        for x, r in [(ex["exception"], ex["rule"])]])


def write_findings(rv: dict, path: Path) -> None:
    _w(path, ["severity", "code", "group", "title", "subject", "detail", "action", "servers", "count", "owner", "due"],
       [[f.severity, f.code, GROUPS[f.group], f.title, f.subject, f.detail, f.action, "; ".join(f.servers), f.count, f.owner, _d(f.due)]
        for f in rv["findings"]])


def actions(rv: dict) -> list:
    return [(f"A-{i:03d}", f) for i, f in enumerate(rv["findings"], 1)]


def write_actions(rv: dict, path: Path) -> None:
    _w(path, ["ref", "severity", "code", "subject", "action", "servers", "owner", "due", "done"],
       [[ref, f.severity, f.code, f.subject, f.action, f.count, f.owner, _d(f.due), ""] for ref, f in actions(rv)])


# ---------------------------------------------------------------- the review pack

def _md(x) -> str:
    return str(x).replace("|", "/").replace("\n", " ")


def pack_md(d: Data, rv: dict, title: str) -> str:
    s = d.settings
    sm = summary(d, rv)
    prev = f" (last review {_p(sm['prev_pct'])})" if sm["prev_pct"] is not None else ""
    out = [f"# {title}", "",
           f"> Prepared on {d.as_of:%a %d %b %Y} from the collection listed at the end, for the monthly security and infrastructure "
           "review. Read-only: no server or GPO was changed. Approved, valid exceptions count as compliant; thresholds are in "
           f"settings.json. Sections marked {TODO} are for the meeting.", "",
           f"**{sm['status']}. Baseline compliance {_p(sm['pct'])}{prev} on {sm['reporting']} of {sm['servers']} servers and "
           f"{sm['settings']} settings; {sm['high_risk']} high-risk deviations on {sm['high_risk_servers']} servers.**", "",
           "## Headlines", ""]
    out.append(f"- {sm['below']} servers below their tier's target; {sm['new_drift']} settings drifted since the last review on "
               f"{sm['new_drift_servers']} servers.")
    for f in [f for f in rv["findings"] if f.code in ("GPO-NOTAPPLIED", "DRF-NEW") and f.severity == RED][:4]:
        out.append(f"- **{_md(f.subject)}** ({_md(f.title.lower())}): {_md(f.detail)}")
    for f in [f for f in rv["findings"] if f.code == "EXC-EXPIRED"]:
        out.append(f"- Expired exception: **{_md(f.subject)}**.")
    st = [f for f in rv["findings"] if f.code in ("HYG-STALE", "HYG-NOTCOLLECTED", "HYG-UNKNOWN")]
    if st:
        out.append("- Coverage: " + "; ".join(_md(f.subject) for f in st) + ".")
    out.append(f"- {sm['red']} red and {sm['amber']} amber findings; {sm['decisions']} decisions needed.")
    out += ["", "## Decisions needed", "", "Fix, accept as a time-limited exception, or change the baseline.", "",
            "| # | Decision | Options | Proposed | Owner | Needed by | Outcome |", "|---|---|---|---|---|---|---|"]
    out += [f"| {x.id} | **{_md(x.decision)}**<br>{_md(x.why)} | {_md(x.options)} | {_md(x.proposed)} | {_md(x.owner)} | "
            f"{_day(x.needed_by)} | |" for x in rv["decisions"]] or ["| – | No decisions needed | | | | | |"]
    out += ["", "## High-risk items", "", "| Ref | Setting | Servers | Cause | Owner | Due | Done |", "|---|---|---|---|---|---|---|"]
    refs = {id(f): ref for ref, f in actions(rv)}
    hr = [f for f in rv["findings"] if f.code == "RISK-HIGH"]
    for f in hr:
        cause = f.detail.split("Cause: ")[-1].rstrip(".")
        out.append(f"| {refs[id(f)]} | **{_md(f.subject)}** | {f.count}: {_md(', '.join(f.servers[:6]))}{' …' if f.count > 6 else ''} | "
                   f"{_md(cause)} | {_md(f.owner)} | {_day(f.due)} | |")
    if not hr:
        out.append("| – | No high-risk deviations | | | | | |")
    out += ["", "## Compliance", "", "| Scope | Compliance | Last review | Off baseline | High risk | New drift |", "|---|---|---|---|---|---|",
            f"| **All** | **{_p(rv['overall']['pct'])}** | {_p(rv['previous']['pct']) if rv['previous'] else '–'} | "
            f"{rv['overall']['deviation'] + rv['overall']['missing']} | {rv['overall']['high_risk']} | {rv['overall']['new_drift']} |"]
    for label, rows in (("", rv["tiers"]), ("Site ", rv["sites"]), ("Environment ", rv["envs"])):
        for k, x in rows:
            out.append(f"| {label}{_md(k)} | {_p(x['pct'])} | | {x['deviation'] + x['missing']} | {x['high_risk']} | {x['new_drift']} |")
    out += ["", "## Other actions", "", "Every finding is an action in `actions.csv` with owner and due date; every deviation per server "
            "and setting is in `deviations.csv`, and what changed since the last review in `drift.csv`.", "",
            "| Ref | Severity | Action | Owner | Due | Done |", "|---|---|---|---|---|---|"]
    for ref, f in actions(rv):
        if f.code == "RISK-HIGH":
            continue
        if f.severity == RED or f.code in ("GPO-OU", "GPO-OTHER", "EXC-INCOMPLETE", "EXC-EXPIRING", "HYG-STALE", "CMP-SERVER"):
            out.append(f"| {ref} | {f.severity} | **{_md(f.subject)}**: {_md(f.action)} | {_md(f.owner)} | {_day(f.due)} | |")
    out += ["", "## Audit evidence (ISO 27001 / NIS2)", "",
            f"- Baseline: {sm['settings']} settings with their reference (`baseline.csv`); exceptions register with approver, ticket and "
            f"expiry ({sm['exceptions']} exceptions, `exceptions-review.csv`).",
            f"- Measurement: settings collected from {sm['reporting']} servers, {sm['checks']:,} checks; compliance per server in "
            "`server-compliance.csv`; deviations with their cause in `deviations.csv`.",
            "- Monitoring of change: drift since the last review in `drift.csv`; Group Policy results per server.",
            "- Treatment: actions with owner and due date in `actions.csv`; decisions and outcome in this pack.",
            f"- Coverage gaps stated, not hidden: {sm['stale']} servers not reporting are counted with their last known values.", "",
            "## Scope and sources", "", f"- Organisation: {s.organisation}", f"- Review date: {d.as_of:%a %d %b %Y %H:%M}" +
            (f"; previous review {s.previous_review:%d %b %Y}" if s.previous_review else ""),
            f"- Target: {s.target_pct:.0f} % per server (per tier where set); red below {s.red_pct:.0f} %. Not reporting: no collection "
            f"for more than {s.stale_days} days.", "", "| Source | File | Records |", "|---|---|---|"]
    out += [f"| {FILES.get(k, k)} | `{k}` | {v:,} |" for k, v in d.sources.items()]
    out += ["", "## Notes", "", f"- Decisions taken: {TODO}", f"- Baseline changes approved (with pilot and date): {TODO}",
            f"- Next review: {TODO}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f2eee6;--card:#fbf8f3;--ink:#0e1a24;--muted:#5d6670;--line:#e2dccf;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#1f5f8b;
--g:#cfeedd;--a:#fbe6bd;--r:#f8d2cd;--n:#e8e2d6}
@media (prefers-color-scheme:dark){:root{--bg:#0e1a24;--card:#142331;--ink:#f2eee6;--muted:#a9b3bb;--line:#24364a;--ok:#4cc38a;--warn:#f0a83a;
--bad:#f2685c;--info:#5aa9f0;--g:#173527;--a:#3d2f12;--r:#45201d;--n:#1b2b3b}}
*{box-sizing:border-box}body{border-top:4px solid #c4672b}h1{font-weight:800;letter-spacing:-.025em;text-transform:uppercase;line-height:1.05}h1::before{content:"IGG · IT Ops toolkit";display:block;font:600 11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;color:#c4672b;margin-bottom:10px}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:24px}
.overall{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:99px;font-weight:700;border:2px solid currentColor}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.red{color:var(--bad)}.amber{color:var(--warn)}.green{color:var(--ok)}
.hbar{height:12px;background:var(--info);border-radius:3px}.hbar.hr{background:var(--bad)}
table.heat td,table.heat th{padding:3px 4px;text-align:center;font-size:11px;border-bottom:1px solid var(--card)}table.heat td.srv{text-align:left;white-space:nowrap;font-size:12px}
table.heat td.c{min-width:34px;font-variant-numeric:tabular-nums}.cg{background:var(--g)}.ca{background:var(--a)}.cr{background:var(--r)}.cn{background:var(--n);color:var(--muted)}
td.subj{min-width:150px}td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);min-width:200px;max-width:340px}td.sm{font-size:13px}
.brk{overflow-wrap:anywhere;word-break:break-word}footer{margin-top:40px;font-size:13px}
"""


def _pill(x: str) -> str:
    return f"<span class='pill {x.lower()}'>{e(x)}</span>"


def _table(head: list[str], rows: list[str], cls: str = "") -> str:
    return (f"<div class='wrap'><table class='{cls}'><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + "".join(rows)
            + "</table></div>")


def _cell(p, target: float, red: float = 80.0) -> str:
    if p is None:
        return "<td class='c cn'>–</td>"
    cls = "cg" if p >= target else "ca" if p >= red else "cr"
    return f"<td class='c {cls}'>{p:.0f}</td>"


def _chg(now: dict, before: dict | None) -> str:
    if not before or now["pct"] is None or before["pct"] is None:
        return "–"
    return f"{now['pct'] - before['pct']:+.1f}"


def render_html(d: Data, rv: dict, title: str) -> str:
    s = d.settings
    sm = summary(d, rv)
    exp = [x for x in rv["exceptions"] if x["state"] == "expired"]
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>{e(s.organisation)} · {sm['servers']} servers in the inventory, {sm['reporting']} "
         f"reporting · {sm['settings']} baseline settings · {sm['checks']:,} checks · run on {d.as_of:%a %d %b %Y %H:%M}"
         + (f" · previous review {s.previous_review:%d %b %Y}" if s.previous_review else "") + "</p>",
         f"<span class='overall {sm['status'].lower()}'>{e(sm['status'])} · {sm['red']} red and {sm['amber']} amber findings</span>",
         "<div class='tiles'>"]
    delta = "" if sm["prev_pct"] is None or sm["pct"] is None else f"{sm['pct'] - sm['prev_pct']:+.1f} pts vs {sm['prev_pct']:.1f} %"
    tiles = [("Overall compliance", _p(sm["pct"]), delta or "no previous review"),
             ("Below target", str(sm["below"]), f"of {sm['reporting']} servers reporting"),
             ("High-risk deviations", str(sm["high_risk"]), f"on {sm['high_risk_servers']} servers"),
             ("New drift", str(sm["new_drift"]), f"settings on {sm['new_drift_servers']} servers"),
             ("Expired exceptions", str(len(exp)), f"of {sm['exceptions']} exceptions"),
             ("Not reporting", str(sm["stale"]), f"for more than {s.stale_days} days")]
    h += [f"<div class='tile'><span class='muted'>{e(a)}</span><b>{e(b)}</b><span class='muted'>{e(c)}</span></div>" for a, b, c in tiles]
    h.append("</div><h2>Decisions needed</h2><p class='muted'>Fix, accept as a time-limited exception, or change the baseline.</p>")
    h.append(_table(["#", "Decision", "Options", "Proposed", "Owner", "By"],
                    [f"<tr><td class='nw'>{e(x.id)}</td><td class='subj'><b>{e(x.decision)}</b><br><span class='sm muted'>{e(x.why)}</span></td>"
                     f"<td class='sm'>{e(x.options)}</td><td class='fix'>{e(x.proposed)}</td><td class='sm'>{e(x.owner)}</td>"
                     f"<td class='nw'>{e(_day(x.needed_by))}</td></tr>" for x in rv["decisions"]]
                    or ["<tr><td colspan='6'>No decisions needed.</td></tr>"]))
    h.append("<h2>Top deviations</h2><p class='muted'>Baseline settings with servers off them, high risk first. Red bars: high-risk "
             "settings.</p>")
    top = sorted([x for x in rv["settings"] if x["off"]], key=lambda x: (not x["rule"].high_risk, -x["off"], x["rule"].id))
    mx = max((x["off"] for x in top), default=1) or 1
    h.append(_table(["Setting", "Area", "Servers off", "", "New", "Exceptions", "Main cause"],
                    [f"<tr><td class='subj'><b>{e(x['rule'].id)}</b> {e(x['rule'].name)}<br><span class='sm muted'>expected "
                     f"{e(x['rule'].expected_text)}</span></td><td class='sm'>{e(x['rule'].area)}</td><td class='num'>{x['off']} / "
                     f"{x['applicable']}</td><td style='width:20%'><div class='hbar{' hr' if x['rule'].high_risk else ''}' "
                     f"style='width:{100 * x['off'] / mx:.1f}%'></div></td><td class='num'>{x['new'] or '–'}</td>"
                     f"<td class='num'>{x['exceptions'] or '–'}</td><td class='sm'>{e(', '.join(f'{k} ({v})' for k, v in x['causes'].most_common(2)))}</td></tr>"
                     for x in top] or ["<tr><td colspan='7'>Every server meets the baseline.</td></tr>"]))
    h.append("<h2>Compliance by tier, site and environment</h2>")
    prev = rv["previous"]
    rows = [f"<tr><td><b>All servers</b></td><td class='num'><b>{_p(rv['overall']['pct'])}</b></td><td class='num'>"
            f"{_p(prev['pct']) if prev else '–'}</td><td class='num'>{rv['overall']['deviation'] + rv['overall']['missing']}</td>"
            f"<td class='num'>{rv['overall']['high_risk']}</td><td class='num'>{rv['overall']['new_drift']}</td></tr>"]
    for label, xs in (("", rv["tiers"]), ("Site ", rv["sites"]), ("Environment ", rv["envs"])):
        for k, x in xs:
            rows.append(f"<tr><td>{e(label)}{e(k)}</td><td class='num'>{_p(x['pct'])}</td><td class='num'></td><td class='num'>"
                        f"{x['deviation'] + x['missing']}</td><td class='num'>{x['high_risk']}</td><td class='num'>{x['new_drift']}</td></tr>")
    h.append(_table(["Scope", "Compliance", "Last review", "Off baseline", "High risk", "New drift"], rows))
    h.append("<h2>Trend by area</h2>")
    h.append(_table(["Area", "Now", "Last review", "Change", "Off baseline", "New drift"],
                    [f"<tr><td>{e(a)}</td><td class='num'>{_p(x['pct'])}</td><td class='num'>{_p(rv['prev_areas'][a]['pct']) if a in rv['prev_areas'] else '–'}</td>"
                     f"<td class='num'>{_chg(x, rv['prev_areas'].get(a))}</td>"
                     f"<td class='num'>{x['deviation'] + x['missing']}</td><td class='num'>{x['new_drift']}</td></tr>"
                     for a, x in rv["areas"]]))
    ar = areas(d)
    code = {a: next(r.id.split("-")[0] for r in d.rules if r.area == a) for a in ar}
    h.append("<h2>Heat map: servers by area</h2><p class='muted'>Compliance % per server and baseline area. Green: at the tier's "
             f"target; amber: from {s.red_pct:.0f} %; red: below. " + " · ".join(f"{e(code[a])} {e(a)}" for a in ar) + "</p>")
    hrows = []
    for r in sorted(rv["servers"], key=lambda r: (r["server"].site, r["server"].tier, r["server"].server)):
        srv = r["server"]
        if not r["reporting"]:
            hrows.append(f"<tr><td class='srv'>{e(srv.server)}</td><td class='c cn' colspan='{len(ar) + 1}'>not collected</td></tr>")
            continue
        note = " <span class='amber'>(stale)</span>" if r["state"] == "stale" else ""
        hrows.append(f"<tr><td class='srv'>{e(srv.server)}{note}</td>{_cell(r['pct'], r['target'], s.red_pct)}"
                     + "".join(_cell(r["areas"].get(a), r["target"], s.red_pct) for a in ar) + "</tr>")
    h.append("<div class='wrap'><table class='heat'><tr><th>Server</th><th>All</th>" +
             "".join(f"<th title='{e(a)}'>{e(code[a])}</th>" for a in ar) + "</tr>" + "".join(hrows) + "</table></div>")
    if rv["exceptions"]:
        h.append("<h2>Exceptions</h2>")
        h.append(_table(["Server", "Setting", "Approved", "Actual", "Approver / ticket", "Expires", "State", "Action"],
                        [f"<tr><td class='nw'>{e(x['exception'].server)}</td><td class='sm'><b>{e(x['exception'].id)}</b> "
                         f"{e(x['rule'].name if x['rule'] else '')}</td><td>{e(x['exception'].approved or '–')}</td><td>{e(x['actual'] or '–')}</td>"
                         f"<td class='sm'>{e(x['exception'].approver or 'none')} / {e(x['exception'].ticket or 'none')}</td>"
                         f"<td class='nw'>{e(_day(x['exception'].expires))}</td><td class='sm "
                         f"{'red' if x['state'] == 'expired' else 'amber' if x['state'] in ('incomplete', 'expiring', 'value differs') else ''}'>"
                         f"{e(x['state'])}</td><td class='fix'>{e(x['action'])}</td></tr>" for x in rv["exceptions"]]))
    h.append("<h2>All findings</h2>")
    h.append(_table(["Severity", "Group", "Subject", "Detail", "Owner", "Due"],
                    [f"<tr><td>{_pill(f.severity)}</td><td class='sm'>{e(GROUPS[f.group])}</td><td class='subj'><b>{e(f.subject)}</b><br>"
                     f"<span class='sm muted'>{e(f.title)}</span></td><td class='sm brk'>{e(f.detail)}<br><span class='muted'>→ "
                     f"{e(f.action)}</span></td><td class='sm'>{e(f.owner)}</td><td class='nw'>{e(_day(f.due))}</td></tr>"
                     for f in rv["findings"]] or ["<tr><td colspan='6'>No findings.</td></tr>"]))
    h.append("<footer class='muted'>Generated by baselinedrift. Fictional demo data unless you ran it on your own collection. The one-page "
             "pack for the monthly review is review-pack.md; every deviation with its cause is in deviations.csv.</footer></main></body></html>")
    return "".join(h)


__all__ = ["render_html", "pack_md", "write_servers", "write_deviations", "write_drift", "write_exceptions", "write_findings",
           "write_actions", "actions", "drift_rows", "CAUSE_LABEL"]
