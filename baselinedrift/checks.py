"""The baseline checks. Compliance: every applicable baseline setting on every server, per server, area, tier and site, against the
target. High risk: deviations on the settings flagged as high risk (SMBv1, NTLMv1/LM, LLMNR, RDP without NLA, LAPS, Defender real-time
protection and ASR, logon and lockout auditing, PowerShell script block logging, Print Spooler on DCs, TLS 1.0/1.1, firewall
profiles). Drift: settings that were compliant at the last review and are not now, grouped by cause; local changes that override the
GPO. Root cause: GPOs not applied (and why), servers in the wrong OU for their tier, settings set by another GPO, exceptions that
expired, are about to expire or have no approver or ticket. Hygiene: servers not reporting, long uptime, patch age, and the
inventory against the collection."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

from .model import Data, Exception_, Rule, Server, Value, _norm, _same, meets

GREEN, AMBER, RED = "GREEN", "AMBER", "RED"
SEV_ORDER = {RED: 0, AMBER: 1, GREEN: 2}
OK_STATES = ("compliant", "exception")
BAD_STATES = ("deviation", "missing")
GROUPS = {"compliance": "Compliance", "risk": "High risk", "deviation": "Deviations", "drift": "Drift", "gpo": "Group Policy",
          "exceptions": "Exceptions", "hygiene": "Hygiene"}
# code: group, title
CHECKS = {
    "RISK-HIGH": ("risk", "High-risk setting off the baseline"),
    "DRF-NEW": ("drift", "New drift since the last review"),
    "GPO-NOTAPPLIED": ("gpo", "GPO not applied"),
    "EXC-EXPIRED": ("exceptions", "Exception expired, deviation still there"),
    "HYG-STALE": ("hygiene", "Servers not reporting"),
    "CMP-SERVER": ("compliance", "Servers below the compliance target"),
    "GPO-OU": ("gpo", "Server in an OU that is not its tier's"),
    "GPO-OTHER": ("gpo", "Baseline setting overridden by another GPO"),
    "DRF-LOCAL": ("drift", "Local change overrides the GPO"),
    "DEV-SETTING": ("deviation", "Setting off the baseline"),
    "EXC-INCOMPLETE": ("exceptions", "Exception without approver, ticket or expiry"),
    "EXC-EXPIRING": ("exceptions", "Exception expiring soon"),
    "HYG-NOTCOLLECTED": ("hygiene", "Servers in the inventory with no collection"),
    "HYG-UNKNOWN": ("hygiene", "Servers collected but not in the inventory"),
    "HYG-UPTIME": ("hygiene", "Long uptime (reboot pending)"),
    "HYG-PATCH": ("hygiene", "Patches older than the threshold"),
}
CAUSE_LABEL = {"gpo-not-applied": "GPO not applied", "exception-expired": "Exception expired", "exception-incomplete":
               "Exception incomplete", "local": "Local change", "other-gpo": "Another GPO", "not-configured": "Not configured",
               "gpo-value": "Value differs", "": ""}


@dataclass
class Result:
    server: Server
    rule: Rule
    value: Value | None
    status: str                         # compliant, exception, deviation, missing
    exception: Exception_ | None = None
    exc_state: str = ""                 # valid, expiring, expired, incomplete, value differs
    cause: str = ""                     # key of CAUSE_LABEL
    cause_text: str = ""
    prev_status: str = ""               # status at the last review ("" when there is no history)
    prev_value: str = ""

    @property
    def ok(self) -> bool:
        return self.status in OK_STATES

    @property
    def new_drift(self) -> bool:
        return self.prev_status in OK_STATES and self.status in BAD_STATES


@dataclass
class Finding:
    code: str
    severity: str
    subject: str
    detail: str
    action: str
    servers: list = field(default_factory=list)
    count: int = 0
    area: str = ""                      # the owner key
    owner: str = ""
    due: date | None = None

    @property
    def group(self) -> str:
        return CHECKS[self.code][0]

    @property
    def title(self) -> str:
        return CHECKS[self.code][1]


@dataclass
class Decision:
    id: str
    decision: str
    why: str
    options: str
    proposed: str
    owner: str
    needed_by: date | None


def pct(ok: int, total: int) -> float | None:
    return 100.0 * ok / total if total else None


def _n(k: int, word: str, plural: str | None = None) -> str:
    return f"{k:,} {word if k == 1 else (plural or word + 's')}"


def _list(xs, k: int = 8) -> str:
    xs = list(xs)
    return ", ".join(xs[:k]) + (f" and {len(xs) - k} more" if len(xs) > k else "")


def worst(xs) -> str:
    xs = list(xs)
    return min(xs, key=lambda x: SEV_ORDER[x]) if xs else GREEN


# ---------------------------------------------------------------- evaluation

def exception_state(x: Exception_, actual: str, when: date, warn_days: int) -> str:
    if not x.complete:
        return "incomplete"
    if x.expires < when:
        return "expired"
    if x.approved and actual and not _same(actual, x.approved):
        return "value differs"
    return "expiring" if (x.expires - when).days <= warn_days else "valid"


def _gpo_map(d: Data) -> dict:
    return {(g.server, _norm(g.gpo)): g for g in d.gpo or []}


def collected_servers(values: dict) -> dict:
    """server -> last collection time."""
    out: dict = {}
    for (srv, _), v in values.items():
        if v.collected and (srv not in out or v.collected > out[srv]):
            out[srv] = v.collected
        out.setdefault(srv, None)
    return out


def evaluate(d: Data, values: dict, when: date, with_cause: bool = True) -> list[Result]:
    """One result per collected inventory server and applicable baseline setting."""
    s = d.settings
    exc = {(x.server, x.id): x for x in d.exceptions or []}
    gpo = _gpo_map(d) if with_cause else {}
    seen = collected_servers(values)
    out = []
    for name in sorted(d.servers):
        srv = d.servers[name]
        if name not in seen:
            continue
        for r in d.rules:
            if not r.applies_to(srv):
                continue
            v = values.get((name, r.id))
            actual = v.actual if v and v.source != "missing" else ""
            ok = meets(r.expected, r.comparison, actual)
            status = "compliant" if ok else "missing" if ok is None else "deviation"
            x = exc.get((name, r.id))
            st = exception_state(x, actual, when, s.exception_warning_days) if x else ""
            if status != "compliant" and st in ("valid", "expiring"):
                status = "exception"
            res = Result(srv, r, v, status, x, st)
            if with_cause and status in BAD_STATES:
                res.cause, res.cause_text = _cause(r, v, x, st, gpo.get((name, _norm(r.gpo))))
            out.append(res)
    return out


def _cause(r: Rule, v: Value | None, x: Exception_ | None, st: str, g) -> tuple[str, str]:
    if g is not None and not g.applied:
        return "gpo-not-applied", f"GPO not applied: {r.gpo}" + (f" ({g.reason})" if g.reason else "")
    if x is not None and st == "expired":
        return "exception-expired", f"Exception {x.ticket or ''} expired on {x.expires:%d %b %Y}".replace("  ", " ")
    if x is not None and st == "incomplete":
        return "exception-incomplete", "Exception without " + " or ".join(
            w for w, ok in (("approver", x.approver), ("ticket", x.ticket), ("expiry", x.expires)) if not ok)
    if v is not None and v.source == "local":
        return "local", "Local change overrides the GPO"
    if v is not None and v.source == "gpo" and v.gpo and r.gpo and _norm(v.gpo) != _norm(r.gpo):
        return "other-gpo", f"Set by another GPO: {v.gpo}"
    if v is None or v.source == "missing":
        return "not-configured", "Not configured" + (f" (expected from {r.gpo})" if r.gpo else "")
    return "gpo-value", f"{r.gpo} sets a value that differs from the baseline" if r.gpo else "Value differs from the baseline"


def attach_previous(d: Data, rs: list[Result]) -> None:
    if d.previous is None:
        return
    when = d.settings.previous_review or (d.today - timedelta(days=30))
    prev = {(p.server.server, p.rule.id): p for p in evaluate(d, d.previous, when, with_cause=False)}
    for r in rs:
        p = prev.get((r.server.server, r.rule.id))
        if p:
            r.prev_status = p.status
            r.prev_value = p.value.actual if p.value else ""


# ---------------------------------------------------------------- statistics

def _stats(rs) -> dict:
    c = Counter(r.status for r in rs)
    n = len(rs)
    return {"applicable": n, "compliant": c["compliant"], "exception": c["exception"], "deviation": c["deviation"],
            "missing": c["missing"], "pct": pct(c["compliant"] + c["exception"], n),
            "high_risk": sum(1 for r in rs if not r.ok and r.rule.high_risk), "new_drift": sum(1 for r in rs if r.new_drift)}


def server_rows(d: Data, rs: list[Result]) -> list[dict]:
    s = d.settings
    seen = collected_servers(d.values)
    by = defaultdict(list)
    for r in rs:
        by[r.server.server].append(r)
    out = []
    for name in sorted(d.servers):
        srv = d.servers[name]
        st = _stats(by.get(name, []))
        last = seen.get(name) if name in seen else None
        age = (d.today - last.date()).days if last else None
        bad = [r for r in by.get(name, []) if not r.ok]
        causes = Counter(CAUSE_LABEL[r.cause] for r in bad)
        st.update(server=srv, collected=last, age=age, reporting=name in seen, target=s.target(srv.tier),
                  risk=sum(s.weight(r.rule.severity) for r in bad), cause=causes.most_common(1)[0][0] if causes else "",
                  areas={a: _stats([r for r in by.get(name, []) if r.rule.area == a])["pct"] for a in areas(d)})
        st["state"] = ("not reporting" if name not in seen else "stale" if age is not None and age > s.stale_days else
                       "below target" if st["pct"] is not None and st["pct"] < st["target"] else "on target")
        out.append(st)
    return out


def areas(d: Data) -> list[str]:
    out = []
    for r in d.rules:
        if r.area not in out:
            out.append(r.area)
    return out


def breakdown(rs: list[Result], key) -> list[tuple[str, dict]]:
    by = defaultdict(list)
    for r in rs:
        by[key(r)].append(r)
    return [(k, _stats(by[k])) for k in sorted(by)]


def setting_rows(d: Data, rs: list[Result]) -> list[dict]:
    """Per baseline setting: how many servers are off it, why, and the trend."""
    by = defaultdict(list)
    for r in rs:
        by[r.rule.id].append(r)
    out = []
    for rule in d.rules:
        xs = by.get(rule.id, [])
        bad = [r for r in xs if not r.ok]
        prev = [r for r in xs if r.prev_status]
        out.append({"rule": rule, "applicable": len(xs), "off": len(bad), "exceptions": sum(r.status == "exception" for r in xs),
                    "new": sum(r.new_drift for r in xs), "pct": pct(len(xs) - len(bad), len(xs)),
                    "prev_off": sum(1 for r in prev if r.prev_status in BAD_STATES),
                    "causes": Counter(CAUSE_LABEL[r.cause] for r in bad), "servers": [r.server.server for r in bad]})
    return out


# ---------------------------------------------------------------- findings

def _causes(rs) -> str:
    c = Counter(r.cause_text for r in rs if r.cause_text)
    return "; ".join(f"{k} ({v})" for k, v in c.most_common(3))


def check_settings(d: Data, rs: list[Result]) -> list[Finding]:
    out = []
    for row in setting_rows(d, rs):
        rule = row["rule"]
        bad = [r for r in rs if r.rule.id == rule.id and not r.ok]
        if not bad:
            continue
        srvs = [r.server.server for r in bad]
        vals = Counter(r.value.actual if r.value and r.value.source != "missing" else "not set" for r in bad)
        detail = (f"{_n(len(bad), 'server')} of {row['applicable']} off the baseline ({rule.expected_text}): {_list(srvs)}. Found: "
                  + ", ".join(f"{k} ({v})" for k, v in vals.most_common(3)) + f". Cause: {_causes(bad)}.")
        act = f"Restore {rule.name} to {rule.expected_text} on {_n(len(bad), 'server')}, fixing the cause first; confirm in the next collection."
        if rule.high_risk:
            out.append(Finding("RISK-HIGH", RED, f"{rule.id} {rule.name}", detail, act, srvs, len(bad), rule.area))
        else:
            out.append(Finding("DEV-SETTING", AMBER, f"{rule.id} {rule.name}", detail, act, srvs, len(bad), rule.area))
    return out


def check_drift(d: Data, rs: list[Result]) -> list[Finding]:
    out = []
    by = defaultdict(list)
    for r in rs:
        if r.new_drift:
            key = (r.cause, r.rule.id) if r.cause in ("local", "gpo-value", "not-configured") else (r.cause, r.cause_text)
            by[key].append(r)
    for key in sorted(by, key=lambda k: (-len(by[k]), k)):
        xs = by[key]
        srvs = sorted({r.server.server for r in xs})
        rules = sorted({r.rule.id for r in xs})
        sev = RED if any(r.rule.high_risk for r in xs) else AMBER
        subj = (f"{xs[0].rule.id} {xs[0].rule.name}: {CAUSE_LABEL[key[0]].lower()}" if key[0] in ("local", "gpo-value", "not-configured")
                else xs[0].cause_text)
        detail = (f"{_n(len(xs), 'setting')} compliant at the last review and not now, on {_n(len(srvs), 'server')}: {_list(srvs)}; "
                  f"settings {_list(rules, 10)}.")
        act = {"gpo-not-applied": "Restore the GPO link or filtering, run gpupdate /force and recollect",
               "local": "Find who changed it and why (change record, event 4657 or the tool that did it), revert to the GPO value",
               "other-gpo": "Remove the conflicting setting or link, or record a decision", "exception-expired":
               "Renew the exception with a plan or fix the setting"}.get(key[0], "Restore the baseline value and recollect")
        out.append(Finding("DRF-NEW", sev, subj, detail, act + ".", srvs, len(xs), xs[0].rule.area if key[0] in
                           ("local", "gpo-value", "not-configured") else "gpo" if key[0] in ("gpo-not-applied", "other-gpo") else "exceptions"))
    loc = defaultdict(list)
    for r in rs:
        if r.cause == "local":
            loc[r.rule.id].append(r)
    for rid in sorted(loc):
        xs = loc[rid]
        srvs = [r.server.server for r in xs]
        out.append(Finding("DRF-LOCAL", AMBER, f"{rid} {xs[0].rule.name}",
                           f"Set locally on {_n(len(srvs), 'server')}, overriding {xs[0].rule.gpo or 'the GPO'}: {_list(srvs)}.",
                           "Revert to the GPO value and find the tool or person that changed it; if the change is needed, raise an exception.",
                           srvs, len(xs), xs[0].rule.area))
    return out


def check_gpo(d: Data, rs: list[Result]) -> list[Finding]:
    s = d.settings
    out = []
    rules_by_gpo = defaultdict(list)
    for r in d.rules:
        if r.gpo:
            rules_by_gpo[_norm(r.gpo)].append(r)
    na = defaultdict(list)
    for g in d.gpo or []:
        if not g.applied and g.server in d.servers:
            na[(g.gpo, g.reason)].append(g.server)
    wrong = wrong_ou(d)
    for (gname, reason) in sorted(na, key=lambda k: (-len(na[k]), k)):
        srvs = sorted(na[(gname, reason)])
        rules = rules_by_gpo.get(_norm(gname), [])
        sev = RED if any(r.high_risk for r in rules) else AMBER
        in_wrong = [x for x in srvs if x in wrong]
        detail = (f"Not applied on {_n(len(srvs), 'server')} ({reason or 'no reason given'}): {_list(srvs)}. It carries "
                  f"{_n(len(rules), 'baseline setting')}" + (f", {sum(r.high_risk for r in rules)} of them high risk" if rules else "")
                  + "." + (f" {len(in_wrong)} of these servers are in an OU that is not their tier's." if in_wrong else ""))
        n = _norm(reason)
        act = ("Link the GPO to the OU (or move the servers back), then gpupdate /force and recollect" if "link" in n or "ou" in n.split()
               or "not linked" in n else "Add the servers to the security filtering group (computer accounts need a restart or "
               "klist -li 0x3e7 purge to pick up the group)" if "security" in n or "denied" in n or "group" in n else
               "Fix the WMI filter so it matches these servers" if "wmi" in n else "Find out why with gpresult /scope computer /h on one server")
        out.append(Finding("GPO-NOTAPPLIED", sev, gname, detail, act + ".", srvs, len(srvs), "gpo"))
    by_tier = defaultdict(list)
    for name, ou in sorted(wrong.items()):
        by_tier[d.servers[name].tier].append(f"{name} ({ou})")
    for tier in sorted(by_tier):
        xs = by_tier[tier]
        ous = s.tier(tier).get("ous", [])
        out.append(Finding("GPO-OU", AMBER, f"{tier}: {_n(len(xs), 'server')} outside the tier's OUs",
                           f"Expected under {', '.join(ous)}: {_list(xs, 5)}.",
                           "Move the servers to the right OU, or link the tier's GPOs to the new OU and add it to settings.json.",
                           [x.split(' ')[0] for x in xs], len(xs), "gpo"))
    oth = defaultdict(list)
    for r in rs:
        if r.cause == "other-gpo":
            oth[r.value.gpo].append(r)
    for g in sorted(oth):
        xs = oth[g]
        srvs = sorted({r.server.server for r in xs})
        rules = sorted({f"{r.rule.id} {r.rule.name} = {r.value.actual}" for r in xs})
        out.append(Finding("GPO-OTHER", AMBER, g,
                           f"{g} wins over the baseline GPO on {_n(len(srvs), 'server')} ({_list(srvs)}): {_list(rules, 4)}.",
                           f"Decide: align {g} with the baseline, accept it as a time-limited exception, or change the baseline.",
                           srvs, len(xs), "gpo"))
    return out


def wrong_ou(d: Data) -> dict:
    out = {}
    for name, srv in d.servers.items():
        ous = [_norm(o) for o in d.settings.tier(srv.tier).get("ous", [])]
        if ous and srv.ou and not any(o in _norm(srv.ou) for o in ous):
            out[name] = srv.ou
    return out


def exception_rows(d: Data, rs: list[Result]) -> list[dict]:
    s = d.settings
    res = {(r.server.server, r.rule.id): r for r in rs}
    rules = {r.id: r for r in d.rules}
    out = []
    for x in d.exceptions or []:
        r = res.get((x.server, x.id))
        v = d.values.get((x.server, x.id))
        actual = v.actual if v and v.source != "missing" else ""
        st = exception_state(x, actual, d.today, s.exception_warning_days)
        rule = rules.get(x.id)
        compliant = bool(rule and meets(rule.expected, rule.comparison, actual))
        if compliant:
            state, act = "not needed", "Close it: the server now meets the baseline"
        elif st == "expired":
            state, act = "expired", "Fix the setting or renew with a new expiry, approver and plan"
        elif st == "incomplete":
            state, act = "incomplete", "Complete approver, ticket and expiry, or reject it"
        elif st == "value differs":
            state, act = "value differs", "The server has a value the exception does not cover: fix it or update the exception"
        elif st == "expiring":
            state, act = "expiring", "Confirm the remediation date with the owner before it expires"
        else:
            state, act = "valid", ""
        out.append({"exception": x, "rule": rule, "actual": actual, "state": state, "action": act, "in_scope": r is not None,
                    "days": (x.expires - d.today).days if x.expires else None})
    return out


def check_exceptions(d: Data, rs: list[Result]) -> list[Finding]:
    out = []
    for e in exception_rows(d, rs):
        x, rule = e["exception"], e["rule"]
        name = f"{x.id} {rule.name}" if rule else x.id
        subj = f"{x.server}: {name}"
        info = f"Approved value {x.approved or '–'}, actual {e['actual'] or 'not set'}; reason: {x.reason or '–'}; approver {x.approver or '–'}; ticket {x.ticket or '–'}"
        if e["state"] == "expired":
            out.append(Finding("EXC-EXPIRED", RED if rule and rule.high_risk else AMBER, subj,
                               f"Expired on {x.expires:%d %b %Y} ({-e['days']} days ago). {info}.", e["action"] + ".", [x.server], 1, "exceptions"))
        elif e["state"] == "incomplete":
            out.append(Finding("EXC-INCOMPLETE", AMBER, subj, f"{info}; expires {x.expires or '–'}. It is not counted as an exception.",
                               e["action"] + ".", [x.server], 1, "exceptions"))
        elif e["state"] == "expiring":
            out.append(Finding("EXC-EXPIRING", AMBER, subj, f"Expires on {x.expires:%d %b %Y}, in {e['days']} days. {info}.",
                               e["action"] + ".", [x.server], 1, "exceptions"))
    return out


def check_hygiene(d: Data, srows: list[dict]) -> list[Finding]:
    s = d.settings
    out = []
    t = d.today
    stale = [r for r in srows if r["reporting"] and r["age"] is not None and r["age"] > s.stale_days and not r["server"].maintenance]
    if stale:
        xs = [f"{r['server'].server} ({r['age']} days)" for r in sorted(stale, key=lambda r: -r["age"])]
        out.append(Finding("HYG-STALE", RED if any(r["server"].tier == "Tier 0" for r in stale) else AMBER,
                           f"{_n(len(stale), 'server')} not reporting for more than {s.stale_days} days",
                           f"Last collection: {_list(xs)}. Their compliance is the last one known.",
                           "Check WinRM and the collector's access (Test-WSMan), whether the servers still exist, and recollect.",
                           [r["server"].server for r in stale], len(stale), "hygiene"))
    nc = [r["server"].server for r in srows if not r["reporting"] and not r["server"].maintenance]
    if nc:
        out.append(Finding("HYG-NOTCOLLECTED", AMBER, f"{_n(len(nc), 'server')} in the inventory with no collection",
                           f"No settings collected: {_list(nc)}. They are left out of the compliance figures.",
                           "Add them to the collection scope or mark them decommissioned in the CMDB.", nc, len(nc), "hygiene"))
    unk = sorted({srv for (srv, _) in d.values} - set(d.servers))
    if unk:
        out.append(Finding("HYG-UNKNOWN", AMBER, f"{_n(len(unk), 'server')} collected but not in the inventory",
                           f"Settings collected from {_list(unk)}, which the inventory does not have: no tier, owner or target.",
                           "Add them to the CMDB with tier and owner, or remove them from AD if they are gone.", unk, len(unk), "hygiene"))
    up = [(r["server"].server, (t - r["server"].last_reboot).days) for r in srows if r["server"].last_reboot and
          (t - r["server"].last_reboot).days > s.max_uptime_days and not r["server"].maintenance]
    if up:
        out.append(Finding("HYG-UPTIME", AMBER, f"{_n(len(up), 'server')} up for more than {s.max_uptime_days} days",
                           "Last reboot: " + _list(f"{a} ({b} days)" for a, b in sorted(up, key=lambda x: -x[1])) +
                           ". Security settings and updates that need a restart are not in effect yet.",
                           "Schedule the restart in the next maintenance window.", [a for a, _ in up], len(up), "hygiene"))
    pa = [(r["server"].server, (t - r["server"].last_patch).days) for r in srows if r["server"].last_patch and
          (t - r["server"].last_patch).days > s.patch_age_days and not r["server"].maintenance]
    if pa:
        out.append(Finding("HYG-PATCH", AMBER, f"{_n(len(pa), 'server')} with patches older than {s.patch_age_days} days",
                           "Last patch: " + _list(f"{a} ({b} days)" for a, b in sorted(pa, key=lambda x: -x[1])) + ".",
                           "Patch in the next window, or record why the server is held back.", [a for a, _ in pa], len(pa), "hygiene"))
    return out


def check_compliance(d: Data, srows: list[dict]) -> list[Finding]:
    s = d.settings
    out = []
    rated = [r for r in srows if r["reporting"] and r["pct"] is not None]
    red = [r for r in rated if r["pct"] < s.red_pct]
    amber = [r for r in rated if s.red_pct <= r["pct"] < r["target"]]
    for sev, xs, txt in ((RED, red, f"below {s.red_pct:.0f} %"), (AMBER, amber, "below their tier's target")):
        if not xs:
            continue
        xs = sorted(xs, key=lambda r: (r["pct"], r["server"].server))
        out.append(Finding("CMP-SERVER", sev, f"{_n(len(xs), 'server')} {txt}",
                           "Compliance: " + _list(f"{r['server'].server} {r['pct']:.0f} %" for r in xs) + ".",
                           "Work through the causes in server-compliance.csv and deviations.csv; recheck at the next collection.",
                           [r["server"].server for r in xs], len(xs), "compliance"))
    return out


# ---------------------------------------------------------------- review

def review(d: Data) -> dict:
    s = d.settings
    rs = evaluate(d, d.values, d.today)
    attach_previous(d, rs)
    srows = server_rows(d, rs)
    findings = (check_settings(d, rs) + check_drift(d, rs) + check_gpo(d, rs) + check_exceptions(d, rs) + check_hygiene(d, srows)
                + check_compliance(d, srows))
    for f in findings:
        f.owner = s.owner(f.area)
        f.due = d.today + timedelta(days=int(s.action_days.get("red" if f.severity == RED else "amber", 30)))
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], list(CHECKS).index(f.code), -f.count, f.subject))
    prev_rs = evaluate(d, d.previous, s.previous_review or d.today, with_cause=False) if d.previous is not None else []
    rv = {"results": rs, "servers": srows, "findings": findings, "settings": setting_rows(d, rs), "exceptions": exception_rows(d, rs),
          "overall": _stats(rs), "previous": _stats(prev_rs) if prev_rs else None,
          "prev_areas": dict(breakdown(prev_rs, lambda r: r.rule.area)) if prev_rs else {},
          "areas": breakdown(rs, lambda r: r.rule.area), "tiers": breakdown(rs, lambda r: r.server.tier or "–"),
          "sites": breakdown(rs, lambda r: r.server.site or "–"), "envs": breakdown(rs, lambda r: r.server.environment),
          "status": worst(f.severity for f in findings)}
    rv["decisions"] = decisions(d, rv)
    return rv


def decisions(d: Data, rv: dict) -> list[Decision]:
    s = d.settings
    out = []
    for f in rv["findings"]:
        if f.code == "EXC-EXPIRED":
            out.append(Decision("", f"Fix or renew the expired exception {f.subject}", f.detail,
                                "Fix now / renew for a fixed period with a dated plan, approver and ticket / change the baseline for "
                                "this role", "Renew for 90 days at most only with a dated remediation plan and a compensating control; "
                                "otherwise fix", s.owner("exceptions"), f.due))
        elif f.code == "EXC-INCOMPLETE":
            out.append(Decision("", f"Approve or reject the exception {f.subject}", f.detail,
                                "Approve with approver, ticket and expiry / reject and fix",
                                "Reject until it has an approver, a ticket and an expiry date", s.owner("exceptions"), f.due))
        elif f.code == "GPO-OTHER":
            rs = [r for r in rv["results"] if r.cause == "other-gpo" and r.value.gpo == f.subject]
            test = all(r.server.environment == "test" for r in rs)
            audit = "pilot" in _norm(f.subject) or "audit" in _norm(f.subject) or any(r.rule.type == "asr" for r in rs)
            prop = ("Move to the baseline value in waves after reviewing the audit events of the last 30 days" if audit else
                    "Fix: the test servers follow the production baseline, so tests find the problems first" if test else
                    "Fix: align the GPO with the baseline, in a pilot ring first")
            out.append(Decision("", f"Settings from {f.subject} on {_n(len(f.servers), 'server')}", f.detail,
                                "Fix (align with the baseline) / accept as a time-limited exception / change the baseline",
                                prop, s.owner("gpo"), f.due))
    out.sort(key=lambda x: (x.needed_by or date.max, x.decision))
    for i, x in enumerate(out, 1):
        x.id = f"D-{i:02d}"
    return out


def summary(d: Data, rv: dict) -> dict:
    fs = rv["findings"]
    srows = rv["servers"]
    ov = rv["overall"]
    prev = rv["previous"]
    exp = [e for e in rv["exceptions"] if e["state"] == "expired"]
    return dict(status=rv["status"], servers=len(d.servers), reporting=sum(r["reporting"] for r in srows),
                stale=sum(1 for r in srows if r["state"] == "stale"), settings=len(d.rules), checks=ov["applicable"],
                pct=ov["pct"], prev_pct=prev["pct"] if prev else None,
                below=sum(1 for r in srows if r["reporting"] and r["pct"] is not None and r["pct"] < r["target"]),
                high_risk=ov["high_risk"], high_risk_servers=len({r.server.server for r in rv["results"] if not r.ok and r.rule.high_risk}),
                new_drift=ov["new_drift"], new_drift_servers=len({r.server.server for r in rv["results"] if r.new_drift}),
                deviations=ov["deviation"] + ov["missing"], exceptions=len(d.exceptions or []), expired=len(exp),
                red=sum(f.severity == RED for f in fs), amber=sum(f.severity == AMBER for f in fs), findings=len(fs),
                decisions=len(rv["decisions"]), today=d.today)


__all__ = ["GREEN", "AMBER", "RED", "CHECKS", "GROUPS", "CAUSE_LABEL", "Finding", "Result", "Decision", "evaluate", "attach_previous",
           "server_rows", "setting_rows", "breakdown", "exception_rows", "check_settings", "check_drift", "check_gpo", "check_exceptions",
           "check_hygiene", "check_compliance", "wrong_ou", "review", "decisions", "summary", "worst", "pct", "areas"]
