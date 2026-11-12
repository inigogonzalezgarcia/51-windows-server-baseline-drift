import csv
import hashlib
import re
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path

from baselinedrift import cli
from baselinedrift.checks import AMBER, RED, check_compliance, check_exceptions, check_gpo, check_hygiene, check_settings, \
    evaluate, attach_previous, review, server_rows, summary
from baselinedrift.model import (Data, Exception_, GpoResult, Rule, Server, Value, load_baseline, load_servers, load_values, meets,
                                 settings_from_dict)
from baselinedrift.report import drift_rows

AS_OF = datetime(2026, 11, 12, 9, 0)
T = AS_OF.date()
ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, header: list[str], rows: list[list]) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    return path


def rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def rule(rid="R-1", expected="1", cmp="equals", high=False, gpo="BASE", applies=("all",), area="Area", sev="medium") -> Rule:
    return Rule(rid, area, f"Rule {rid}", "registry", r"HKLM\X", "V", expected, cmp, sev, list(applies), gpo, "", high)


def server(name="S1", tier="Tier 1", **kw) -> Server:
    return Server(name, kw.pop("role", "App"), tier, **kw)


def val(srv, rid, actual, src="gpo", gpo="BASE", when=datetime(2026, 11, 11, 2, 0)) -> Value:
    return Value(srv, rid, actual, src, gpo, when)


def data(rules, servers, values, previous=None, exceptions=None, gpo=None, **raw) -> Data:
    raw.setdefault("previous_review", "2026-10-12")
    d = Data(settings_from_dict(raw), AS_OF, list(rules), {s.server: s for s in servers})
    d.values = {(v.server, v.id): v for v in values}
    d.previous = None if previous is None else {(v.server, v.id): v for v in previous}
    d.exceptions = exceptions
    d.gpo = gpo
    return d


def codes(fs) -> dict:
    out = {}
    for f in fs:
        out.setdefault(f.code, f.severity)
    return out


class TestLoading(unittest.TestCase):
    def test_baseline_columns_comparisons_severity_and_tiers(self):
        with tempfile.TemporaryDirectory() as t:
            p = write(Path(t) / "b.csv", ["Control id", "Category", "Setting name", "Check type", "Registry path", "Registry value",
                                          "Required value", "Operator", "Impact", "Scope", "GPO name", "Standard", "Critical"],
                      [["SEC-01", "Security options", "LM level", "Registry", r"HKLM\SYSTEM\Lsa", "LmCompatibilityLevel", "5", ">=?",
                        "Critical", "T0; tier1", "BASE", "A.8.5", "yes"],
                       ["AUD-02", "Audit policy", "Lockout", "auditpol", "Account Lockout", "", "Failure|Success and Failure", "one of",
                        "low", "", "AUD", "", ""],
                       ["SEC-01", "dup", "", "", "", "", "", "", "", "", "", "", ""], ["", "no id", "", "", "", "", "", "", "", "", "", "", ""]])
            rs = load_baseline(p)
        self.assertEqual([r.id for r in rs], ["SEC-01", "AUD-02"])
        a, b = rs
        self.assertEqual((a.type, a.severity, a.applies, a.high_risk, a.gpo), ("registry", "high", ["Tier 0", "Tier 1"], True, "BASE"))
        self.assertEqual(a.comparison, "equals")                       # unknown operator falls back to equals
        self.assertEqual((b.comparison, b.severity, b.applies, b.high_risk), ("in", "low", ["all"], False))
        self.assertTrue(a.applies_to(server(tier="Tier 0")) and not a.applies_to(server(tier="Tier 2")))
        self.assertTrue(b.applies_to(server(tier="Tier 2")))

    def test_comparisons(self):
        self.assertTrue(meets("5", "min", "5") and not meets("5", "min", "3") and meets("3", "max", "1"))
        self.assertIsNone(meets("1", "equals", " "))
        self.assertTrue(meets("False", "equals", "false") and meets("True", "equals", "Enabled") and not meets("False", "equals", "True"))
        self.assertTrue(meets("1", "equals", "1.0") and not meets("1", "equals", "Present"))
        self.assertTrue(meets("Failure|Success and Failure", "in", "Success and Failure") and not meets("Failure|Success and Failure",
                                                                                                         "in", "Success"))
        self.assertTrue(meets("Automatic|Manual", "not_in", "Disabled"))
        self.assertFalse(meets("Automatic|Manual", "not_in", "manual"))
        self.assertTrue(meets("*S-1-5-32-546", "contains", "*S-1-5-32-546,*S-1-5-21-1-2-3-501"))
        self.assertFalse(meets("*S-1-5-32-546", "contains", "*S-1-5-21-1-2-3-501"))
        self.assertFalse(meets("5", "min", "not a number"))

    def test_servers_values_sources_and_names(self):
        with tempfile.TemporaryDirectory() as t:
            s = write(Path(t) / "s.csv", ["Hostname", "Server role", "Admin tier", "Distinguished name", "Env", "Last boot", "Patched"],
                      [["fab-get-fs01.fabrikam.local", "File server", "1", "OU=Servers,OU=Tier 1", "Production", "2026-10-14",
                        "13/10/2026"], ["DC01", "DC", "T0", "OU=Domain Controllers", "UAT", "", ""]])
            v = write(Path(t) / "v.csv", ["Computer", "Setting id", "Value", "Set by", "Winning GPO", "Timestamp"],
                      [["FAB-GET-FS01.fabrikam.local", "SMB-01", "True", "Local", "", "2026-11-11T02:10:00Z"],
                       ["FAB-GET-FS01", "NET-01", "0", "Group Policy", "BASE", "2026-11-11 02:10"],
                       ["FAB-GET-FS01", "PSH-01", "1", "Missing", "", ""], ["FAB-GET-FS01", "PSH-02", "", "", "", ""]])
            ss, vs = load_servers(s), load_values(v)
        fs = ss["FAB-GET-FS01"]
        self.assertEqual((fs.tier, fs.environment, fs.last_reboot, fs.last_patch), ("Tier 1", "prod", date(2026, 10, 14), date(2026, 10, 13)))
        self.assertEqual((ss["DC01"].tier, ss["DC01"].environment), ("Tier 0", "test"))
        self.assertEqual([(k[1], x.source, x.actual) for k, x in sorted(vs.items())],
                         [("NET-01", "gpo", "0"), ("PSH-01", "missing", ""), ("PSH-02", "missing", ""), ("SMB-01", "local", "True")])
        self.assertEqual(vs[("FAB-GET-FS01", "SMB-01")].collected, datetime(2026, 11, 11, 2, 10))


class TestChecks(unittest.TestCase):
    def test_compliance_counts_exceptions_missing_and_targets(self):
        rs = [rule(f"R-{k}") for k in range(10)] + [rule("DC-1", applies=("Tier 0",))]
        sv = [server("A"), server("B"), server("DC", "Tier 0"), server("NOCOL")]
        vals = [val("A", f"R-{k}", "1") for k in range(10)]
        vals += [val("B", f"R-{k}", "1") for k in range(7)] + [val("B", "R-7", "0", "local"), val("B", "R-8", "", "missing")]
        vals += [val("DC", f"R-{k}", "1") for k in range(10)] + [val("DC", "DC-1", "0")]
        exc = [Exception_("B", "R-7", "0", "app", "CISO", "RISK-1", date(2027, 1, 31))]
        d = data(rs, sv, vals, exceptions=exc, tiers={"Tier 0": {"target_pct": 100}})
        res = evaluate(d, d.values, T)
        sr = {r["server"].server: r for r in server_rows(d, res)}
        self.assertEqual((sr["A"]["pct"], sr["A"]["state"]), (100.0, "on target"))
        b = sr["B"]
        self.assertEqual((b["applicable"], b["compliant"], b["exception"], b["deviation"], b["missing"]), (10, 7, 1, 0, 2))
        self.assertEqual((b["pct"], b["state"]), (80.0, "below target"))          # R-9 has no row at all: missing
        self.assertAlmostEqual(sr["DC"]["pct"], 100 * 10 / 11)
        self.assertEqual((sr["DC"]["target"], sr["NOCOL"]["state"]), (100.0, "not reporting"))
        fs = check_compliance(d, list(sr.values()))
        self.assertEqual(sorted((f.severity, tuple(f.servers)) for f in fs), [("AMBER", ("B", "DC"))])
        d.settings.red_pct = 85
        self.assertEqual([f.severity for f in check_compliance(d, list(sr.values()))], [RED, AMBER])

    def test_high_risk_and_other_deviations(self):
        rs = [rule("HR-1", "0", high=True), rule("MED-1", "5", "min")]
        sv = [server("A"), server("B")]
        d = data(rs, sv, [val("A", "HR-1", "1", "local"), val("B", "HR-1", "0"), val("A", "MED-1", "3"), val("B", "MED-1", "6")])
        fs = check_settings(d, evaluate(d, d.values, T))
        self.assertEqual([(f.code, f.severity, f.servers) for f in fs], [("RISK-HIGH", RED, ["A"]), ("DEV-SETTING", AMBER, ["A"])])
        self.assertIn("Local change overrides the GPO", fs[0].detail)
        self.assertIn("BASE sets a value that differs", fs[1].detail)

    def test_causes_gpo_not_applied_expired_incomplete_local_other_gpo(self):
        rs = [rule("R-1"), rule("R-2"), rule("R-3"), rule("R-4"), rule("R-5")]
        d = data(rs, [server("A"), server("B")],
                 [val("A", "R-1", "", "missing"), val("B", "R-1", "", "missing"), val("B", "R-2", "0", "local"),
                  val("B", "R-3", "0", "local"), val("B", "R-4", "0", "local"), val("B", "R-5", "0", "gpo", "TEST GPO")],
                 exceptions=[Exception_("B", "R-2", "0", "x", "CISO", "RISK-9", date(2026, 11, 5)),
                             Exception_("B", "R-3", "0", "x", "", "RITM1", date(2027, 1, 1))],
                 gpo=[GpoResult("A", "BASE", False, "Not linked to OU=New"), GpoResult("B", "BASE", True)])
        c = {(r.server.server, r.rule.id): (r.cause, r.status) for r in evaluate(d, d.values, T) if not r.ok}
        self.assertEqual(c, {("A", "R-1"): ("gpo-not-applied", "missing"), ("A", "R-2"): ("gpo-not-applied", "missing"),
                             ("A", "R-3"): ("gpo-not-applied", "missing"), ("A", "R-4"): ("gpo-not-applied", "missing"),
                             ("A", "R-5"): ("gpo-not-applied", "missing"), ("B", "R-1"): ("not-configured", "missing"),
                             ("B", "R-2"): ("exception-expired", "deviation"), ("B", "R-3"): ("exception-incomplete", "deviation"),
                             ("B", "R-4"): ("local", "deviation"), ("B", "R-5"): ("other-gpo", "deviation")})

    def test_new_drift_against_the_previous_review(self):
        rs = [rule("R-1", high=True), rule("R-2"), rule("R-3")]
        sv = [server("A"), server("NEW")]
        cur = [val("A", "R-1", "0", "local"), val("A", "R-2", "1"), val("A", "R-3", "1"), val("NEW", "R-1", "1")]
        prev = [val("A", "R-1", "1"), val("A", "R-2", "0", "local"), val("A", "R-3", "1")]
        d = data(rs, sv, cur, previous=prev, exceptions=[Exception_("A", "R-3", "1", "x", "CISO", "T-1", date(2026, 11, 1))])
        res = evaluate(d, d.values, T)
        attach_previous(d, res)
        rv = review(d)
        self.assertEqual([(r.server.server, r.rule.id) for r in res if r.new_drift], [("A", "R-1")])
        dr = drift_rows(d, rv)
        self.assertEqual([(x[0], x[3], x[9]) for x in dr], [("A", "R-1", "new drift"), ("NEW", "", "new server"), ("A", "R-2", "resolved")])
        f = [f for f in rv["findings"] if f.code == "DRF-NEW"][0]
        self.assertEqual((f.severity, f.servers, f.subject), (RED, ["A"], "R-1 Rule R-1: local change"))
        self.assertEqual((rv["previous"]["pct"], summary(d, rv)["new_drift"]), (100 * 2 / 3, 1))

    def test_gpo_not_applied_wrong_ou_and_other_gpo(self):
        rs = [rule("R-1", high=True, gpo="BASE"), rule("R-2", gpo="LAPS")]
        sv = [server("A", ou="OU=Engineering,OU=Tier 1,DC=x"), server("B", ou="OU=Servers,OU=Tier 1,DC=x"),
              server("C", ou="ou=servers,ou=tier 1,dc=x")]
        d = data(rs, sv, [val("A", "R-1", ""), val("B", "R-1", "0", "gpo", "TEST"), val("C", "R-1", "1"), val("C", "R-2", "1")],
                 gpo=[GpoResult("A", "BASE", False, "Not linked to OU=Engineering"), GpoResult("B", "LAPS", False,
                      "Security filtering: not a member of LAPS-Servers"), GpoResult("C", "BASE", True)],
                 tiers={"Tier 1": {"ous": ["OU=Servers,OU=Tier 1"]}})
        fs = check_gpo(d, evaluate(d, d.values, T))
        self.assertEqual([(f.code, f.severity, f.subject, f.servers) for f in fs],
                         [("GPO-NOTAPPLIED", RED, "BASE", ["A"]), ("GPO-NOTAPPLIED", AMBER, "LAPS", ["B"]),
                          ("GPO-OU", AMBER, "Tier 1: 1 server outside the tier's OUs", ["A"]), ("GPO-OTHER", AMBER, "TEST", ["B"])])
        self.assertIn("Link the GPO", fs[0].action)
        self.assertIn("security filtering group", fs[1].action)
        self.assertIn("1 of these servers are in an OU", fs[0].detail)

    def test_exception_states(self):
        rs = [rule(f"R-{k}") for k in range(1, 6)]
        vals = [val("A", f"R-{k}", "0", "local") for k in range(1, 5)] + [val("A", "R-5", "1")]
        exc = [Exception_("A", "R-1", "0", "x", "CISO", "T1", date(2026, 11, 5)), Exception_("A", "R-2", "0", "x", "CISO", "", date(2027, 1, 1)),
               Exception_("A", "R-3", "0", "x", "CISO", "T3", date(2026, 12, 1)), Exception_("A", "R-4", "2", "x", "CISO", "T4", date(2027, 6, 1)),
               Exception_("A", "R-5", "0", "x", "CISO", "T5", date(2027, 6, 1))]
        d = data(rs, [server("A")], vals, exceptions=exc)
        rv = review(d)
        self.assertEqual([x["state"] for x in rv["exceptions"]], ["expired", "incomplete", "expiring", "value differs", "not needed"])
        self.assertEqual([(f.code, f.severity) for f in check_exceptions(d, rv["results"])],
                         [("EXC-EXPIRED", AMBER), ("EXC-INCOMPLETE", AMBER), ("EXC-EXPIRING", AMBER)])
        st = {r.rule.id: r.status for r in rv["results"]}
        self.assertEqual(st, {"R-1": "deviation", "R-2": "deviation", "R-3": "exception", "R-4": "deviation", "R-5": "compliant"})
        self.assertEqual(sorted(x.decision.split(" ")[0] for x in rv["decisions"]), ["Approve", "Fix"])

    def test_hygiene_stale_coverage_uptime_and_patch(self):
        rs = [rule("R-1")]
        sv = [server("DC", "Tier 0", last_reboot=date(2026, 8, 1), last_patch=date(2026, 7, 1)), server("A"), server("GONE"),
              server("MAINT", maintenance=True)]
        vals = [val("DC", "R-1", "1", when=datetime(2026, 10, 20)), val("A", "R-1", "1"), val("GHOST", "R-1", "1"),
                val("MAINT", "R-1", "1", when=datetime(2026, 9, 1))]
        d = data(rs, sv, vals)
        fs = check_hygiene(d, server_rows(d, evaluate(d, d.values, T)))
        self.assertEqual([(f.code, f.severity, f.servers) for f in fs],
                         [("HYG-STALE", RED, ["DC"]), ("HYG-NOTCOLLECTED", AMBER, ["GONE"]), ("HYG-UNKNOWN", AMBER, ["GHOST"]),
                          ("HYG-UPTIME", AMBER, ["DC"]), ("HYG-PATCH", AMBER, ["DC"])])
        self.assertIn("23 days", fs[0].detail)

    def test_review_orders_findings_owners_due_dates_and_decisions(self):
        rs = [rule("NET-01", "0", high=True, area="Network"), rule("RDP-01", "1", high=True, area="RDP")]
        sv = [server("T1", environment="test"), server("T2", environment="test"), server("J")]
        d = data(rs, sv, [val("T1", "NET-01", "1", "gpo", "TEST GPO"), val("T2", "NET-01", "1", "gpo", "TEST GPO"), val("J", "NET-01", "0"),
                          val("T1", "RDP-01", "1"), val("T2", "RDP-01", "1"), val("J", "RDP-01", "0", "gpo", "JUMP GPO")],
                 owners={"Network": "Net team"})
        rv = review(d)
        f = rv["findings"][0]
        self.assertEqual((f.code, f.severity, f.owner, f.due), ("RISK-HIGH", RED, "Net team", date(2026, 11, 19)))
        other = [x for x in rv["findings"] if x.code == "GPO-OTHER"]
        self.assertEqual([(x.subject, x.due) for x in other], [("TEST GPO", date(2026, 12, 12)), ("JUMP GPO", date(2026, 12, 12))])
        props = {x.decision: x.proposed for x in rv["decisions"]}
        self.assertIn("test servers follow the production baseline", props["Settings from TEST GPO on 2 servers"])
        self.assertIn("pilot ring", props["Settings from JUMP GPO on 1 server"])
        self.assertEqual([x.id for x in rv["decisions"]], ["D-01", "D-02"])
        self.assertEqual(rv["status"], RED)


class TestEndToEnd(unittest.TestCase):
    def test_demo_end_to_end_is_deterministic_with_the_planted_findings(self):
        with tempfile.TemporaryDirectory() as t:
            digests = []
            for _ in range(2):
                self.assertEqual(cli.main(["demo", "--data", str(Path(t) / "d"), "--out", str(Path(t) / "o")]), 0)
                files = sorted(list((Path(t) / "d").iterdir()) + list((Path(t) / "o").iterdir()))
                digests.append({p.name: hashlib.sha1(p.read_bytes()).hexdigest() for p in files})
                self.assertFalse(any(b"\r\n" in p.read_bytes() for p in files))
            self.assertEqual(digests[0], digests[1])
            self.assertEqual(sorted(p.name for p in (Path(t) / "o").iterdir()), sorted(cli.OUTPUTS))
            size = sum(p.stat().st_size for p in (Path(t) / "d").iterdir())
            fd = rows(Path(t) / "o" / "findings.csv")
            sc = {r["server"]: r for r in rows(Path(t) / "o" / "server-compliance.csv")}
            dev = rows(Path(t) / "o" / "deviations.csv")
            pack = (Path(t) / "o" / "review-pack.md").read_text(encoding="utf-8")
        self.assertLess(size, 1_000_000)
        hr = {r["subject"].split(" ")[0]: r["servers"].split("; ") for r in fd if r["code"] == "RISK-HIGH"}
        self.assertEqual(hr["SMB-01"], ["FAB-GET-FS01", "FAB-SVQ-FS01"])
        self.assertEqual(hr["SVC-01"], ["FAB-SVQ-DC02"])
        self.assertEqual(len(hr["LAP-01"]), 4)
        self.assertEqual(len(hr["DEF-02"]), 9)
        self.assertIn("FAB-GET-JMP01", hr["RDP-01"])
        self.assertEqual(sum(1 for s in hr["NET-01"] if s.startswith("FAB-TST")), 6)
        self.assertEqual(len(hr["PSH-01"]), 13)
        na = {r["subject"]: r for r in fd if r["code"] == "GPO-NOTAPPLIED"}
        self.assertEqual(na["FAB-SEC Server Baseline"]["count"], "7")
        self.assertEqual([r["subject"] for r in fd if r["code"] == "EXC-EXPIRED"], ["FAB-GET-APP07: TLS-01 TLS 1.0 server disabled"])
        self.assertEqual([r["subject"] for r in fd if r["code"] == "EXC-INCOMPLETE"], ["FAB-SVQ-APP03: SEC-02 SMB server signing required"])
        self.assertEqual(sorted(s for s, r in sc.items() if r["state"] == "stale"), ["FAB-GET-WEB03", "FAB-SVQ-APP05", "FAB-SVQ-BKP01"])
        self.assertEqual(sc["FAB-SVQ-SQL02"]["state"], "not reporting")
        self.assertTrue(all(int(sc[s]["days_since_collection"]) >= 20 for s in ("FAB-GET-WEB03", "FAB-SVQ-APP05", "FAB-SVQ-BKP01")))
        self.assertTrue(any(r["server"] == "FAB-GET-APP07" and r["setting_id"] == "TLS-01" and r["new_drift"] == "yes" for r in dev))
        self.assertIn("## Decisions needed", pack)
        self.assertIn("## Audit evidence (ISO 27001 / NIS2)", pack)
        self.assertEqual(fd[0]["severity"], "RED")

    def test_review_reports_missing_files_and_runs_on_the_minimum(self):
        with tempfile.TemporaryDirectory() as t:
            o = str(Path(t) / "o")
            self.assertEqual(cli.main(["review", t, "--out", o]), 2)
            self.assertEqual(cli.main(["review", "--out", o]), 2)
            self.assertEqual(cli.main(["review", str(Path(t) / "nope"), "--out", o]), 2)
            write(Path(t) / "baseline.csv", ["SettingId", "Name", "Expected"], [["R-1", "One", "1"]])
            write(Path(t) / "servers.csv", ["Server", "Tier"], [["S1", "1"]])
            write(Path(t) / "settings.csv", ["Server", "SettingId", "Actual", "Source"], [["S1", "R-1", "1", "GPO"]])
            self.assertEqual(cli.main(["review", t, "--out", o, "--as-of", "2026-11-12"]), 0)
            sc = rows(Path(o) / "server-compliance.csv")
            fd = rows(Path(o) / "findings.csv")
            dr = rows(Path(o) / "drift.csv")
        self.assertEqual((sc[0]["server"], sc[0]["compliance_pct"], sc[0]["state"]), ("S1", "100.0", "on target"))
        self.assertEqual((fd, dr), ([], []))


class TestCollector(unittest.TestCase):
    def test_collector_is_read_only_and_uses_the_real_commands(self):
        ps = (ROOT / "scripts" / "Collect-BaselineSettings.ps1").read_text(encoding="utf-8")
        self.assertIn(".SYNOPSIS", ps)
        for needed in ("Get-ItemProperty", "auditpol /get /category:* /r", "Get-Service", "Get-NetFirewallProfile", "Get-SmbServerConfiguration",
                       "Get-MpComputerStatus", "Get-MpPreference", "AttackSurfaceReductionRules_Ids", "Get-ADComputer",
                       "Get-GPResultantSetOfPolicy", "Get-GPRegistryValue", "Invoke-Command", "secedit /export"):
            self.assertIn(needed, ps)
        code = "\n".join(line for line in ps.split("#>")[1].splitlines() if not line.strip().startswith("#"))
        forbidden = re.findall(r"\b(Set-\w+|New-ItemProperty|Remove-ItemProperty|Enable-\w+|Disable-\w+|Restart-\w+|Stop-\w+|Start-Service|"
                               r"New-GPLink|Set-GPLink|Invoke-GPUpdate|auditpol /set|secedit /configure|ConvertFrom-SecureString|"
                               r"Export-Clixml)\b", code)
        self.assertEqual(forbidden, [])
        removes = re.findall(r"Remove-Item \$(\w+)", code)
        self.assertEqual(sorted(set(removes)), ["tmp", "xmlPath"])          # only its own temporary files


if __name__ == "__main__":
    unittest.main()
