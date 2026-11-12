"""Loading: the approved baseline (baseline.csv), the server inventory from AD or the CMDB (servers.csv), the settings collected per
server (settings.csv, from scripts/Collect-BaselineSettings.ps1), last month's collection (previous.csv), the exceptions
(exceptions.csv) and the Group Policy results (gpo-results.csv). Forgiving column names, into plain dataclasses."""
from __future__ import annotations

import csv
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

BASELINE_ALIASES = {
    "id": ["SettingId", "Setting id", "Id", "Control id", "Rule id", "setting"],
    "area": ["Area", "Category", "Section", "domain"],
    "name": ["Name", "Setting", "Setting name", "Title", "Description", "policy setting"],
    "type": ["Type", "Check type", "Source type", "Collector", "kind"],
    "path": ["Path", "Registry path", "Key", "Registry key", "Policy name", "Policy path", "subcategory", "service", "profile"],
    "value_name": ["ValueName", "Value name", "Registry value", "Property", "value"],
    "expected": ["Expected", "Expected value", "Required value", "Baseline value", "Recommended value", "target value"],
    "comparison": ["Comparison", "Operator", "Compare", "Match", "rule"],
    "severity": ["Severity", "Impact", "Priority", "Criticality"],
    "applies": ["AppliesTo", "Applies to", "Scope", "Tier", "Target", "applies"],
    "gpo": ["Gpo", "GPO", "GPO name", "Group Policy", "Policy object", "set by"],
    "reference": ["Reference", "Ref", "Control", "Standard", "Iso", "framework"],
    "high_risk": ["HighRisk", "High risk", "Critical", "Key control", "flagged"],
}
SERVER_ALIASES = {
    "server": ["Server", "Name", "Computer", "ComputerName", "Hostname", "Host", "dnshostname", "ci name"],
    "role": ["Role", "Server role", "Function", "Service", "description"],
    "tier": ["Tier", "Admin tier", "Tier level", "Security tier"],
    "os": ["OS", "OperatingSystem", "Operating system", "OS version", "operatingsystemversion"],
    "build": ["Build", "OS build", "Version", "BuildNumber"],
    "ou": ["OU", "Organizational unit", "DistinguishedName", "Distinguished name", "OU path", "container"],
    "site": ["Site", "Location", "AD site", "Datacenter", "Office"],
    "owner": ["Owner", "Service owner", "Managed by", "ManagedBy", "Responsible", "support group"],
    "environment": ["Environment", "Env", "Stage", "Lifecycle"],
    "last_patch": ["LastPatch", "Last patch", "Last patch date", "Last update", "Patched", "last patched", "installedon"],
    "last_reboot": ["LastReboot", "Last reboot", "Last boot", "LastBootUpTime", "Last boot time", "boot time"],
    "maintenance": ["Maintenance", "In maintenance", "Maintenance mode", "Decommissioning"],
}
VALUE_ALIASES = {
    "server": ["Server", "Computer", "ComputerName", "Hostname", "Host", "Name"],
    "id": ["SettingId", "Setting id", "Id", "Control id", "Rule id", "setting"],
    "actual": ["Actual", "Actual value", "Value", "Current value", "Current", "Result"],
    "source": ["Source", "Set by", "Origin", "Configured by"],
    "gpo": ["GpoName", "GPO name", "Gpo", "GPO", "Winning GPO", "Policy object"],
    "collected": ["CollectedAt", "Collected at", "Collected", "Timestamp", "Scan date", "Date", "last seen"],
}
EXCEPTION_ALIASES = {
    "server": ["Server", "Computer", "ComputerName", "Hostname", "Host", "Name", "scope"],
    "id": ["SettingId", "Setting id", "Id", "Control id", "Rule id", "setting"],
    "approved": ["ApprovedValue", "Approved value", "Allowed value", "Accepted value", "Value"],
    "reason": ["Reason", "Justification", "Business reason", "Rationale", "description"],
    "approver": ["Approver", "Approved by", "Risk owner", "Accepted by"],
    "ticket": ["Ticket", "Change", "Reference", "Risk id", "Request", "ticket number"],
    "expires": ["Expires", "Expiry", "Expiry date", "Expiration", "Valid until", "End date", "review date"],
}
GPO_ALIASES = {
    "server": ["Server", "Computer", "ComputerName", "Hostname", "Host", "Name"],
    "gpo": ["Gpo", "GPO", "GPO name", "GpoName", "Policy", "Group Policy"],
    "applied": ["Applied", "Is applied", "Status", "Applied yes no", "Result"],
    "reason": ["Reason", "Denied reason", "Filtering", "Why", "Not applied reason", "detail"],
    "last_refresh": ["LastRefresh", "Last refresh", "Last applied", "ReadTime", "Last processed", "timestamp"],
}
YES = {"yes", "y", "true", "1", "x", "si", "applied", "enabled", "on"}
NO = {"no", "n", "false", "0", "not applied", "denied", "disabled", "off", "filtered"}
BOOL_TRUE = {"true", "yes", "enabled", "on"}
BOOL_FALSE = {"false", "no", "disabled", "off"}
DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M", "%d/%m/%Y", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%d %b %Y", "%d-%b-%Y")
COMPARISONS = ("equals", "min", "max", "in", "not_in", "contains")
DEFAULT_OWNERS = {"accounts": "Windows server team", "security options": "Windows server team", "network": "Windows server team",
                  "smb/tls": "Windows server team", "audit policy": "Security operations", "powershell": "Security operations",
                  "services": "Windows server team", "firewall": "Network and firewall team", "defender": "Endpoint security",
                  "laps": "Identity team", "rdp": "Windows server team", "user rights": "Identity team", "gpo": "Group Policy owner",
                  "exceptions": "Security risk manager", "hygiene": "Windows server team", "compliance": "Head of infrastructure"}


def _norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", "".join(ch for ch in s if not unicodedata.combining(ch))).strip()


def parse_dt(v) -> datetime | None:
    s = str(v or "").strip()
    if not s or _norm(s) in {"n a", "na", "none", "null", "never", "tbd"}:
        return None
    s = re.sub(r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})$", "", s)
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def parse_d(v) -> date | None:
    x = parse_dt(v)
    return x.date() if x else None


def num(v) -> float | None:
    s = str(v or "").strip()
    if not re.fullmatch(r"-?\d+([.,]\d+)?", s):
        return None
    return float(s.replace(",", "."))


def yes_no(v) -> bool | None:
    n = _norm(v)
    if n in YES:
        return True
    if n in NO:
        return False
    return None


def tier_name(v) -> str:
    """'0', 'T0', 'Tier 0', 'tier0' -> 'Tier 0'; anything else is kept as it is."""
    m = re.fullmatch(r"(?:tier|t)?\s*(\d)", _norm(v).replace(" ", ""))
    return f"Tier {m.group(1)}" if m else str(v or "").strip()


def severity(v) -> str:
    n = _norm(v)
    if n in {"high", "critical", "cat i", "1", "h"}:
        return "high"
    if n in {"low", "cat iii", "3", "l", "info", "informational"}:
        return "low"
    return "medium"


def comparison(v) -> str:
    n = _norm(v).replace(" ", "_")
    alias = {"eq": "equals", "equal": "equals", "": "equals", "is": "equals", "ge": "min", "gte": "min", "at_least": "min",
             "minimum": "min", "le": "max", "lte": "max", "at_most": "max", "maximum": "max", "one_of": "in", "any_of": "in",
             "not_one_of": "not_in", "notin": "not_in", "none_of": "not_in", "includes": "contains", "has": "contains"}
    n = alias.get(n, n)
    return n if n in COMPARISONS else "equals"


def source(v) -> str:
    """gpo, local or missing."""
    n = _norm(v)
    if n in {"", "missing", "not configured", "notconfigured", "absent", "none", "not set", "default"}:
        return "missing"
    if "gpo" in n or "group policy" in n or "policy" in n or "domain" in n:
        return "gpo"
    return "local"


def _options(expected: str) -> list[str]:
    return [x.strip() for x in re.split(r"[|;]", expected) if x.strip()]


def _same(a: str, b: str) -> bool:
    na, nb = _norm(a), _norm(b)
    if na in BOOL_TRUE | BOOL_FALSE and nb in BOOL_TRUE | BOOL_FALSE:
        return (na in BOOL_TRUE) == (nb in BOOL_TRUE)
    x, y = num(a), num(b)
    if x is not None and y is not None:
        return x == y
    return na == nb


def meets(expected: str, cmp: str, actual: str) -> bool | None:
    """Does the actual value meet the baseline? None when there is no actual value."""
    if actual is None or str(actual).strip() == "":
        return None
    actual = str(actual).strip()
    if cmp in ("min", "max"):
        x, y = num(actual), num(expected)
        if x is None or y is None:
            return False
        return x >= y if cmp == "min" else x <= y
    if cmp == "in":
        return any(_same(actual, o) for o in _options(expected))
    if cmp == "not_in":
        return not any(_same(actual, o) for o in _options(expected))
    if cmp == "contains":
        items = {_norm(x) for x in re.split(r"[,;|]", actual) if x.strip()}
        return all(_norm(o) in items for o in _options(expected))
    return _same(actual, expected)


def _read(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = fh.readline()
        fh.seek(0)
        delim = max(",;\t", key=header.count)
        reader = csv.DictReader(fh, delimiter=delim)
        return list(reader.fieldnames or []), list(reader)


def _map(fields: list[str], aliases: dict[str, list[str]]) -> dict[str, str]:
    heads = {_norm(h): h for h in fields}
    cols = {}
    for k, names in aliases.items():
        for n in names + [k.replace("_", " ")]:
            if _norm(n) in heads and heads[_norm(n)] not in cols.values():
                cols[k] = heads[_norm(n)]
                break
    return cols


def _rows(path: Path, aliases: dict[str, list[str]]) -> list[dict]:
    fields, raw = _read(path)
    cols = _map(fields, aliases)
    return [{k: (r.get(c) or "").strip() for k, c in cols.items()} for r in raw]


def host(v) -> str:
    """Short upper-case server name: 'fab-get-fs01.fabrikam.local' -> 'FAB-GET-FS01'."""
    return str(v or "").strip().split(".")[0].upper()


# ---------------------------------------------------------------- records

@dataclass
class Rule:
    id: str
    area: str = ""
    name: str = ""
    type: str = "registry"
    path: str = ""
    value_name: str = ""
    expected: str = ""
    comparison: str = "equals"
    severity: str = "medium"
    applies: list = field(default_factory=lambda: ["all"])
    gpo: str = ""
    reference: str = ""
    high_risk: bool = False

    def applies_to(self, server: "Server") -> bool:
        keys = {_norm(x) for x in self.applies}
        return bool(keys & {"all", "", _norm(server.tier), _norm(server.role), _norm(server.environment)})

    @property
    def expected_text(self) -> str:
        sym = {"equals": "=", "min": "≥", "max": "≤", "in": "one of", "not_in": "not", "contains": "includes"}[self.comparison]
        return f"{sym} {self.expected}"


@dataclass
class Server:
    server: str
    role: str = ""
    tier: str = ""
    os: str = ""
    build: str = ""
    ou: str = ""
    site: str = ""
    owner: str = ""
    environment: str = "prod"
    last_patch: date | None = None
    last_reboot: date | None = None
    maintenance: bool = False


@dataclass
class Value:
    server: str
    id: str
    actual: str = ""
    source: str = "missing"            # gpo, local or missing
    gpo: str = ""
    collected: datetime | None = None


@dataclass
class Exception_:
    server: str
    id: str
    approved: str = ""
    reason: str = ""
    approver: str = ""
    ticket: str = ""
    expires: date | None = None

    @property
    def complete(self) -> bool:
        return bool(self.approver and self.ticket and self.expires)


@dataclass
class GpoResult:
    server: str
    gpo: str
    applied: bool = True
    reason: str = ""
    last_refresh: datetime | None = None


@dataclass
class Settings:
    organisation: str = "Windows Server estate"
    review_date: datetime | None = None
    previous_review: date | None = None
    target_pct: float = 95.0
    red_pct: float = 80.0
    stale_days: int = 14
    max_uptime_days: int = 60
    patch_age_days: int = 45
    exception_warning_days: int = 30
    tiers: dict = field(default_factory=dict)              # {"Tier 0": {"ous": ["OU=Domain Controllers"], "target_pct": 100}}
    severity_weights: dict = field(default_factory=lambda: {"high": 5, "medium": 3, "low": 1})
    action_days: dict = field(default_factory=lambda: {"red": 7, "amber": 30})
    owners: dict = field(default_factory=lambda: dict(DEFAULT_OWNERS))

    def owner(self, area: str) -> str:
        k = _norm(area).replace(" ", "")
        for a, o in reversed(list(self.owners.items())):
            if _norm(a).replace(" ", "") == k:
                return o
        for a, o in DEFAULT_OWNERS.items():
            if _norm(a).replace(" ", "") == k:
                return o
        return "Windows server team"

    def target(self, tier: str) -> float:
        t = self.tier(tier)
        return float(num(t.get("target_pct")) or self.target_pct) if t else self.target_pct

    def tier(self, tier: str) -> dict:
        for k, v in self.tiers.items():
            if _norm(tier_name(k)) == _norm(tier):
                return v or {}
        return {}

    def weight(self, sev: str) -> float:
        return float(num(self.severity_weights.get(sev)) or {"high": 5, "medium": 3, "low": 1}[sev])


def settings_from_dict(raw: dict) -> Settings:
    s = Settings()
    for k, v in raw.items():
        if not hasattr(s, k) or v is None:
            continue
        cur = getattr(s, k)
        if k == "review_date":
            s.review_date = parse_dt(v)
        elif k == "previous_review":
            s.previous_review = parse_d(v)
        elif isinstance(cur, dict):
            if k == "tiers":
                s.tiers = {tier_name(a): b for a, b in v.items()}
            else:
                cur.update({str(a): b for a, b in v.items()})
        elif isinstance(cur, int) and not isinstance(cur, bool):
            setattr(s, k, int(float(v)))
        elif isinstance(cur, float):
            setattr(s, k, float(v))
        else:
            setattr(s, k, str(v))
    return s


@dataclass
class Data:
    settings: Settings
    as_of: datetime
    rules: list = field(default_factory=list)
    servers: dict = field(default_factory=dict)              # name -> Server (the inventory)
    values: dict = field(default_factory=dict)               # (server, id) -> Value
    previous: dict | None = None                             # (server, id) -> Value
    exceptions: list | None = None
    gpo: list | None = None
    sources: dict = field(default_factory=dict)

    @property
    def today(self) -> date:
        return self.as_of.date()


# ---------------------------------------------------------------- loaders

def load_baseline(path: Path) -> list[Rule]:
    out, seen = [], set()
    for r in _rows(path, BASELINE_ALIASES):
        if not r.get("id") or r["id"] in seen:
            continue
        seen.add(r["id"])
        sev = severity(r.get("severity"))
        hr = yes_no(r.get("high_risk"))
        applies = [x.strip() for x in re.split(r"[|;,]", r.get("applies", "")) if x.strip()] or ["all"]
        out.append(Rule(r["id"], r.get("area", "") or "other", r.get("name", "") or r["id"], _norm(r.get("type")) or "registry",
                        r.get("path", ""), r.get("value_name", ""), r.get("expected", ""), comparison(r.get("comparison")), sev,
                        [tier_name(a) for a in applies], r.get("gpo", ""), r.get("reference", ""), bool(hr)))
    return out


def load_servers(path: Path) -> dict:
    out = {}
    for r in _rows(path, SERVER_ALIASES):
        if not r.get("server"):
            continue
        env = _norm(r.get("environment")) or "prod"
        env = "test" if env in {"test", "dev", "development", "staging", "uat", "pre", "preprod", "qa", "lab"} else \
            "prod" if env in {"prod", "production", "live", "pro"} else env
        s = Server(host(r["server"]), r.get("role", ""), tier_name(r.get("tier")), r.get("os", ""), r.get("build", ""), r.get("ou", ""),
                   r.get("site", ""), r.get("owner", ""), env, parse_d(r.get("last_patch")), parse_d(r.get("last_reboot")),
                   bool(yes_no(r.get("maintenance"))))
        out[s.server] = s
    return out


def load_values(path: Path) -> dict:
    out = {}
    for r in _rows(path, VALUE_ALIASES):
        if not r.get("server") or not r.get("id"):
            continue
        src = source(r.get("source"))
        actual = r.get("actual", "")
        if src == "missing":
            actual = ""
        elif actual == "" and not r.get("source"):
            src = "missing"
        v = Value(host(r["server"]), r["id"], actual, src, r.get("gpo", ""), parse_dt(r.get("collected")))
        out[(v.server, v.id)] = v
    return out


def load_exceptions(path: Path) -> list[Exception_]:
    out = []
    for r in _rows(path, EXCEPTION_ALIASES):
        if not r.get("server") or not r.get("id"):
            continue
        out.append(Exception_(host(r["server"]), r["id"], r.get("approved", ""), r.get("reason", ""), r.get("approver", ""),
                              r.get("ticket", ""), parse_d(r.get("expires"))))
    return sorted(out, key=lambda x: (x.server, x.id))


def load_gpo(path: Path) -> list[GpoResult]:
    out = []
    for r in _rows(path, GPO_ALIASES):
        if not r.get("server") or not r.get("gpo"):
            continue
        a = yes_no(r.get("applied"))
        out.append(GpoResult(host(r["server"]), r["gpo"], True if a is None else a, r.get("reason", ""), parse_dt(r.get("last_refresh"))))
    return out


FILES = {
    "baseline.csv": "Approved security baseline, by tier and role",
    "servers.csv": "Server inventory (AD or the CMDB)",
    "settings.csv": "Settings collected per server (Collect-BaselineSettings.ps1)",
    "previous.csv": "Last review's collection (for drift)",
    "exceptions.csv": "Approved exceptions",
    "gpo-results.csv": "Group Policy results per server (RSoP)",
}


def load(folder: Path, as_of: datetime | None = None) -> Data:
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"no folder {folder}")
    sp = folder / "settings.json"
    s = settings_from_dict(json.loads(sp.read_text(encoding="utf-8"))) if sp.exists() else Settings()
    when = as_of or s.review_date or datetime.now().replace(second=0, microsecond=0)
    for f in ("baseline.csv", "servers.csv", "settings.csv"):
        if not (folder / f).exists():
            raise FileNotFoundError(f"{folder}: need {f} ({FILES[f]})")
    d = Data(s, when)
    d.rules = load_baseline(folder / "baseline.csv")
    if not d.rules:
        raise ValueError(f"{folder / 'baseline.csv'}: no settings (check the SettingId column)")
    d.servers = load_servers(folder / "servers.csv")
    d.values = load_values(folder / "settings.csv")
    d.sources = {"baseline.csv": len(d.rules), "servers.csv": len(d.servers), "settings.csv": len(d.values)}
    if (folder / "previous.csv").exists():
        d.previous = load_values(folder / "previous.csv")
        d.sources["previous.csv"] = len(d.previous)
    if (folder / "exceptions.csv").exists():
        d.exceptions = load_exceptions(folder / "exceptions.csv")
        d.sources["exceptions.csv"] = len(d.exceptions)
    if (folder / "gpo-results.csv").exists():
        d.gpo = load_gpo(folder / "gpo-results.csv")
        d.sources["gpo-results.csv"] = len(d.gpo)
    return d


__all__ = ["Data", "Settings", "Rule", "Server", "Value", "Exception_", "GpoResult", "load", "load_baseline", "load_servers",
           "load_values", "load_exceptions", "load_gpo", "settings_from_dict", "meets", "comparison", "severity", "source",
           "tier_name", "host", "yes_no", "num", "parse_d", "parse_dt", "FILES"]
