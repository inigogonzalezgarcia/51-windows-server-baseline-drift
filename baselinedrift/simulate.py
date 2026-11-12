"""Deterministic demo data: Fabrikam Aerospace, a made-up aerospace parts manufacturer with two sites (Getafe and Sevilla), 56 Windows
servers in the inventory (4 domain controllers in tier 0, member servers in tier 1, 6 test servers) and a 45-setting security
baseline. The review runs on 12 November 2026; the previous one was on 12 October. The problems are placed on purpose among servers
that follow the baseline:

- SMBv1 re-enabled locally on the two file servers by a legacy scanner integration;
- the server baseline GPO not applying to 7 servers moved to a new OU that has no link to it;
- LAPS missing on the 4 new servers (not in the LAPS GPO's security filtering group);
- LLMNR on in the test environment (a test GPO wins over the baseline);
- the Print Spooler set to automatic on one domain controller;
- RDP without NLA on the Getafe jump server (set by the jump server GPO);
- two Defender ASR rules in audit on 9 servers where block is expected (a pilot GPO that was never closed);
- TLS 1.0 enabled on an old application server whose exception expired last week;
- 3 servers not reporting for 20 days or more;
- an exception with no approver;
- PowerShell script block and module logging off on the Sevilla member servers (the GPO link was disabled).
"""
from __future__ import annotations

import csv
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

ORG = "Fabrikam Aerospace"
AS_OF = datetime(2026, 11, 12, 9, 0)
PREVIOUS = date(2026, 10, 12)
SEED = 51
DOMAIN = "DC=fabrikam,DC=local"

G_BASE, G_DC, G_AUD, G_DEF, G_FW, G_LAPS, G_PS = ("FAB-SEC Server Baseline", "FAB-SEC Domain Controller Baseline", "FAB-SEC Audit Policy",
                                                   "FAB-SEC Defender", "FAB-SEC Windows Firewall", "FAB-SEC LAPS",
                                                   "FAB-SEC PowerShell Logging")
G_TEST, G_JUMP, G_PILOT = "FAB-TEST Server Settings", "FAB-ADM Jump Servers", "FAB-SEC Defender ASR Pilot"
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
SCH = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
TS = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
PSK = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
ASR = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
ADMINS, GUESTS = "*S-1-5-32-544", "*S-1-5-32-546"
# id, area, name, type, path, value name, expected, comparison, severity, applies to, GPO, reference, high risk
BASELINE = [
    ("ACC-01", "Accounts", "Blank passwords only at the console", "registry", LSA, "LimitBlankPasswordUse", "1", "equals", "medium", "All", G_BASE, "A.8.5; FAB-SRV-001", ""),
    ("ACC-02", "Accounts", "Do not store the LAN Manager hash", "registry", LSA, "NoLMHash", "1", "equals", "high", "All", G_BASE, "A.8.5; FAB-SRV-002", ""),
    ("ACC-03", "Accounts", "No anonymous enumeration of SAM accounts and shares", "registry", LSA, "RestrictAnonymous", "1", "equals", "medium", "All", G_BASE, "A.8.3; FAB-SRV-003", ""),
    ("ACC-04", "Accounts", "WDigest keeps no clear-text credentials", "registry", r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", "0", "equals", "high", "All", G_BASE, "A.8.5; FAB-SRV-004", ""),
    ("ACC-05", "Accounts", "LSA protection (RunAsPPL)", "registry", LSA, "RunAsPPL", "1|2", "in", "medium", "All", G_BASE, "A.8.5; FAB-SRV-005", ""),
    ("SEC-01", "Security options", "LAN Manager auth level: NTLMv2 only, refuse LM and NTLM", "registry", LSA, "LmCompatibilityLevel", "5", "min", "high", "All", G_BASE, "A.8.5; FAB-SRV-010", "yes"),
    ("SEC-02", "Security options", "SMB server signing required", "registry", r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", "1", "equals", "high", "All", G_BASE, "A.8.20; FAB-SRV-011", ""),
    ("SEC-03", "Security options", "SMB client signing required", "registry", r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", "1", "equals", "medium", "All", G_BASE, "A.8.20; FAB-SRV-012", ""),
    ("SEC-04", "Security options", "LDAP server signing required", "registry", r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", "2", "equals", "high", "Tier 0", G_DC, "A.8.20; FAB-DC-001", ""),
    ("SEC-05", "Security options", "NTLM server session security: NTLMv2 and 128-bit", "registry", LSA + r"\MSV1_0", "NTLMMinServerSec", "537395200", "equals", "medium", "All", G_BASE, "A.8.5; FAB-SRV-013", ""),
    ("SEC-06", "Security options", "UAC Admin Approval Mode on", "registry", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "1", "equals", "medium", "All", G_BASE, "A.8.2; FAB-SRV-014", ""),
    ("NET-01", "Network", "LLMNR off (turn off multicast name resolution)", "registry", r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", "0", "equals", "high", "All", G_BASE, "A.8.20; FAB-SRV-020", "yes"),
    ("SMB-01", "SMB and TLS", "SMBv1 server off", "smb", "", "EnableSMB1Protocol", "False", "equals", "high", "All", G_BASE, "A.8.20; FAB-SRV-030", "yes"),
    ("SMB-02", "SMB and TLS", "SMBv1 client driver disabled", "registry", r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", "4", "equals", "medium", "All", G_BASE, "A.8.20; FAB-SRV-031", ""),
    ("TLS-01", "SMB and TLS", "TLS 1.0 server disabled", "registry", SCH + r"\TLS 1.0\Server", "Enabled", "0", "equals", "high", "All", G_BASE, "A.8.24; FAB-SRV-032", "yes"),
    ("TLS-02", "SMB and TLS", "TLS 1.1 server disabled", "registry", SCH + r"\TLS 1.1\Server", "Enabled", "0", "equals", "high", "All", G_BASE, "A.8.24; FAB-SRV-033", "yes"),
    ("TLS-03", "SMB and TLS", "SSL 3.0 server disabled", "registry", SCH + r"\SSL 3.0\Server", "Enabled", "0", "equals", "high", "All", G_BASE, "A.8.24; FAB-SRV-034", "yes"),
    ("AUD-01", "Audit policy", "Audit Logon", "auditpol", "Logon", "", "Success and Failure", "equals", "high", "All", G_AUD, "A.8.15; FAB-SRV-040", "yes"),
    ("AUD-02", "Audit policy", "Audit Account Lockout", "auditpol", "Account Lockout", "", "Failure|Success and Failure", "in", "high", "All", G_AUD, "A.8.15; FAB-SRV-041", "yes"),
    ("AUD-03", "Audit policy", "Audit Credential Validation", "auditpol", "Credential Validation", "", "Success and Failure", "equals", "medium", "All", G_AUD, "A.8.15; FAB-SRV-042", ""),
    ("AUD-04", "Audit policy", "Audit Security Group Management", "auditpol", "Security Group Management", "", "Success|Success and Failure", "in", "medium", "All", G_AUD, "A.8.15; FAB-SRV-043", ""),
    ("AUD-05", "Audit policy", "Audit User Account Management", "auditpol", "User Account Management", "", "Success and Failure", "equals", "medium", "All", G_AUD, "A.8.15; FAB-SRV-044", ""),
    ("AUD-06", "Audit policy", "Audit Process Creation", "auditpol", "Process Creation", "", "Success|Success and Failure", "in", "medium", "All", G_AUD, "A.8.15; FAB-SRV-045", ""),
    ("AUD-07", "Audit policy", "Audit Audit Policy Change", "auditpol", "Audit Policy Change", "", "Success|Success and Failure", "in", "medium", "All", G_AUD, "A.8.15; FAB-SRV-046", ""),
    ("AUD-08", "Audit policy", "Audit Directory Service Changes", "auditpol", "Directory Service Changes", "", "Success|Success and Failure", "in", "medium", "Tier 0", G_DC, "A.8.15; FAB-DC-002", ""),
    ("AUD-09", "Audit policy", "Security log maximum size (KB)", "registry", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", "MaxSize", "196608", "min", "low", "All", G_AUD, "A.8.15; FAB-SRV-047", ""),
    ("PSH-01", "PowerShell", "Script block logging on", "registry", PSK + r"\ScriptBlockLogging", "EnableScriptBlockLogging", "1", "equals", "high", "All", G_PS, "A.8.15; FAB-SRV-050", "yes"),
    ("PSH-02", "PowerShell", "Module logging on", "registry", PSK + r"\ModuleLogging", "EnableModuleLogging", "1", "equals", "medium", "All", G_PS, "A.8.15; FAB-SRV-051", ""),
    ("SVC-01", "Services", "Print Spooler disabled on domain controllers", "service", "Spooler", "StartType", "Disabled", "equals", "high", "Tier 0", G_DC, "A.8.9; FAB-DC-003", "yes"),
    ("SVC-02", "Services", "Windows Remote Management running", "service", "WinRM", "Status", "Running", "equals", "low", "All", G_BASE, "A.8.9; FAB-SRV-060", ""),
    ("FW-01", "Firewall", "Domain profile on", "firewall", "Domain", "Enabled", "True", "equals", "high", "All", G_FW, "A.8.20; FAB-SRV-070", "yes"),
    ("FW-02", "Firewall", "Private profile on", "firewall", "Private", "Enabled", "True", "equals", "high", "All", G_FW, "A.8.20; FAB-SRV-071", "yes"),
    ("FW-03", "Firewall", "Public profile on", "firewall", "Public", "Enabled", "True", "equals", "high", "All", G_FW, "A.8.20; FAB-SRV-072", "yes"),
    ("DEF-01", "Defender", "Real-time protection on", "defender", "", "RealTimeProtectionEnabled", "True", "equals", "high", "All", G_DEF, "A.8.7; FAB-SRV-080", "yes"),
    ("DEF-02", "Defender", "ASR: block credential stealing from LSASS", "asr", ASR, "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "1", "equals", "high", "All", G_DEF, "A.8.7; FAB-SRV-081", "yes"),
    ("DEF-03", "Defender", "ASR: block abuse of exploited vulnerable signed drivers", "asr", ASR, "56a863a9-875e-4185-98a7-b882c64b5ce5", "1", "equals", "medium", "All", G_DEF, "A.8.7; FAB-SRV-082", ""),
    ("DEF-04", "Defender", "Antivirus signatures at most 3 days old", "defender", "", "AntivirusSignatureAge", "3", "max", "medium", "All", G_DEF, "A.8.7; FAB-SRV-083", ""),
    ("DEF-05", "Defender", "Tamper protection on", "defender", "", "IsTamperProtected", "True", "equals", "medium", "All", G_DEF, "A.8.7; FAB-SRV-084", ""),
    ("LAP-01", "LAPS", "LAPS manages the local administrator password", "laps", "", "msLAPS-PasswordExpirationTime", "Present", "equals", "high", "Tier 1", G_LAPS, "A.8.2; FAB-SRV-090", "yes"),
    ("RDP-01", "RDP", "Network Level Authentication required", "registry", TS, "UserAuthentication", "1", "equals", "high", "All", G_BASE, "A.8.5; FAB-SRV-100", "yes"),
    ("RDP-02", "RDP", "RDP security layer: TLS", "registry", TS, "SecurityLayer", "2", "equals", "medium", "All", G_BASE, "A.8.24; FAB-SRV-101", ""),
    ("RDP-03", "RDP", "RDP encryption level: high", "registry", TS, "MinEncryptionLevel", "3", "min", "low", "All", G_BASE, "A.8.24; FAB-SRV-102", ""),
    ("URA-01", "User rights", "Debug programs: Administrators only", "userright", "", "SeDebugPrivilege", ADMINS, "equals", "medium", "All", G_BASE, "A.8.2; FAB-SRV-110", ""),
    ("URA-02", "User rights", "Deny access from the network: Guests", "userright", "", "SeDenyNetworkLogonRight", GUESTS, "contains", "medium", "All", G_BASE, "A.8.2; FAB-SRV-111", ""),
    ("URA-03", "User rights", "Log on through RDP (DCs): Administrators only", "userright", "", "SeRemoteInteractiveLogonRight", ADMINS, "equals", "medium", "Tier 0", G_DC, "A.8.2; FAB-DC-004", ""),
]
GOOD = {"ACC-05": "2", "SEC-01": "5", "AUD-02": "Failure", "AUD-04": "Success", "AUD-06": "Success", "AUD-07": "Success",
        "AUD-08": "Success", "AUD-09": "196608", "RDP-03": "3", "URA-02": GUESTS}
# what a server has for the server baseline GPO's settings when that GPO does not apply (Windows defaults; "" = not set)
NO_BASE = {"ACC-01": "1", "ACC-02": "1", "ACC-03": "0", "ACC-04": "", "ACC-05": "", "SEC-01": "", "SEC-02": "0", "SEC-03": "0",
           "SEC-05": "536870912", "SEC-06": "1", "NET-01": "", "SMB-01": "False", "SMB-02": "", "TLS-01": "", "TLS-02": "", "TLS-03": "",
           "SVC-02": "Running", "RDP-01": "", "RDP-02": "", "RDP-03": "", "URA-01": ADMINS,
           "URA-02": "*S-1-5-21-1004336348-1177238915-682003330-501"}

OU_DC = f"OU=Domain Controllers,{DOMAIN}"


def _ou(site: str, sub: str = "Servers") -> str:
    return f"OU={sub},OU=Tier 1,OU={site},{DOMAIN}"


# name, role, site, OS, owner, environment
SERVERS = [
    ("FAB-GET-DC01", "Domain controller", "Getafe", "2022", "Identity team"), ("FAB-GET-DC02", "Domain controller", "Getafe", "2022", "Identity team"),
    ("FAB-SVQ-DC01", "Domain controller", "Sevilla", "2022", "Identity team"), ("FAB-SVQ-DC02", "Domain controller", "Sevilla", "2022", "Identity team"),
    ("FAB-GET-FS01", "File server", "Getafe", "2019", "Windows server team"), ("FAB-GET-FS02", "File server", "Getafe", "2022", "Windows server team"),
    ("FAB-SVQ-FS01", "File server", "Sevilla", "2019", "Windows server team"),
] + [(f"FAB-GET-APP{k:02d}", "Application server", "Getafe", "2016" if k == 7 else "2022" if k > 8 else "2019",
      ["ERP team", "MES team", "PLM team", "Quality apps team"][k % 4]) for k in range(1, 11)] \
  + [(f"FAB-SVQ-APP{k:02d}", "Application server", "Sevilla", "2022" if k > 6 else "2019",
      ["ERP team", "MES team", "Quality apps team"][k % 3]) for k in range(1, 9)] \
  + [(f"FAB-GET-SQL{k:02d}", "SQL Server", "Getafe", "2019", "Database team") for k in range(1, 5)] \
  + [(f"FAB-SVQ-SQL{k:02d}", "SQL Server", "Sevilla", "2019", "Database team") for k in range(1, 4)] \
  + [(f"FAB-GET-WEB{k:02d}", "Web server (IIS)", "Getafe", "2022", "Web team") for k in range(1, 4)] \
  + [(f"FAB-SVQ-WEB{k:02d}", "Web server (IIS)", "Sevilla", "2022", "Web team") for k in range(1, 3)] \
  + [("FAB-GET-JMP01", "Jump server", "Getafe", "2022", "Windows server team"), ("FAB-GET-PRN01", "Print server", "Getafe", "2019",
      "Windows server team"), ("FAB-SVQ-PRN01", "Print server", "Sevilla", "2019", "Windows server team"),
     ("FAB-GET-WSUS01", "WSUS", "Getafe", "2019", "Windows server team"), ("FAB-GET-BKP01", "Backup server", "Getafe", "2022",
      "Backup team"), ("FAB-SVQ-BKP01", "Backup server", "Sevilla", "2022", "Backup team")] \
  + [(f"FAB-GET-ENG{k:02d}", "Engineering application", "Getafe", "2022", "Engineering IT") for k in range(1, 8)] \
  + [(f"FAB-TST-{x}", "Test server", "Getafe", "2022", "Application test team") for x in ("APP01", "APP02", "APP03", "APP04", "SQL01", "WEB01")]
BUILD = {"2016": "10.0.14393", "2019": "10.0.17763", "2022": "10.0.20348"}
ENG = [f"FAB-GET-ENG{k:02d}" for k in range(1, 8)]
NEW = ["FAB-GET-APP09", "FAB-GET-APP10", "FAB-SVQ-APP07", "FAB-SVQ-APP08"]
PILOT = [f"FAB-GET-APP{k:02d}" for k in range(1, 7)] + [f"FAB-GET-SQL{k:02d}" for k in range(1, 4)]
STALE = {"FAB-SVQ-APP05": 24, "FAB-GET-WEB03": 21, "FAB-SVQ-BKP01": 20}
NOT_COLLECTED = "FAB-SVQ-SQL02"
UNKNOWN = "FAB-GET-OLD01"
UPTIME = {"FAB-GET-APP07": 141, "FAB-GET-SQL02": 75, "FAB-SVQ-SQL03": 88}
PATCH = {"FAB-GET-APP07": 120, "FAB-SVQ-SQL03": 70}
EXCEPTIONS = [
    ("FAB-GET-APP07", "TLS-01", "1", "Legacy quality-records app (vendor client only speaks TLS 1.0); upgrade planned", "Head of Information Security", "RISK-0217", "2026-11-05"),
    ("FAB-SVQ-APP03", "SEC-02", "0", "Old scan-to-folder appliance does not sign SMB", "", "RITM0041877", "2027-02-28"),
    ("FAB-GET-APP04", "SMB-02", "3", "MES client reads an old NAS share over SMBv1; NAS replacement in project PRJ-118", "Head of Information Security", "RISK-0231", "2027-03-31"),
    ("FAB-GET-APP08", "TLS-02", "1", "Partner EDI gateway still on TLS 1.1; partner migrating", "CISO", "RISK-0240", "2026-12-01"),
    ("FAB-SVQ-WEB01", "RDP-03", "2", "Old monitoring console used RDP encryption level 2", "Head of Information Security", "RISK-0198", "2027-01-31"),
]


def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def inventory() -> list[dict]:
    out = []
    for name, role, site, os_, owner in SERVERS:
        tier = "Tier 0" if role == "Domain controller" else "Tier 1"
        env = "test" if name.startswith("FAB-TST") else "prod"
        ou = OU_DC if tier == "Tier 0" else _ou(site, "Engineering") if name in ENG else _ou(site, "Test") if env == "test" else _ou(site)
        out.append({"server": name, "role": role, "tier": tier, "os": f"Windows Server {os_}", "build": BUILD[os_], "ou": ou,
                    "site": site, "owner": owner, "environment": env})
    return out


def gpos_for(s: dict) -> list[tuple[str, bool, str]]:
    """The GPOs each server should get, whether they apply and why not."""
    name = s["server"]
    out = [(G_BASE, name not in ENG, f"Not linked to OU=Engineering,OU=Tier 1,OU={s['site']}" if name in ENG else ""),
           (G_AUD, True, ""), (G_DEF, True, ""), (G_FW, True, "")]
    if s["tier"] == "Tier 0":
        out.append((G_DC, True, ""))
        out.append((G_PS, True, ""))
    else:
        out.append((G_LAPS, name not in NEW, "Security filtering: not a member of FAB-LAPS-Servers" if name in NEW else ""))
        off = s["site"] == "Sevilla" and name not in STALE
        out.append((G_PS, not off, "Link disabled on OU=Servers,OU=Tier 1,OU=Sevilla" if off else ""))
    if s["environment"] == "test":
        out.append((G_TEST, True, ""))
    if s["role"] == "Jump server":
        out.append((G_JUMP, True, ""))
    if name in PILOT:
        out.append((G_PILOT, True, ""))
    return out


def values(s: dict, previous: bool = False) -> dict:
    """Setting id -> (actual, source, GPO) for one server, now or at the last review."""
    name = s["server"]
    out = {}
    for row in BASELINE:
        rid, typ, expected, applies, gpo = row[0], row[3], row[6], row[9], row[10]
        if applies not in ("All", s["tier"]):
            continue
        good = GOOD.get(rid, expected.split("|")[0])
        out[rid] = (good, "GPO", gpo)
    if name.startswith("FAB-GET-OLD"):
        return out
    if not previous:
        if name in ENG:
            for rid, v in NO_BASE.items():
                if rid in out:
                    out[rid] = (v, "Local" if v else "Missing", "")
        if name in NEW:
            out["LAP-01"] = ("", "Missing", "")
        if s["site"] == "Sevilla" and s["tier"] == "Tier 1" and name not in STALE:
            out["PSH-01"] = ("", "Missing", "")
            out["PSH-02"] = ("", "Missing", "")
        if name in ("FAB-GET-FS01", "FAB-SVQ-FS01"):
            out["SMB-01"] = ("True", "Local", "")
        if name == "FAB-SVQ-DC02":
            out["SVC-01"] = ("Automatic", "Local", "")
    if s["environment"] == "test":
        out["NET-01"] = ("1", "GPO", G_TEST)
    if s["role"] == "Jump server":
        out["RDP-01"] = ("0", "GPO", G_JUMP)
    if name in PILOT:
        out["DEF-02"] = ("2", "GPO", G_PILOT)
        out["DEF-03"] = ("2", "GPO", G_PILOT)
    if name == "FAB-GET-APP07":
        out["TLS-01"] = ("1", "Local", "")
    if name == "FAB-SVQ-APP03":
        out["SEC-02"] = ("0", "Local", "")
    if name == "FAB-GET-APP04":
        out["SMB-02"] = ("3", "Local", "")
    if name == "FAB-GET-APP08":
        out["TLS-02"] = ("1", "Local", "")
    if name == "FAB-SVQ-WEB01" and previous:
        out["RDP-03"] = ("2", "Local", "")
    return out


def build(rnd: random.Random) -> dict:
    inv = inventory()
    servers, settings, previous, gpo = [], [], [], []
    for s in inv:
        name = s["server"]
        patched = AS_OF.date() - timedelta(days=PATCH.get(name, rnd.randint(28, 31)))
        reboot = AS_OF.date() - timedelta(days=UPTIME.get(name, (AS_OF.date() - patched).days))
        servers.append([name, s["role"], s["tier"], s["os"], s["build"], s["ou"], s["site"], s["owner"], s["environment"],
                        patched.isoformat(), reboot.isoformat(), "No"])
        if name == NOT_COLLECTED:
            continue
        prev_at = datetime(2026, 10, 11, 2, 0) + timedelta(minutes=rnd.randint(0, 150))
        for rid, (v, src, g) in (values(s, previous=True) if name not in NEW else {}).items():
            previous.append([name, rid, v, src, g, prev_at.strftime("%Y-%m-%d %H:%M")])
        at = (AS_OF - timedelta(days=STALE[name], hours=7) if name in STALE else
              datetime(2026, 11, 11, 2, 0) + timedelta(minutes=rnd.randint(0, 150)))
        cur = values(s)
        for rid, (v, src, g) in cur.items():
            if rid == "DEF-04" and src == "GPO":
                v = str(rnd.choice([0, 0, 1]))
            settings.append([name, rid, v, src, g, at.strftime("%Y-%m-%d %H:%M")])
        for g, applied, reason in gpos_for(s):
            if name in STALE and g == G_PS:
                applied, reason = True, ""
            gpo.append([name, g, "Yes" if applied else "No", reason, at.strftime("%Y-%m-%d %H:%M")])
    # a server that is still collected but no longer in the inventory
    old = {"server": UNKNOWN, "tier": "Tier 1", "site": "Getafe", "environment": "prod", "role": ""}
    at = datetime(2026, 11, 11, 2, 47)
    for rid, (v, src, g) in values(old).items():
        settings.append([UNKNOWN, rid, v, src, g, at.strftime("%Y-%m-%d %H:%M")])
    settings.sort(key=lambda r: (r[0], r[1]))
    previous.sort(key=lambda r: (r[0], r[1]))
    gpo.sort(key=lambda r: (r[0], r[1]))
    return {"servers": servers, "settings": settings, "previous": previous, "gpo": gpo}


def settings_json() -> dict:
    return {
        "organisation": ORG,
        "review_date": AS_OF.strftime("%Y-%m-%d %H:%M"),
        "previous_review": PREVIOUS.isoformat(),
        "target_pct": 95,
        "red_pct": 80,
        "stale_days": 14,
        "max_uptime_days": 60,
        "patch_age_days": 45,
        "exception_warning_days": 30,
        "tiers": {"Tier 0": {"ous": ["OU=Domain Controllers"], "target_pct": 100},
                  "Tier 1": {"ous": ["OU=Servers,OU=Tier 1", "OU=Test,OU=Tier 1"], "target_pct": 95}},
        "severity_weights": {"high": 5, "medium": 3, "low": 1},
        "action_days": {"red": 7, "amber": 30},
        "owners": {"Accounts": "Windows server team", "Security options": "Windows server team", "Network": "Windows server team",
                   "SMB and TLS": "Windows server team", "Audit policy": "Security operations", "PowerShell": "Security operations",
                   "Services": "Windows server team", "Firewall": "Network and firewall team", "Defender": "Endpoint security",
                   "LAPS": "Identity team", "RDP": "Windows server team", "User rights": "Identity team", "gpo": "Group Policy owner",
                   "exceptions": "Security risk manager", "hygiene": "Windows server team", "compliance": "Head of infrastructure"},
    }


def write(folder: Path) -> None:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    b = build(random.Random(SEED))
    _w(folder / "baseline.csv", ["SettingId", "Area", "Name", "Type", "Path", "ValueName", "Expected", "Comparison", "Severity",
                                 "AppliesTo", "Gpo", "Reference", "HighRisk"], [list(r) for r in BASELINE])
    _w(folder / "servers.csv", ["Server", "Role", "Tier", "OS", "Build", "OU", "Site", "Owner", "Environment", "LastPatch", "LastReboot",
                                "Maintenance"], b["servers"])
    _w(folder / "settings.csv", ["Server", "SettingId", "Actual", "Source", "GpoName", "CollectedAt"], b["settings"])
    _w(folder / "previous.csv", ["Server", "SettingId", "Actual", "Source", "GpoName", "CollectedAt"], b["previous"])
    _w(folder / "exceptions.csv", ["Server", "SettingId", "ApprovedValue", "Reason", "Approver", "Ticket", "Expires"],
       [list(x) for x in EXCEPTIONS])
    _w(folder / "gpo-results.csv", ["Server", "Gpo", "Applied", "Reason", "LastRefresh"], b["gpo"])
    (folder / "settings.json").write_text(json.dumps(settings_json(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


__all__ = ["write", "build", "ORG", "AS_OF", "BASELINE", "SEED"]
