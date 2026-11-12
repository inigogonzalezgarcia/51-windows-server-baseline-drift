# Data format

Put the files in one folder and run `python -m baselinedrift review <folder>`. `baseline.csv`, `servers.csv` and `settings.csv` are required; every other file adds its checks (a check without its file is skipped, not passed). Comma, semicolon or tab separated, UTF-8. Column names are matched loosely (case, accents and punctuation are ignored), and the alternatives below are accepted. Dates as ISO 8601 (`2026-11-12`, `2026-11-11T02:10:00Z`), `dd/mm/yyyy`, `MM/dd/yyyy` or `12 Nov 2026`; the time zone suffix is ignored. Server names are compared by their short name in upper case (`fab-get-fs01.fabrikam.local` = `FAB-GET-FS01`).

`baseline.csv` is the approved baseline, kept by the security and Windows teams; `servers.csv` comes from AD or the CMDB; `settings.csv` and `gpo-results.csv` from `scripts/Collect-BaselineSettings.ps1` (or any tool that reads the same values, such as an RMM or configuration scanner export reshaped to these columns); `previous.csv` is last month's `settings.csv`; `exceptions.csv` is the exceptions register.

## How the review works

| Step | Rule |
|---|---|
| Scope | Every server in `servers.csv` that has collected values, and every baseline setting whose `AppliesTo` matches the server's tier, role or environment (or `All`) |
| Status | `compliant` when the actual value meets the baseline; `missing` when there is no value (not configured, or no row for that setting); `deviation` otherwise. A deviation covered by a valid exception (approver, ticket and expiry, not expired, and the actual value is the approved one) is `exception` |
| Compliance % | (compliant + exception) / applicable, per server, area, tier, site, environment and overall. The target is `target_pct` (95), or the tier's `target_pct` in `tiers` (100 for tier 0 in the demo) |
| High risk | `HighRisk` = Yes in the baseline. Every high-risk setting with servers off it is a RED finding (`RISK-HIGH`) |
| Drift | With `previous.csv`: the same baseline is applied to last month's values (exceptions as they stood on `previous_review`). New drift = compliant or excepted then, deviation or missing now |
| Cause | The first that applies: the baseline GPO is not applied on the server (`gpo-results.csv`), the exception expired, the exception has no approver, ticket or expiry, the value was set locally (`Source` = Local), another GPO set it (`GpoName` differs from the baseline's `Gpo`), not configured, or the baseline GPO itself sets a different value |
| Severity | RED: high-risk deviations, new drift that includes a high-risk setting, a GPO with high-risk settings not applied, an expired exception on a high-risk setting, a tier 0 server not reporting, a server below `red_pct` (80). Everything else AMBER. The review is RED with any RED finding |
| Due dates | RED actions `action_days.red` (7) days from the review date, AMBER `action_days.amber` (30) |
| Servers not reporting | Last `CollectedAt` older than `stale_days` (14): `HYG-STALE`; their last known values are still counted, and the report marks them |

## Comparison

| Comparison | Example | Meets when |
|---|---|---|
| `equals` (default) | `1`, `False`, `Disabled` | The same value: numbers as numbers (`1` = `1.0`), True/False/Yes/No/Enabled/Disabled/On/Off as booleans, text case-insensitive |
| `min` / `max` | `LmCompatibilityLevel` ≥ 5; signature age ≤ 3 | Numeric |
| `in` / `not_in` | `Failure\|Success and Failure` | One of the options separated by `\|` or `;` (or none of them) |
| `contains` | `*S-1-5-32-546` | The actual list (comma separated, as secedit writes user rights) includes every expected item |

## baseline.csv

One row per setting.

| Column | Alternatives | Notes |
|---|---|---|
| SettingId | Setting id, Control id, Rule id | Required, unique (`SMB-01`). The prefix before the dash is the short code of the area in the heat map |
| Area | Category, Section | Accounts, Security options, Network, SMB and TLS, Audit policy, PowerShell, Services, Firewall, Defender, LAPS, RDP, User rights… |
| Name | Setting name, Title | |
| Type | Check type, Collector | What the collector reads: `registry`, `auditpol`, `service`, `firewall`, `smb`, `defender`, `asr`, `laps`, `userright` (see below) |
| Path | Registry path, Policy name, subcategory | Registry key (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`), audit subcategory (`Logon`), service name (`Spooler`), firewall profile (`Domain`), or the policy key for `asr` |
| ValueName | Value name, Property | Registry value, property (`StartType`, `Enabled`, `EnableSMB1Protocol`, `RealTimeProtectionEnabled`), ASR rule GUID, AD attribute or privilege (`SeDebugPrivilege`) |
| Expected | Expected value, Required value | |
| Comparison | Operator | See above |
| Severity | Impact, Priority | `high`, `medium` (default), `low`; weights in `severity_weights` for the risk score per server |
| AppliesTo | Applies to, Scope, Tier | `All`, `Tier 0`, `Tier 1`, a role (`Domain controller`) or an environment (`test`), several separated by `;` |
| Gpo | GPO name, Set by | The GPO that should set it: used for the cause and for `GPO-NOTAPPLIED` |
| Reference | Control, Standard | ISO 27001 Annex A control, NIS2 measure or internal standard id: the audit trail |
| HighRisk | High risk, Critical | `Yes` puts the setting in the high-risk list |

### Types the collector reads

| Type | Read with | Typical values |
|---|---|---|
| `registry` | `Get-ItemProperty` | The DWORD or string value |
| `auditpol` | `auditpol /get /category:* /r`, column `Inclusion Setting` | `No Auditing`, `Success`, `Failure`, `Success and Failure` |
| `service` | `Get-Service` | `StartType`: `Automatic`, `Manual`, `Disabled`; `Status`: `Running`, `Stopped` |
| `firewall` | `Get-NetFirewallProfile -PolicyStore ActiveStore` | `Enabled`: `True` / `False` |
| `smb` | `Get-SmbServerConfiguration` | `EnableSMB1Protocol`: `True` / `False` |
| `defender` | `Get-MpComputerStatus` (or `Get-MpPreference`) | `RealTimeProtectionEnabled`, `IsTamperProtected`: `True` / `False`; `AntivirusSignatureAge`: days |
| `asr` | `Get-MpPreference`, `AttackSurfaceReductionRules_Ids` and `_Actions` | `0` off, `1` block, `2` audit, `5` not configured, `6` warn |
| `userright` | `secedit /export /areas USER_RIGHTS` | SIDs, comma separated (`*S-1-5-32-544`) |
| `laps` | `Get-ADComputer -Properties msLAPS-PasswordExpirationTime` | `Present` when the attribute has a value (only the expiry time is read) |

## servers.csv

| Column | Alternatives | Notes |
|---|---|---|
| Server | Name, Computer, Hostname, dnshostname | Required |
| Role | Server role, Function | Can be used in `AppliesTo` |
| Tier | Admin tier, Security tier | `0`, `T0`, `Tier 0` → `Tier 0` |
| OS, Build | Operating system, OS build | Informational |
| OU | Distinguished name, OU path | Compared with the tier's `ous` in the settings: `GPO-OU` when it is under none of them |
| Site | Location, AD site | Compliance per site |
| Owner | Service owner, Managed by | In the deviations |
| Environment | Env, Stage | `prod` (production, live) or `test` (dev, staging, UAT, QA, lab) |
| LastPatch | Last patch date, installedon | Older than `patch_age_days` (45): `HYG-PATCH` |
| LastReboot | Last boot, LastBootUpTime | Older than `max_uptime_days` (60): `HYG-UPTIME` |
| Maintenance | In maintenance, Decommissioning | `Yes` leaves the server out of the hygiene checks |

## settings.csv and previous.csv

One row per server and setting.

| Column | Alternatives | Notes |
|---|---|---|
| Server | Computer, Hostname | Required. A server that is not in servers.csv is reported as `HYG-UNKNOWN` |
| SettingId | Setting id | Required, as in baseline.csv |
| Actual | Value, Current value | Empty with no source = not configured |
| Source | Set by, Origin | `GPO`, `Local`, `Missing` (or not configured, absent). A hint from the collector; see the script's help |
| GpoName | Winning GPO | The GPO that set the value, when known |
| CollectedAt | Collected, Timestamp | The newest per server is its last collection |

## exceptions.csv

| Column | Alternatives | Notes |
|---|---|---|
| Server | Computer | Required |
| SettingId | Setting id | Required |
| ApprovedValue | Allowed value | Empty = any value; otherwise the actual value must be this one (`value differs` when it is not) |
| Reason | Justification | |
| Approver | Approved by, Risk owner | Empty: `EXC-INCOMPLETE`, and the exception does not count |
| Ticket | Change, Risk id | Empty: `EXC-INCOMPLETE` |
| Expires | Expiry date, Valid until | Empty: `EXC-INCOMPLETE`. Passed: `EXC-EXPIRED`; within `exception_warning_days` (30): `EXC-EXPIRING`. An exception on a server that now meets the baseline is listed as `not needed` |

## gpo-results.csv

| Column | Alternatives | Notes |
|---|---|---|
| Server | Computer | |
| Gpo | GPO name | |
| Applied | Status | `Yes` / `No` |
| Reason | Denied reason, Filtering | Security filtering, WMI filter, not linked, link disabled. Words such as "link", "security", "denied" and "WMI" choose the suggested fix |
| LastRefresh | ReadTime | Informational |

## settings.json

| Key | Default | Meaning |
|---|---|---|
| `organisation`, `review_date`, `previous_review` | | Name, review date (`2026-11-12 09:00`) and the date of the last review (exceptions are judged on that date for the previous status) |
| `target_pct`, `red_pct` | 95 / 80 | Compliance target per server, and RED below |
| `tiers` | `{}` | Per tier: `ous` (the OUs where its servers belong, matched as text inside the server's OU) and `target_pct` |
| `stale_days` | 14 | Days without collection before a server counts as not reporting |
| `max_uptime_days`, `patch_age_days` | 60 / 45 | Hygiene thresholds |
| `exception_warning_days` | 30 | Days before expiry for `EXC-EXPIRING` |
| `severity_weights` | 5 / 3 / 1 | Risk score per server: the weights of its high, medium and low deviations |
| `action_days` | 7 / 30 | Days to the due date of RED / AMBER actions |
| `owners` | | Owner per baseline area (`Accounts`, `Firewall`…) and for `gpo`, `exceptions`, `hygiene` and `compliance` |

## Outputs

| File | Columns |
|---|---|
| `server-compliance.csv` | server, site, tier, role, environment, owner, OS, OU, state (on target, below target, stale, not reporting), last collection and its age, applicable, compliant, exceptions, deviations, not configured, compliance %, target, high-risk deviations, new drift, risk score, main cause |
| `deviations.csv` | One row per server and setting that is not compliant (exceptions included): expected, actual, source, GPO, status, severity, high risk, new drift, cause, exception ticket and state, reference, owner |
| `drift.csv` | Changes since the last review: new drift, resolved, other status changes, changed values, and new servers |
| `exceptions-review.csv` | Every exception with the actual value, days to expiry, state (valid, expiring, expired, incomplete, value differs, not needed) and the action |
| `findings.csv` | severity, code, group, title, subject, detail, action, servers, count, owner, due |
| `actions.csv` | ref, severity, code, subject, action, servers, owner, due, done |
