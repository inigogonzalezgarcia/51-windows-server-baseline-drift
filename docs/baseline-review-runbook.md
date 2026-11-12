# Monthly Windows Server baseline review

How to run the monthly review of the Windows Server security baseline with `baselinedrift`, decide what to do with each deviation, change the baseline without breaking applications, and keep the evidence an ISO 27001 or NIS2 auditor will ask for. The tool only reads; settings, GPOs and exceptions are changed by their owners, through change management.

## Who is involved

| Role | Part |
|---|---|
| Windows server team | Runs the collection and the review, fixes deviations on the servers, owns the server baseline GPOs |
| Group Policy owner | Links, filtering and WMI filters; reviews any GPO that touches a baseline setting |
| Security (CISO office) | Owns the baseline content, approves exceptions and baseline changes, uses the pack as audit evidence |
| Security operations | Audit policy, PowerShell logging and the event collection that depends on them |
| Endpoint security | Defender and the ASR rules |
| Identity team | Domain controllers (tier 0), LAPS, user rights |
| Application and service owners | Confirm what an application needs before a setting is enforced; request exceptions |
| Change manager | Every fix and every GPO change goes through a change record |

## The monthly cycle

| When | What | Output |
|---|---|---|
| Day 1 | Rename last month's `settings.csv` to `previous.csv`; export `servers.csv` from AD or the CMDB; run `scripts/Collect-BaselineSettings.ps1` | `data/` |
| Day 1 | Run the review; send each owner their servers from `server-compliance.csv` and `deviations.csv` | `output/` |
| Day 1 to 5 | RED findings: high-risk deviations, GPOs not applied, expired exceptions on high-risk settings, tier 0 not reporting. Fix or raise a decision; do not wait for the meeting | change records |
| Day 5 | Monthly review with security and infrastructure: the pack, the decisions, the exceptions expiring | `review-pack.md` |
| Day 5 to 30 | AMBER actions by their due date; recollect the fixed servers to close them | `actions.csv` |
| Every quarter | Review the baseline itself: new Microsoft guidance, settings that cause exceptions on many servers, settings nobody can explain | baseline change request |

```powershell
Move-Item .\data\settings.csv .\data\previous.csv -Force
.\scripts\Collect-BaselineSettings.ps1 -Baseline .\data\baseline.csv -Servers .\data\servers.csv -OutputFolder .\data
python -m baselinedrift review data/
```

Collect from an admin workstation or jump server of the right tier: a tier 1 account for member servers, a tier 0 account from a tier 0 host for the domain controllers. Do not use a domain admin session to read member servers.

## Reading the result

1. **Coverage first.** Servers not reporting, servers in the inventory with no collection, servers collected that the inventory does not know. A server that does not report is not compliant, it is unknown; the pack says so.
2. **Causes before settings.** One GPO not applied explains dozens of deviations. Fix the link, the security filtering or the WMI filter, run `gpupdate /force` (or wait for the refresh), recollect, and only then look at what is left.
3. **High-risk deviations.** SMBv1, LM and NTLMv1, LLMNR, RDP without NLA, LAPS, Defender real-time protection and ASR, logon and lockout auditing, PowerShell script block logging, the Print Spooler on DCs, TLS 1.0 and 1.1, firewall profiles. Each has an owner and a date of days, not weeks.
4. **New drift.** Something changed since last month: a change that should have gone through change management, a tool that rewrites settings, a server moved between OUs. Find the change, not just the value.
5. **Local changes.** A local value that differs from the GPO usually comes from an installer, a vendor script or someone fixing an incident at night. Ask before reverting: the application may depend on it, and the right answer may be an exception.

## Fix, exception or baseline change

| The situation | Decision | Who approves |
|---|---|---|
| The setting broke nothing, it was changed by mistake or by a tool | **Fix**: revert to the baseline through a change, find and stop the source | Server owner, standard change |
| An application really needs a weaker value for a time | **Exception**: approved value, reason, compensating control, approver, ticket and an expiry of 6 months at most | Security (risk owner) |
| The baseline is wrong for a whole role or environment | **Baseline change**: a new value or a new `AppliesTo`, piloted first | Security and the Windows team, normal change |
| The deviation is in test only | Usually **fix**: test should mirror production, or the problems appear on the day of the release | Test environment owner |

The review proposes one of the three for every expired or incomplete exception and for every GPO that overrides the baseline; the meeting decides and writes the outcome in the pack.

## Changing the baseline without breaking applications

- **Audit mode first** where the setting has one: ASR rules in audit (`2`) and the events 1121 (block) and 1122 (audit) in the Defender Operational log; NTLM auditing ("Network security: Restrict NTLM: Audit incoming NTLM traffic") and the NTLM Operational log before refusing LM and NTLM; SMB signing and the SMB1 access audit (`Set-SmbServerConfiguration -AuditSmb1Access $true`, done by the owner, not by this tool) before removing SMBv1; the Schannel events before disabling TLS 1.0 and 1.1.
- **Pilot ring**: a GPO linked to a pilot OU or filtered to a pilot group with a few servers of each role, for two to four weeks. Then the rest, by waves, with a rollback plan (unlink the pilot GPO).
- **Close the pilot**: a pilot GPO left behind wins over the baseline for months. The review shows it as "set by another GPO"; give every pilot an end date.
- **Tell the owners**: the application owners get the list of settings that will change on their servers and the date, and the service desk knows what to look for.
- **Recollect after each wave** and compare: the drift report should show the expected changes and nothing else.

## Exception rules

- Every exception has a server, a setting, the approved value, a reason, a compensating control, an approver (the risk owner, not the requester), a ticket and an expiry date.
- An exception without approver, ticket or expiry does not count: the deviation stays a deviation (`EXC-INCOMPLETE`).
- Expiring in 30 days: the owner confirms the remediation date or asks for a renewal with a reason (`EXC-EXPIRING`).
- Expired: the deviation counts again from the day after, and the decision is fix or renew (`EXC-EXPIRED`).
- An exception on a server that now meets the baseline is closed (`not needed` in `exceptions-review.csv`).
- Exceptions on high-risk settings are reviewed at every monthly meeting, not only at expiry.

## Evidence for ISO 27001 and NIS2 audits

Keep, for each month, the inputs (`baseline.csv`, `servers.csv`, `settings.csv`, `exceptions.csv`, `gpo-results.csv`) and the outputs in a controlled location with restricted access. Together they show:

| What the auditor asks | Evidence |
|---|---|
| A defined secure configuration (ISO 27001 A.8.9, configuration management) | `baseline.csv` with the reference of each setting, and the approval of its last change |
| That it is applied and measured | `server-compliance.csv` and `deviations.csv` for the month; the compliance trend |
| That changes are detected | `drift.csv` against the previous month |
| That deviations are treated | `actions.csv` with owner, date and done; the decisions and outcomes in `review-pack.md` |
| That exceptions are controlled (risk acceptance) | `exceptions-review.csv` with approver, ticket and expiry |
| Logging and malware protection (A.8.15, A.8.7) | The audit policy, PowerShell logging and Defender areas of the report |
| NIS2 cyber hygiene and risk management measures | The monthly cycle itself: the pack, the actions and the trend over several months |

State the gaps instead of hiding them: servers not reporting, servers outside the collection, settings the collector cannot read. An auditor trusts a report that shows its limits.
