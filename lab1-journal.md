# Lab Journal

## 2026-09-03 — Wazuh server build

**Did:** Installed Ubuntu Server 24.04 in VirtualBox (8 GB RAM, 4 vCPU, 60 GB disk).
Enabled OpenSSH during setup and now manage the server over SSH from my host machine.

**Decision:** Used a Bridged network adapter instead of NAT so the Windows endpoint and my
host can both reach the manager directly.

**Server IP:** 192.168.68.58

**Notes — telemetry vs detection:**
Sysmon only writes detailed logs on the endpoint; it doesn't decide what's suspicious.
Wazuh collects those logs centrally and runs detection rules against them.
Key point: you can't detect what you never logged.

**Next:** Run the Wazuh installation assistant, then build the Windows endpoint.












## 2026-09-04 — Static IP configuration

**Problem:** Wazuh dashboard unreachable after restarting the server VM.

**Cause:** The manager's IP had shifted from .58 to .60 — the address came from DHCP, so
the router issued a different lease after the VM was powered off.

**Impact:** Any agent enrolled against the old address would have silently stopped
reporting. In a real deployment this is a monitoring blind spot, not just an inconvenience.

**Fix:** Set a static address in /etc/netplan/50-cloud-init.yaml (dhcp4: no, address
192.168.68.58/22, gateway 192.168.68.1) and applied with netplan apply.

**Lesson:** Infrastructure that other systems depend on needs a fixed address.

**Observation:** 298 alerts generated in 24h from the manager itself, with no agents
enrolled — mostly SSH logins and sudo usage. First look at what alert noise means in
practice.

**Next:** Build the Windows 11 endpoint and enroll it as the first agent.






**Problem:** Dashboard returned HTTP 500 after rotating the admin password.

**Cause:** The password tool rotates credentials for all internal users, including
`kibanaserver` — the account the dashboard itself authenticates with. Rotating one
credential silently broke a service dependency I wasn't aware of.

**Fix:** Re-ran the tool with -a -A to regenerate all internal credentials and update
the dependent config files, then restarted indexer, manager and dashboard.

**Lesson:** Credential rotation in a multi-component stack has blast radius beyond the
account you intended to change. Map service dependencies before rotating.







## 2026-09-04 — Sysmon deployed

**Did:** Installed Sysmon with the sysmon-modular configuration. Verified logging via
Get-WinEvent against Microsoft-Windows-Sysmon/Operational.

**First events observed:** Five consecutive Event ID 8 (CreateRemoteThread), tagged
T1055 Process Injection. Source: dwm.exe from C:\Windows\System32, targeting a SYSTEM
process. All legitimate — dwm.exe injects threads as part of normal window management.

**Triage reasoning:** Legitimate binary, correct path, expected behaviour for that process,
timing consistent with boot. Verdict: benign.

**What would change the verdict:** the same event with a source like winword.exe or
powershell.exe, a binary running outside System32, or a target such as lsass.exe.

**Takeaway:** Sysmon's severity mapping describes the technique, not the intent. The first
five events after deployment were all high-severity and all benign — a compact illustration
of why untuned telemetry buries real detections.


## 2026-09-05 — First attack test: T1136 Create Account

Created a local account named `backdoor` and added it to the administrators group.

Both log sources detected it, but inconsistently:
- Security channel: rules 60109 / 60110, level 8, mapped to T1098 Account Manipulation
- Sysmon: rules 92031 / 92033 / 92039, level 3, mapped to Discovery

The Sysmon classification is wrong — this was account creation and privilege escalation,
not discovery. Built-in rules match on net.exe execution without inspecting the arguments,
so `net user X /add` and plain `net user` enumeration look identical to them.

The problem: the full command line only exists in the Sysmon event, which is the
low-severity one. In an environment triaging at level 5+, the most useful forensic
evidence would never be seen.

See screenshots/t1136-sysmon-misclassified.png and
screenshots/t1136-security-channel-alerts.png

Next: write a custom rule matching net.exe with /add, mapped to T1136.001, level 12.



**Custom rule 100100 works.** Same attack now fires at level 12, correctly mapped to
T1136.001, with the command line surfaced directly in the alert description.

Notable: Windows executed `net1 user testadmin ... /add`, not `net`. The regex used
`net\d?` which caught it. A rule matching `net.exe` literally would have missed this
entirely — and an attacker aware of the net/net1 aliasing could use it to evade
naive detections.

### Clear Event Logs — T1070.001

**Executed:** wevtutil cl Security

**Finding 1 — logs survive centralization:** After clearing the local Security log, the
backdoor account-creation events (02:31:25) were gone from the endpoint but still fully
visible in Wazuh. They were forwarded to the manager when they occurred; clearing the host
cannot reach them.

**Finding 2 — the clear itself is detected:** Rule 63103 "The audit log was cleared",
level 5, event 1102. Windows logs the clear action as the final entry before wiping, so
it is not silent.

**Priority gap:** Level 5 is low for an action that is rarely legitimate. Candidate for a
custom rule raising severity to 12.

See screenshots/t1070-logs-survive-after-clear.png and
screenshots/t1070-clear-detected.png

### Scheduled Task Persistence — T1053.005

**Executed:** schtasks /create /tn "WindowsUpdate" /tr "calc.exe" /sc onlogon /ru System

**Finding 1 — logging gap, not detection gap:** No alert fired initially. Investigation
showed event 4698 was never logged — the audit subcategory "Other Object Access Events"
is disabled by default in Windows. No SIEM can detect what the source never records.

**Fix:** Enabled auditing via auditpol, recreated the task, confirmed event 4698 appears
and reaches Wazuh (rule 60228, level 4).

**Finding 2 — priority gap:** Rule 60228 fires at level 4 and alerts on ANY scheduled
task, including legitimate ones — noisy in a real environment.

**Custom rule 100102 (level 12):** Instead of raising severity for all tasks, matches the
combination of two suspicious indicators in the task XML — runs as SYSTEM (S-1-5-18) AND
triggers at logon. Legitimate user tasks rarely combine both, so false positives stay low.

**Lesson:** Detection engineering starts at the log source. Verify telemetry exists before
writing rules; default Windows auditing has blind spots for persistence techniques.

See screenshots/t1053-detected-after-audit-fix.png and
screenshots/t1053-custom-rule-detection.png

**Note:** Set-MpPreference -DisableRealtimeMonitoring did NOT disable protection —
Get-MpPreference still showed False. Windows Tamper Protection blocked the change. This is
a meaningful defensive control: a common evasion technique (T1562.001) fails against a
default-hardened modern Windows host. An attacker would need to disable Tamper Protection
first, which itself requires interactive access to the Defender UI or specific registry
manipulation.
