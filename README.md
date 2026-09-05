# SOC Home Lab — Detection Engineering with Wazuh & Sysmon

> A hands-on home lab built to practice threat detection: executing real adversary
> techniques against a monitored Windows endpoint, measuring whether the SIEM detects them,
> and closing the gaps with custom rules and log-source tuning.

---

## Overview

**Goal:** Build a working detection pipeline end-to-end, run adversary techniques against it,
measure detection coverage, and close the gaps — through custom Wazuh rules and by fixing
the log sources themselves.

**Key finding:** Default telemetry is not enough. Detecting these five techniques required
layering four log sources (Sysmon, Windows Security, PowerShell, and Windows Defender), three
log-source fixes, and four custom detection rules. Only one technique was caught out of the
box.

**Skills demonstrated:** log collection and centralization, endpoint telemetry with Sysmon,
adversary emulation, detection engineering, MITRE ATT&CK mapping, alert triage, and — most
importantly — root-cause investigation of *why* a technique was or wasn't detected.

---

## Lab Architecture

| Component | Role | Specs |
|---|---|---|
| Ubuntu Server 24.04 | Wazuh manager, indexer, dashboard | 8 GB RAM / 4 vCPU / 60 GB |
| Windows 11 Enterprise | Monitored endpoint ("victim") | 4 GB RAM / 2 vCPU / 60 GB |
| Sysmon + sysmon-modular | Endpoint telemetry source | — |

Network: VirtualBox Bridged Adapter — both hosts on the same LAN segment, static IP on the
manager so agents never lose it.

Log sources feeding the manager: Sysmon/Operational, Security, PowerShell/Operational,
Windows Defender/Operational.

`[INSERT: a simple network diagram — endpoint → manager → dashboard]`

---

## Build Summary

1. **Wazuh server** — single-node install (indexer + manager + dashboard) on Ubuntu, managed
   over SSH. Set a static IP after discovering DHCP reassigned the manager's address on
   reboot, which would silently break agent reporting.
2. **Windows endpoint** — Windows 11 Enterprise VM, Wazuh agent enrolled and confirmed
   Active.
3. **Telemetry** — Sysmon deployed with the sysmon-modular configuration; additional log
   channels added as investigation revealed blind spots.
4. **Validation** — confirmed events flowing to the dashboard in near real time.

`[INSERT: screenshot — wazuh-agent-active.png]`

---

## Detection Testing

### Coverage Summary

| # | Technique | ATT&CK ID | Detected | Rule / Fix |
|---|-----------|-----------|----------|------------|
| 1 | Create Local Admin Account | T1136.001 / T1098 | No → Yes | Custom rule 100100 |
| 2 | Clear Event Logs | T1070.001 | Yes (built-in) | Rule 63103 |
| 3 | Scheduled Task Persistence | T1053.005 | No → Yes | Audit fix + custom rule 100102 |
| 4 | Defender Tampering | T1562.001 | No → Yes | Defender channel + custom rule 100104 |
| 5 | LSASS Memory Access | T1003.001 | Blocked by platform | Documented gap + Sysmon rule |

**Result:** 5 techniques tested. Only 1 was detected out of the box. 3 required a log-source
fix and/or a custom rule; 1 was blocked outright by Windows 11's LSA Protection, leaving a
documented platform-level detection blind spot. Four custom rules/config changes written in
total.

---

## Detection Entries

### 1. Create Local Admin Account — T1136.001 / T1098

**Tactic:** Persistence / Privilege Escalation

**Why an attacker does this:** creates a controlled account with admin rights to guarantee
return access even if the original entry point is closed.

**Execution:**
```
net user backdoor P@ssw0rd123! /add
net localgroup administrators backdoor /add
```

**Detection outcome — split and inconsistent:**
- Security channel: rules 60109 / 60110, level 8, mapped correctly to T1098.
- Sysmon: rules 92031 / 92033 / 92039, level 3, mislabelled as Discovery.

**Gap:** Sysmon captured the full command line but the built-in rules classify any `net.exe`
run as Discovery without inspecting arguments — so `net user X /add` and plain enumeration
look identical. The forensically valuable event (with the command line) sat at level 3 and
would be invisible in an environment triaging at level 5+.

**Custom rule 100100 (level 12):** matches `net\d?` with `/add` in the command line, mapped
to T1136.001, surfacing the command in the alert. Notably caught `net1.exe` — Windows aliases
`net` to `net1` internally, which a naive `net.exe` rule would miss and an attacker could
abuse to evade.

`[INSERT: t1136-custom-rule-detection.png]`

---

### 2. Clear Event Logs — T1070.001

**Tactic:** Defense Evasion

**Why an attacker does this:** wipes local logs to destroy evidence of the intrusion.

**Execution:**
```
wevtutil cl Security
```

**Detection outcome — two findings:**
1. **Logs survive centralization.** After clearing the local Security log, the earlier
   backdoor account-creation events were gone from the endpoint but still fully visible in
   Wazuh — they had been forwarded to the manager when they occurred. An attacker can wipe
   the host but cannot reach what already left it. This is the core value of centralized
   logging.
2. **The clear itself is detected.** Rule 63103 "The audit log was cleared", level 5
   (event 1102). Windows logs the clear action as the final entry before wiping, so it isn't
   silent.

**Analyst note:** Level 5 is low for an action that is almost never legitimate — a candidate
for a custom rule raising severity. Not a detection gap; a prioritization gap.

`[INSERT: t1070-logs-survive-after-clear.png]`

---

### 3. Scheduled Task Persistence — T1053.005

**Tactic:** Persistence

**Why an attacker does this:** registers a task that re-runs their payload automatically,
often named to mimic a legitimate system task.

**Execution:**
```
schtasks /create /tn "WindowsUpdate" /tr "calc.exe" /sc onlogon /ru System
```

**Detection outcome:** no alert initially. Root-cause investigation (rather than assuming a
rule gap) showed **event 4698 was never logged** — the audit subcategory "Other Object Access
Events" is disabled by default in Windows. No SIEM can detect what the source never records.

**Fix:** enabled auditing via `auditpol`, recreated the task, confirmed event 4698 appears
and reaches Wazuh (rule 60228, level 4).

**Custom rule 100102 (level 12):** rather than raising severity for *all* tasks (noisy),
matches the combination of two suspicious indicators in the task XML — runs as SYSTEM
(`S-1-5-18`) **and** triggers at logon. Legitimate user tasks rarely combine both, keeping
false positives low.

`[INSERT: t1053-custom-rule-detection.png]`

---

### 4. Impair Defenses: Defender Tampering — T1562.001

**Tactic:** Defense Evasion

**Why an attacker does this:** disables or blinds antivirus so their tools run undetected.

**Execution:**
```
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\Users\Public"
```

**Detection outcome — a multi-layer investigation:**
- `DisableRealtimeMonitoring` had **no effect** — Tamper Protection blocked it. A common
  evasion technique fails against a default-hardened host.
- `Add-MpPreference` succeeded but was nearly invisible: Sysmon missed it (internal cmdlet,
  no new process), and PowerShell Script Block Logging produced no event for the cmdlet even
  when wrapped in an explicit script block — verified absent in the local Windows log too.

**Resolution:** ingested the **Windows Defender/Operational** channel. Event 5007 (rule
62154) records the configuration change directly, regardless of how it was invoked —
capturing exactly what the other sources missed. **Custom rule 100104 (level 12)** maps it to
T1562.001 and surfaces the excluded path.

**Lesson:** no single telemetry source is complete. This technique was invisible to
process-creation and script-block logging but fully visible in Defender's own log.

---

### 5. LSASS Memory Access — T1003.001

**Tactic:** Credential Access

**Why an attacker does this:** dumps lsass memory to steal cached credentials for lateral
movement.

**Execution:**
```
rundll32.exe comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full
```

**Detection outcome — blocked by the platform, with a resulting blind spot:**
- The dump itself failed on every attempt with "Access is denied" — Windows 11 LSA Protection
  blocks reading lsass memory even from an elevated SYSTEM context.
- **Traced through every layer:** sysmon-modular filters Event 10 (ProcessAccess) for lsass
  by default; a targeted Sysmon rule was added and confirmed to log Event 10 — but only for
  legitimate system access (svchost/sysmain). The malicious attempt produced **no Event 10 at
  all**, because LSA Protection denies access *before* the ProcessAccess callback fires. No
  Event 1 with the command line, no Script Block event, and Wazuh's built-in lsass rule
  (92900) only matches GrantedAccess `0x1010`/`0x40`, which this path doesn't use.

**Conclusion — a platform-level blind spot.** On a hardened Windows 11 host this technique
fails so early it leaves almost no telemetry. The only residual signal is the "Access is
denied" error, visible only with command-line monitoring.

**Lesson:** strong prevention can *reduce* detective visibility — when the OS blocks an action
pre-emptively, the attempt may never generate the events a SIEM relies on. The same technique
would succeed *and* evade Wazuh's default rule on an older or unprotected host, which is
exactly where this gap becomes dangerous. Added a Sysmon ProcessAccess rule for lsass anyway,
since it broadens coverage for other dumping methods.

---

## Gaps & Limitations

- **LSASS access (T1003.001):** failed attempts leave almost no telemetry on a hardened host;
  the built-in Wazuh rule 92900 is narrow (specific GrantedAccess values) and would miss
  several real dumping paths on an unprotected host.
- **Defender tampering via cmdlet:** not visible through process or script-block telemetry;
  requires the Defender operational log specifically.
- **Default Windows auditing has blind spots** — scheduled-task creation isn't logged until
  the relevant audit subcategory is manually enabled.
- **Scope:** single endpoint, no Active Directory, no lateral movement, no domain
  environment. Detection tuned for this host, not validated at scale.

---

## Key Takeaways

- **Detection starts at the log source, not the rule.** Two of five techniques failed to
  alert because the event was never logged — not because a rule was missing. Verify telemetry
  exists before writing detections.
- **No single source is complete.** Full coverage required four channels; each covered the
  others' blind spots.
- **Centralization defeats local log deletion** — evidence forwarded to the manager survives
  a `wevtutil cl`.
- **Prevention and detection can trade off.** LSA Protection blocked the credential dump so
  early that it also erased the telemetry needed to detect the attempt.
- **Good rules inspect context, not just presence.** The strongest custom rules matched
  argument/field combinations (net + /add; SYSTEM + logon) rather than a single indicator,
  keeping false positives low.

---

## Custom Rules & Config

See [`rules/local_rules.xml`](rules/local_rules.xml) for the four custom Wazuh rules
(100100, 100102, 100104) and [`configs/`](configs/) for the Sysmon ProcessAccess addition and
agent log-channel configuration.

---

## Next Steps

- Add an Active Directory domain to test lateral movement and domain-level persistence.
- Convert custom rules to Sigma format for portability across SIEMs.
- Tune down noise (the DWM Event 8 process-injection false positives are a good first target).
- Add automated response actions for high-severity detections.

---

## References

- Wazuh documentation
- MITRE ATT&CK
- sysmon-modular by Olaf Hartong
