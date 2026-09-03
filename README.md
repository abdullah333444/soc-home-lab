# SOC Home Lab — Detection Engineering with Wazuh & Sysmon

> A hands-on home lab built to practice threat detection: simulating adversary techniques
> on a monitored Windows endpoint and validating whether they are detected by the SIEM.

---

## Overview

**Goal:** Build a working detection pipeline, execute real adversary techniques against it,
and measure detection coverage — then close the gaps with custom rules.

**Skills demonstrated:** log collection and centralization, endpoint telemetry with Sysmon,
adversary emulation, detection engineering, MITRE ATT&CK mapping, alert triage.

---

## Lab Architecture

| Component | Role | Specs |
|---|---|---|
| Ubuntu Server 24.04 | Wazuh manager, indexer, dashboard | 8 GB RAM / 4 vCPU / 60 GB |
| Windows 11 Enterprise | Monitored endpoint ("victim") | 4 GB RAM / 2 vCPU / 60 GB |
| Sysmon + sysmon-modular | Endpoint telemetry source | — |
| Atomic Red Team | Adversary emulation framework | — |

Network: VirtualBox Bridged Adapter — both hosts on the same LAN segment.

`[INSERT: a simple network diagram here]`

---

## Build Summary

1. **Wazuh server deployment** — single-node install via the official assistant script.
2. **Agent enrollment** — Windows endpoint registered to the manager and confirmed `Active`.
3. **Telemetry tuning** — Sysmon deployed with a curated configuration to capture process
   creation, network connections, and registry modifications.
4. **Log flow validation** — confirmed events arriving in the dashboard in near real time.

`[INSERT: screenshot of the Wazuh dashboard showing the agent as Active]`

---

## Detection Testing

### Coverage Summary

| # | Technique | ATT&CK ID | Detected | Rule Source |
|---|---|---|---|---|
| 1 | `[technique name]` | `T####` | Yes | Built-in |
| 2 | `[technique name]` | `T####` | No → Yes | Custom rule |
| 3 | `[technique name]` | `T####` | Yes | Built-in |

**Result:** `[X]` of `[Y]` techniques detected out of the box. `[Z]` gaps identified and
closed with custom detection rules.

---

## Detection Entries

### `[N]. [Technique Name]` — `T####`

**Tactic:** `[e.g. Defense Evasion]`

**Why an attacker does this**
`[One or two sentences on what this technique achieves for the adversary.]`

**Execution**

```powershell
[the exact command or Atomic test number used]
```

**Telemetry generated**
`[Which log source captured it? Sysmon Event ID? Windows Security Event ID? Key fields?]`

**Detection outcome**
`[Did an alert fire? Which rule ID? What severity? If nothing fired — say so plainly.]`

`[INSERT: screenshot of the alert, or of the raw event if no alert fired]`

**Analyst notes**
`[What would you check next if you saw this in production? What legitimate activity could
trigger the same rule — i.e. what causes false positives? How would you tune it?]`

**Custom rule** *(only if you wrote one)*

```xml
[your rule XML here]
```

---

## Gaps & Limitations

- `[Techniques that produced no telemetry at all, and why]`
- `[Detections that would be too noisy for a real environment]`
- `[What this lab does not simulate — lateral movement, domain environment, etc.]`

---

## Key Takeaways

`[3–5 bullets. Something specific you learned, not "I learned Wazuh".]`

---

## Next Steps

`[Active Directory, Sigma rule conversion, automated response, log volume tuning, etc.]`

---

## References

- Wazuh documentation
- MITRE ATT&CK
- Atomic Red Team
- sysmon-modular by Olaf Hartong
