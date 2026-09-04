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






**Wazuh 4.14 installed successfully** (indexer + manager + dashboard, single node).
Dashboard reachable at https://192.168.68.58 — self-signed cert, browser warning expected.





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
