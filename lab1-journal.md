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

**Observation:** 298 alerts generated in 24h from the manager itself, with no agents
enrolled — mostly SSH logins and sudo usage. First look at what alert noise means in
practice.

**Next:** Build the Windows 11 endpoint and enroll it as the first agent.
