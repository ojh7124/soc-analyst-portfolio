# Summary / Context
* This project simulates a full end-to-end incident response investigation based on a compromised Windows endpoint (`DESKTOP-TBSUDKQ`).
* It tracks an adversary from `initial access` through local `discovery`, `persistence` establishment, `defence evasion`, and `credential access` using Splunk.
* Each phase includes detailed forensic `analysis` and verified `containment` steps that align with NIST SP-800-61 (Incident Handling Lifecycle).

---

## Incident Metadata: IR-2026-1005-01

| Metadata Field | Value |
| :--- | :--- |
| **Ticket Status** | Closed / Contained |
| **Severity Level** | High |
| **Target Endpoint** | `DESKTOP-TBSUDKQ` (192.168.71.128) |
| **Attacker Host** | Kali Linux (192.168.71.1) |
| **Assigned Analyst** | Oliver (SOC Analyst) |
| **SIEM Platform** | Splunk Enterprise |
| **Framework Mapping** | MITRE ATT&CK (T1110.001, T1059, T1033, T1053.005, T1070.001, T1003.002)|

---

## Lab Architecture & Environment

```text
               +-------------------------------------------------+
               |             Isolated Virtual Network            |
               |                                                 |
               |   +-----------------+     +-----------------+   |
               |   |   Kali Linux    |     |   Windows 11    |   |
               |   |  (Attacker VM)  |     |   (Target VM)   |   |
               |   | 192.168.71.1    |     | 192.168.71.128  |   |
               |   +--------+--------+     +--------+--------+   |
               |            |                       |            |
               |            |                       |            |
               |            +--- Attack Telemetry --+            |
               |                                    |            |
               |                            (Universal Forwarder)|
               |                                    v            |
               |                           +-----------------+   |
               |                           | Splunk SIEM Host|   |
               |                           | (Ingestion)     |   |
               |                           +-----------------+   |
               +-------------------------------------------------+
