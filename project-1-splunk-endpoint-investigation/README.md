# Incident Investigation Report: IR-2026-1005-01

| Metadata Field | Value |
| :--- | :--- |
| **Ticket Status** | Closed / Contained |
| **Severity Level** | High |
| **Target Endpoint** | `DESKTOP-TBSUDKQ` (192.168.71.128) |
| **Attacker Host** | Kali Linux (192.168.71.x) |
| **Assigned Analyst** | Oliver (SOC Analyst) |
| **SIEM Platform** | Splunk Enterprise |
| **Framework Mapping** | MITRE ATT&CK (T1110, T1059, T1033, T1053.005) |

---

## Lab Architecture & Environment

```text
               +-------------------------------------------------+
               |             Isolated Virtual Network            |
               |                                                 |
               |   +-----------------+     +-----------------+   |
               |   |   Kali Linux    |     |   Windows 11    |   |
               |   |  (Attacker VM)  |     |   (Target VM)   |   |
               |   | 192.168.71.x    |     | 192.168.71.128  |   |
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
