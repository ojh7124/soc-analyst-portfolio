# Summary 

* This directory contains individual detection rules using Splunk.
* Each markdown file acts as an independent case study demonstrating detection engineering, rule deployment, alert configuration, and validation. 

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
