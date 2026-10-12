# Detection Engineering: Splunk SPL & SIGMA Rules

## Overview

Following the forensic investigation of host `DESKTOP-TBSUDKQ`, custom detection rules were engineered to identify future occurrences of the techniques observed across all five attack phases. Each detection incorporates both vendor-agnostic **SIGMA YAML** rules for cross-platform rule management and **Splunk SPL** queries for direct operational deployment.

---

## Detection Engineering Summary

| Phase | Attack Technique | MITRE ATT&CK ID | Primary Log Source | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **01. Initial Access** | Brute Force (SMB) | T1110.001 | Security Event Code 4625 / 4624 | High |
| **02. Discovery** | Account & Privilege Discovery | T1087.001 / T1033 | Security Event Code 4688 / Sysmon 1 | Low / Medium |
| **03. Persistence** | Scheduled Task Creation | T1053.005 | Security Event Code 4698 / 4688 | Medium |
| **04. Defense Evasion** | Clear Windows Event Logs | T1070.001 | Security Event Code 1102 / 4688 | High |
| **05. Credential Access** | SAM Registry Hive Dumping | T1003.002 | Security Event Code 4688 / Sysmon 1 | Critical |

---

## Phase 01: Brute Force (SMB)

### SIGMA YAML Rule
```yaml
title: Potential SMB Brute Force Followed by Successful Logon
id: 1d2e3f4a-5b6c-7d8e-9f0a-1b2c3d4e5f6a
status: experimental
description: Detects a high volume of failed SMB logon attempts (Event ID 4625) from a single IP address followed by a successful logon (Event ID 4624).
author: SOC Analyst Portfolio
date: 2026-10-12
logsource:
  product: windows
  service: security
detection:
  failed_selection:
    EventID: 4625
    LogonType: 3
  successful_selection:
    EventID: 4624
    LogonType: 3
  timeframe: 5m
  condition: failed_selection | count() > 5 then successful_selection
falsepositives:
  - Misconfigured service accounts or network shares using outdated credentials.
level: high
tags:
  - attack.initial_access
  - attack.t1110.001

### Splunk SPL Rule  
index=* (EventCode=4625 OR EventCode=4624) Logon_Type=3
| stats count(eval(EventCode=4625)) as Failed_Logons, 
        count(eval(EventCode=4624)) as Successful_Logons 
        by Account_Name, Source_Network_Address
| where Failed_Logons > 5 AND Successful_Logons > 0
