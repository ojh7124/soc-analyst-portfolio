# ServiceNow Security Incident Report: IR-2026-1005-01

## 1. Executive Summary

* **Ticket ID:** `SIR0010005` / `IR-2026-1005-01`
* **Target Endpoint:** `DESKTOP-TBSUDKQ` (`192.168.71.128`)
* **Compromised Account:** `HelpDesk_User`
* **Attacker IP:** `192.168.71.x` (Kali Linux)
* **Status:** `Closed / Resolved`
* **Overview:** 5-stage attack chain investigation covering initial brute-force through attempted credential access. Stage 5 (`reg save HKLM\SAM`) was **blocked** by host controls (`TokenElevationTypeDefault (1)` / `0x5 Access is Denied`).

---

## 2. Investigation & ServiceNow Analysis

<img width="1920" height="970" alt="Screenshot (32)" src="https://github.com/user-attachments/assets/6ff0efb8-89a2-45c3-9302-76ac7d113842" />

### Lifecycle Summary
* **Phase 1 (Initial Access):** SMB Brute-Force against `HelpDesk_User`
* **Phase 2 (Discovery):** `whoami /all` execution
* **Phase 3 (Persistence):** Scheduled task creation (`PersistenceTask`)
* **Phase 4 (Defense Evasion):** Security event log cleared (`wevtutil cl Security`)
* **Phase 5 (Credential Access):** WMI execution of `reg save HKLM\SAM C:\Users\Public\sam.hive` (**Failed / Blocked**)

---

## 3. Containment Actions (NIST SP 800-61)

*(Screenshots and details coming tomorrow)*


