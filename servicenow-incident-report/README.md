# ServiceNow Security Incident Report: IR-2026-1005-01

## 1. Executive Summary

* **Ticket ID:** `SIR0010005` / `IR-2026-1005-01`
* **Target Endpoint:** `DESKTOP-TBSUDKQ` (`192.168.71.128`)
* **Compromised Account:** `HelpDesk_User`
* **Attacker IP:** `192.168.71.x` (Kali Linux)
* **Status:** `Closed / Resolved`
* **Overview:** 5-stage attack chain investigation covering initial brute-force through attempted credential access.

---

## 2. ServiceNow Analysis Report

<img width="1920" height="968" alt="Screenshot (33)" src="https://github.com/user-attachments/assets/2d62029e-26d3-4e93-95f4-948e24f03bf4" />

### Lifecycle Summary
* **Phase 1 (Initial Access):** SMB Brute-Force against `HelpDesk_User`
* **Phase 2 (Discovery):** `whoami /all` execution
* **Phase 3 (Persistence):** Scheduled task creation (`PersistenceTask`)
* **Phase 4 (Defense Evasion):** Security event log cleared (`wevtutil cl Security`)
* **Phase 5 (Credential Access):** WMI execution of `reg save HKLM\SAM C:\Users\Public\sam.hive` (**Failed / Blocked**)

---

## 3. ServiceNow Containment Report

<img width="1920" height="894" alt="Screenshot (34)" src="https://github.com/user-attachments/assets/e6333a4f-3c50-4f4b-9d47-af75b70d6f10" />



