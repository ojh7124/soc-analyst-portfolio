# Phase 1: Initial Access

## 1. Hypothesis
* **What I was looking for:** Evidence of a brute force attack targeting a single local account on the windows endpoint.
* **Analyst Hypothesis:** If a brute-force attack occurred, I expect to see multiple rapid failed logon events (`4625`) originating from a single source IP, followed by a successful logon (`4624`) once the correct password was discovered.

---

## 2. SPL Query
To test this hypothesis, I executed the following search in Splunk to isolate logon activity for `HelpDesk_User`:

` ` `spl
index=* (EventCode=4625 OR EventCode=4624) "HelpDesk_User" | sort _time | table _time, Source_Network_Address, EventCode, Account_Name, Account_Domain, Logon_Type, Logon_Process, Sub_Status
` ` `

<img width="1920" height="1026" alt="Screenshot (1)" src="https://github.com/user-attachments/assets/575305fe-d4b2-4e2e-9475-7c504db434ea" />

---

## 3. Key Artifacts & IOCs

* **Target Account:** `HelpDesk_User`
* **Source IP:** `192.168.71.1`
* **EventCode Pattern:** 3x Event Code `4625` (Failed Logon) within a 4-second window, followed immediately at `17:55:35` by Event Code `4624` (Successful Logon).
* **Logon Type:** `3` (Network Logon). This confirms the authentication occurred remotely over SMB (Port 445).

---

## 4. Conclusion
* **Verdict:** True Positive
* **Severity:** High
* **Framework Mapping:** MITRE ATT&CK T1110
* **Summary:** Validated successful brute force attack against local account `HelpDesk_User` originating from IP `192.168.71.1` via SMB (Port 445).

---
  
## 5. Containment
* **Isolate Host:** Isolate `DESKTOP-TBSUDKQ` from the local network.
* **Account Revocation:** Disable `HelpDesk_User` in Local Users and Groups.
<img width="1006" height="100" alt="Screenshot (4)" src="https://github.com/user-attachments/assets/06a7f5d4-03da-46f7-8028-35070b864b0e" />
* **Session Termination:** Terminate all active SMB connections initiated by `HelpDesk_User`.
<img width="1006" height="200" alt="Screenshot (3)" src="https://github.com/user-attachments/assets/1779e8a3-24cf-4226-a36a-9dfe798b454c" />
* **Reset Credentials:** Force an immediate password reset for `HelpDesk_User`.  
