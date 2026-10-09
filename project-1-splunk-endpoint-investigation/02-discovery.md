# Phase 2: Discovery

## 1. Hypothesis
* **What I was looking for:** Evidence of post-exploitation reconnaissance activity executed shortly after the initial breach via brute force at `(05/10/2026 17:55:35)`.
* **Analyst Hypothesis:** I expect to see the command-line execution of built-in Windows enumeration tools `(e.g. whoami, net user, ipconfig)` spawned via `cmd.exe` to inspect privilege levels and system configuration.

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1)  Creator_Process_Name="C:\\Windows\\System32\\cmd.exe" | sort _time  | table  _time, New_Process_Name, Process_Command_Line, EventCode, Account_Name, Account_Domain
` ` `

<img width="1920" height="650" alt="Screenshot (6)" src="https://github.com/user-attachments/assets/c828ac1b-fb1b-4db9-8a01-189a51e57609" />

---

## 3. Key Artifacts & IOCs

* **Executed Process:** `C:\Windows\System32\whoami.exe`
* **Command Line:** `whoami /all` 
* **Parent Process:** `C:\Windows\System32\cmd.exe`
* **Execution Timestamp:** `2026-10-05 17:59:49` (~4 minutes post-compromise)
* **Account Context:** `DESKTOP-TBSUDKQ$` (Note: Windows Event Code 4688 records the computer account as the Subject when commands are executed within the compromised HelpDesk_User session context).

---

## 4. Conclusion
* **Verdict:** True Positive 
* **Severity:** Medium 
* **Framework Mapping:** MITRE ATT&CK T1033 (System Owner/User Discovery)
* **Summary:** Confirmed adversary reconnaissance activity. Following successful authentication, the attacker spawned `whoami /all` via `cmd.exe` at `17:59:49` to enumerate account privlidges, group memberships, and SIDs on the endpoint.
