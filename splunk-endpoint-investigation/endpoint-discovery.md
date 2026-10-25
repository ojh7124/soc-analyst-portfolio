# Investigation: Endpoint Discovery

## Executive Summary
This investigation analyzes post-exploitation reconnaissance activity originating from a compromised endpoint (`DESKTOP-TBSUDKQ`). Telemetry captures the execution of native Windows enumeration utilities (`whoami.exe`) spawned via the command processor (`cmd.exe`) to inspect security context, privileges, and system configurations.

---

## 1. Hypothesis
* I expect to see the command-line execution of built-in Windows enumeration tools (e.g. `whoami`, `net user`, `ipconfig`) spawned via `cmd.exe` to inspect privilege levels and system configuration.
  
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
* **Execution Timestamp:** `2026-10-05 17:59:49`
* **Account Context:** `DESKTOP-TBSUDKQ$` (Note: Windows Event Code 4688 records the computer account as the Subject when commands are executed within the compromised HelpDesk_User session context).

---

## 4. Conclusion
* **Verdict:** True Positive 
* **Severity:** Medium 
* **Framework Mapping:** MITRE ATT&CK T1033 (System Owner/User Discovery)
* **Summary:** Confirmed adversary reconnaissance activity. The attacker spawned `whoami /all` via `cmd.exe` at `17:59:49` to enumerate account privileges, group memberships, and SIDs on the endpoint.

---

## 5. Containment 
* **Terminate Active Reconnaissance Shells:** Kill any active `cmd.exe` processes (such as those running `whoami /all`) on the endpoint.

<img width="1006" height="124" alt="Screenshot (9)" src="https://github.com/user-attachments/assets/3746ff5e-a694-4a48-b1c6-a843be4880ea" />

* **Isolate Host from Network:** Block all incoming and outgoing network traffic at the local OS firewall level to stop lateral movement.

<img width="1006" height="522" alt="Screenshot (10)" src="https://github.com/user-attachments/assets/720db11d-38a8-4052-85fe-bb3cd21f794a" />
<img width="1006" height="524" alt="Screenshot (11)" src="https://github.com/user-attachments/assets/93a40905-6e18-43e1-9397-a918be75165d" />

