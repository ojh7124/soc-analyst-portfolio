# Phase 3: Persistence 

## 1. Hypothesis
* **What I was looking for:** Evidence of persistence mechanisms established by the adversary following successful compromise and reconnaissance.
* **Analyst Hypothesis:** If the attacker intends to maintain long term-access to the windows endpoint, I expect to see the creation of scheduled tasks (e.g. using `schtasks.exe`) or modification of registry run keys to ensure recurring execution of payloads.

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1)  Creator_Process_Name="C:\\Windows\\System32\\cmd.exe" | sort _time  | table  _time, New_Process_Name, Process_Command_Line, EventCode, Account_Name, Account_Domain
` ` `

<img width="1920" height="588" alt="Screenshot (8)" src="https://github.com/user-attachments/assets/d744c654-e417-4a9b-9562-e09045a84402" />

---

## 3. Key Artifacts & IOCs

* **Executed Process:** `C:\Windows\System32\schtasks.exe`
* **Command Line:** `schtasks  /create /tn PersistenceTask /tr calc.exe /sc daily /st 09:00 /ru SYSTEM /f`
* **Task Name:** `PersistenceTask`
* **Payload Executed:** `calc.exe` (acting as a proof-of-concept payload / placeholder binary)
* **Schedule/Trigger:** `daily` at `09:00 AM`
* **Execution Context/Privileges:** `SYSTEM`
* **Execution Timestamp:** `2026-10-05 18:07:54` (~12 minutes post-compromise)

---

## 4. Conclusion
* **Verdict:** True Positive 
* **Severity:** High 
* **Framework Mapping:** MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task)
* **Summary:** Confirmed adversary persistence mechanism. The attacker leveraged `schtasks.exe` via `cmd.exe` to create a recurring scheduled task named `PersistenceTask`, forcing the system to execute `calc.exe` daily at 09:00 AM under elevated `SYSTEM` privileges to maintain backdoored access.

---

## 5. Containment

* **Scheduled Task Disablement & Deletion:** Disabled and permanently removed the unauthorized scheduled task (`PersistenceTask`) created by the adversary to prevent recurring execution under elevated `SYSTEM` privileges.

<img width="1006" height="120" alt="Screenshot (12)" src="https://github.com/user-attachments/assets/c9977079-d952-4371-9fe8-49983626e3dc" />

* * **Task Verification:** Executed a query against the Windows Task Scheduler to confirm complete removal of the persistence mechanism.

<img width="1006" height="102" alt="Screenshot (13)" src="https://github.com/user-attachments/assets/4239166d-3f8a-4398-9c9e-121c2bbc9bda" />

* **Payload Neutralisation:** Removed associated executable artifacts from disk to prevent re-infection.

<img width="1006" height="96" alt="Screenshot (14)" src="https://github.com/user-attachments/assets/876552a4-6c44-4120-9a3f-2214c8c45bc0" />


