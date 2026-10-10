# Phase 3: Persistence 

## 1. Hypothesis
* **What I was looking for:** Evidence of persistence mechanisms established by the adversary following successful compromise and reconnaissance.
* **Analyst Hypothesis:** If the attacker intends to maintain long term-access to the windows endpoint, I expect to see the creation of scheduled tasks `(e.g. using schtasks.exe)` or modification of registry run keys to ensure recurring execution of payloads.

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1)  Creator_Process_Name="C:\\Windows\\System32\\cmd.exe" | sort _time  | table  _time, New_Process_Name, Process_Command_Line, EventCode, Account_Name, Account_Domain
` ` `

<img width="1920" height="840" alt="Screenshot (7)" src="https://github.com/user-attachments/assets/5c63a5f0-f71a-4063-b132-c62bb6e01381" />

---

## 3. Key Artifacts & IOCs

* **Executed Process:** `C:\Windows\System32\schtasks.exe`
* **Command Line:** 
* **Parent Process:** 
* **Execution Timestamp:** 
* **Account Context:**
---

## 4. Conclusion
* **Verdict:**
* **Severity:** 
* **Framework Mapping:**
* **Summary:** 
