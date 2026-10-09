# Phase 2: Discovery

## 1. Hypothesis
* **What I was looking for:** Evidence of post-exploitation discover/reconnaissance activity executed shortly after the initial successful breach via brute force at `(05/10/2026 17:55:35)`.
* **Analyst Hypothesis:** I expect to see the command-line execution of build-in Windows enumeration tools `(e.g. whoami, net user, ipconfig)` spawned via `cmd.exe` to inspect privilege levels and system configuration.

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1)  Creator_Process_Name="C:\\Windows\\System32\\cmd.exe" | sort _time  | table  _time, New_Process_Name, Process_Command_Line, EventCode, Account_Name, Account_Domain
` ` `

<img width="1920" height="650" alt="Screenshot (6)" src="https://github.com/user-attachments/assets/c828ac1b-fb1b-4db9-8a01-189a51e57609" />

---

## 3. Key Artifacts & IOCs

* **Target Account:**
* **Source IP:** 
* **EventCode Pattern:**
* **Logon Type:**

---

## 4. Conclusion
* **Verdict:** 
* **Severity:**
* **Framework Mapping:**
* **Summary:**
