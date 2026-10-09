# Phase 2: Discovery

## 1. Hypothesis
* **What I was looking for:**
* **Analyst Hypothesis:**

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1)  Creator_Process_Name="C:\\Windows\\System32\\cmd.exe" | sort _time  | table  _time, New_Process_Name, Process_Command_Line
` ` `

<img width="1920" height="1026" alt="Screenshot (1)" src="https://github.com/user-attachments/assets/575305fe-d4b2-4e2e-9475-7c504db434ea" />

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
