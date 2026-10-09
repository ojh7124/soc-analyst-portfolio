# Phase 2: Discovery

## 1. Hypothesis
* **What I was looking for:**
* **Analyst Hypothesis:**

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1)  Creator_Process_Name="C:\\Windows\\System32\\cmd.exe" | sort _time  | table  _time, New_Process_Name, Process_Command_Line
` ` `



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
