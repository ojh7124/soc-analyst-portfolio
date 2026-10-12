# Phase 5: Credential Access & Exfiltration

## 1. Hypothesis

* **What I was looking for:** Evidence of the adversary dumping local credentials and staging sensitive system data for extraction following defense evasion.
* **Analyst Hypothesis:** If the attacker attempts to steal credentials or stage data, I expect to see process activity related to SAM registry hive dumping (T1003.002) and file staging in temporary local directories (T1074.001).

---

## 2. SPL Query

` ` `
index=* (EventCode=4688 OR EventCode=1) ("reg save" OR "HKLM" OR "SAM" OR "SYSTEM" OR "SECURITY" OR "*.zip" OR "*.rar" OR "*.tar" OR "compress")
| sort _time
| table _time, host, EventCode, Account_Name, New_Process_Name, Process_Command_Line
` ` `

<img width="1920" height="737" alt="Screenshot (18)" src="https://github.com/user-attachments/assets/2ad4d2b4-5d72-4a19-ba08-76495cb6a6e5" />

---

## 3. Key Artifacts & IOCs

* **Executed Process:** `C:\Windows\System32\reg.exe`
* **Parent Process:** `C:\Windows\System32\cmd.exe`
* **Parent Command Line:** `"cmd.exe" /T:fg /Q /C reg save HKLM\SAM C:\Users\Public\system.hive > \Windows\Temp\KpnABZDV 2>&1`
* **Child Command Line:** `reg save HKLM\SAM C:\Users\Public\system.hive`
* **Event Code Triggered:** `4688` (Process Creation)
* **Execution Timestamp:** `2026-10-07 20:06:25`
* **Account Context:** `DESKTOP-TBSUDKQ$` (Executed on host)
* **Staged File Artifact:** `C:\Users\Public\system.hive` (Contains local account password hashes)
* **Temporary Output File Artifact:** `\Windows\Temp\KpnABZDV` (Created by output redirection to hide console errors)

---

## 4. Conclusion

* **Verdict:** True Positive 
* **Severity:** Critical
* **Framework Mapping:**
  * MITRE ATT&CK T1003.002 (OS Credential Dumping: Security Account Manager)
  * MITRE ATT&CK T1074.001 (Data Staged: Local Data Staging)
* **Summary:** Confirmed credential access and data staging. At `20:06:25`, the adversary executed `reg save HKLM\SAM` via `cmd.exe` to export the local Security Account Manager hive into `C:\Users\Public\system.hive`. This allowed offline extraction of password hashes while outputting errors quietly to `\Windows\Temp\KpnABZDV`.

---

## 5. Containment

* **Staged Artifact Deletion:** Remove both the exported SAM hive from the staging path and the temporary stdout/stderr redirection file.

<img width="1006" height="130" alt="Screenshot (19)" src="https://github.com/user-attachments/assets/50e5b876-0615-4f1c-8599-91de15502d0a" />

* **Credential Remediation:** Mandatory password reset for all local user accounts on `DESKTOP-TBSUDKQ` (including `HelpDesk_User`) due to offline hash exposure.

<img width="1006" height="108" alt="Screenshot (20)" src="https://github.com/user-attachments/assets/95683091-4a05-4b5a-82c8-c8153b55e5cc" />
  
* **Host Remediation & Re-imaging** Since local SAM hashes were exposed, prepare host `DESKTOP-TBSUDKQ` for full reimaging and redeployement after final forensic log capture.
