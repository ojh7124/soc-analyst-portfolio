# Phase 5: Credential Access

## 1. Hypothesis

* **What I was looking for:** Evidence of post-exploitation credential harvesting targeting local SAM registry hives via remote execution channels following defence evasion.
* **Analyst Hypothesis:** If the adversary attempts to dump local account NTLM hashes, I expect to observe Windows process creation telemetry (Event Code `4688`) capturing command-line execution of `reg save` targeting `HLKM/SAM` via network management protocols (T1003.002).

---

## 2. SPL Query

` ` `
index=* host="DESKTOP-TBSUDKQ" EventCode=4688 ("reg save" OR "HKLM\\SAM" OR "HKLM\\SYSTEM")
| eval Process_Cmd=coalesce(Process_Command_Line, CommandLine)
| eval Parent_Proc=coalesce(Creator_Process_Name, Parent_Process_Name)
| eval Process_Name=coalesce(New_Process_Name, Process_Name)
| table _time, host, Account_Name, Parent_Proc, Process_Name, Process_Cmd, Token_Elevation_Type
| sort _time asc
` ` `

<img width="1920" height="754" alt="Screenshot (27)" src="https://github.com/user-attachments/assets/8fa963c2-49c1-49a1-ae8a-57293ebd110a" />


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
