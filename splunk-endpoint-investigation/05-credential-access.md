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
* **Parent Process:** `C:\Windows\System32\wbem\WmiPrvSE.exe ->  `C:\Windows\System32\cmd.exe`
* **Parent Command Line:** `reg save HKLM\SAM C:\Users\Public\sam.hive`
* **Child Command Line:** `reg save HKLM\SAM C:\Users\Public\system.hive`
* **Event Code Triggered:** `4688` (Process Creation)
* **Execution Timestamp:** `2026-10-17 22:57:56`
* **Account Context:** `HelpDesk_User`
* **Token Elevation Context:** `TokenElevationTypeDefault (1)` (Non-elevated user token)

---

## 4. Conclusion

* **Verdict:** True Positive (Attempted Post-Exploitation)
* **Severity:** High
* **Execution Status:** Failed / Blocked (`Access is denied` / Exit Code `0x5`)
* **Framework Mapping:**
  * MITRE ATT&CK T1003.002 (OS Credential Dumping: Security Account Manager)
* **Summary:** Confirmed attempted credential access via remote WMI execution[cite: 3]. At `22:57:56`, the adversary attempted to execute `reg save HKLM\SAM` using the compromised `HelpDesk_User` account[cite: 3]. However, because the execution token lacked administrative elevation (`TokenElevationTypeDefault (1)`), host-based access controls successfully prevented the registry dump, resulting in an `Access is denied` error.

---

## 5. Containment

* **Staged Artifact Deletion:** Remove both the exported SAM hive from the staging path and the temporary stdout/stderr redirection file.

<img width="1006" height="130" alt="Screenshot (19)" src="https://github.com/user-attachments/assets/50e5b876-0615-4f1c-8599-91de15502d0a" />

* **Credential Remediation:** Mandatory password reset for all local user accounts on `DESKTOP-TBSUDKQ` (including `HelpDesk_User`) due to offline hash exposure.

<img width="1006" height="108" alt="Screenshot (20)" src="https://github.com/user-attachments/assets/95683091-4a05-4b5a-82c8-c8153b55e5cc" />
  
* **Host Remediation & Re-imaging** Since local SAM hashes were exposed, prepare host `DESKTOP-TBSUDKQ` for full reimaging and redeployement after final forensic log capture.
