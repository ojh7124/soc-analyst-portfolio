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
* **Parent Process:** `C:\Windows\System32\wbem\WmiPrvSE.exe` -> `C:\Windows\System32\cmd.exe`
* **Parent Command Line:** `cmd.exe /Q /c reg save HKLM\SAM C:\Users\Public\sam.hive 1> \Windows\Temp\cNPOtp 2>&1`
* **Child Command Line:** `reg save HKLM\SAM C:\Users\Public\sam.hive`
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
* **Summary:** Confirmed attempted credential access via remote WMI execution. At `22:57:56`, the adversary attempted to execute `reg save HKLM\SAM` using the compromised `HelpDesk_User` account. However, because the execution token lacked administrative elevation (`TokenElevationTypeDefault (1)`), host-based access controls successfully prevented the registry dump, resulting in an `Access is denied` error.

---

## 5. Containment

* **Account Disablement & Session Termination:** Immediately disable the compromised `HelpDesk_User` account in Active Directory / local SAM and terminate all active network SMB/WMI sessions initiated from the attacker IP.

<img width="1007" height="284" alt="Screenshot (28)" src="https://github.com/user-attachments/assets/5475efac-32b0-429c-9a68-a5aa2f2f4637" />

* **Host Isolation:** Apply network isolation on `DESKTOP-TBSUDKQ` via host firewall to block lateral movement and C2 traffic while maintaining telemetry to Splunk.

<img width="1006" height="472" alt="Screenshot (29)" src="https://github.com/user-attachments/assets/375f8a85-24d3-4968-9d34-22c0c5a6a6cb" />

* **Credential Invalidation:** Revoke all active tokens, Kerberos tickets, and cached credentials associated with `HelpDesk_User` across the environment.

<img width="1006" height="272" alt="Screenshot (30)" src="https://github.com/user-attachments/assets/e4501778-81de-49f9-bab0-ff9e3f0657dd" />
