# Detection Rule 1: Brute Force Attack

## The Threat
* **Signs of a brute force attack:** A high volume of failures originating from the same source followed by a success indicates a brute-force attack succeeded.
* **What to look for:**
  * **Event ID 4625:** An account `failed` to authenticate (wrong password).
  * **Event ID 4624:** An account `successfully` authenticated (correct password).
  * **Logon Type 3:** A `network logon` (occurs when a user or computer authenticates to a machine remotley over the network rather than through a local interactive session).

---

## The Splunk SPL Query

```
index=* (EventCode=4625 OR EventCode=4624) Logon_Type=3 
| stats count(eval(EventCode=4625)) as Failed_Logons, 
        count(eval(EventCode=4624)) as Successful_Logons 
        by Account_Name, Source_Network_Address
| where Failed_Logons > 5 AND Successful_Logons > 0
| eval Threat_Confidence="High", Incident_Type="SMB Brute Force Success"
| table _time, Account_Name, Source_Network_Address, Failed_Logons, Successful_Logons, Threat_Confidence
```
