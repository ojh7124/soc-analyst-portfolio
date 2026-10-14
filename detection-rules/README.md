# Detection Rule 1: Brute Force Attack

## The Threat
* **How to identify a brute-force attack:** A high volume of rapid failed logon events (Event ID `4625`) originating from a single source IP, followed by a successful logon (Event ID `4624`), indicates a brute force attack succeeded. Network logon (Logon Type `3`) means authentication to the system was over the network rather than through a local interactive session.

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
