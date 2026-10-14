# SPL Detection Rule: Brute Force Attack

## The Threat
* **Identifying a brute-force attack:** A high volume of rapid failed logon events (Event ID `4625`) originating from a single source IP, followed by a successful logon (Event ID `4624`), indicates a brute force attack succeeded. Network logon (Logon Type `3`) means authentication to the system was over the network rather than through a local interactive session.

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

**1.** `index=* (EventCode=4625 OR EventCode=4624) Logon_Type=3`:
   * Filters the search window specifically for network logon attempts that either failed or succeeded.

**2.** `| stats count(eval(...)) ... by Account_Name, Source_Network_Address`:
   * Groups the events by the target user account and the attacker's source IP address, counting failures and successes separately.

**3.** `| where Failed_Logons > 5 AND Successful_Logons > 0`:
   * Filters out noise. It only triggers an alert if there were more than 5 failed attempts and at least 1 successful login from that same source/account pairing.

**4.** `| eval ... | table ...`:
   * Enriches the output with clear metadata and formats it into a clean presentation table for the SOC analyst.

---
