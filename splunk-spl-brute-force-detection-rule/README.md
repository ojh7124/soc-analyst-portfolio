# Splunk Detection Rule: Brute Force Attack

## The Threat
* **Identifying a brute-force attack:** A high volume of rapid failed logon events (Event ID `4625`) originating from a single source IP, followed by a successful logon (Event ID `4624`), indicates a brute force attack succeeded. Network logon (Logon Type `3`) means authentication to the system was over the network rather than through a local interactive session.

---

## The SPL Query

```
index=* (EventCode=4625 OR EventCode=4624) Logon_Type=3 
| stats count(eval(EventCode=4625)) as Failed_Logons, 
        count(eval(EventCode=4624)) as Successful_Logons,
        earliest(_time) as First_Attempt,
        latest(_time) as Last_Attempt
        by Account_Name, Source_Network_Address
| where Failed_Logons > 2 AND Successful_Logons > 0
| convert ctime(First_Attempt) ctime(Last_Attempt)
| eval Threat_Confidence="High", Incident_Type="SMB Brute Force Success"
| table First_Attempt, Account_Name, Source_Network_Address, Failed_Logons, Successful_Logons, Threat_Confidence
```

**1. `index=* (EventCode=4625 OR EventCode=4624) Logon_Type=3`**: 
* Filters the search window specifically for network logon attempts (common with SMB traffic) that either failed or succeeded.

**2. `| stats count(eval(...)) ... by Account_Name, Source_Network_Address`**: 
* Groups events by the target user account and source IP address while capturing earliest/latest timestamps, counting failures and successes separately.

**3. `| where Failed_Logons > 2 AND Successful_Logons > 0`**: 
* Filters out noise. It only triggers an alert if there were more than 2 failed attempts followed by at least 1 successful login from that same source and account pairing.

**4. `| convert ctime(...) | eval ... | table ...`**: 
* Converts raw UNIX timestamps into human-readable times, enriches the output with threat classification metadata, and formats the result into a clean SOC presentation table.

<img width="1920" height="728" alt="Screenshot (21)" src="https://github.com/user-attachments/assets/3b468b53-60e5-4db6-b7dd-122f234523a5" />

---

## Rule Deployment & Alert Configuration 

To transition this SPL query from a manual search into an automated detection rule, it was configured as a **Scheduled Alert** in Splunk Enterprise:

* **Alert Name:** `Detect-Brute-Force-Success`
* **Execution Schedule:** Run every 1 hour (looking back over the last 5 minutes of data).
* **Trigger Condition:** `Number of Results > 0` (Triggers if any source IP successfully logs in after multiple failures).
* **Alert Actions:** 
  * Log event to an internal notable index / security dashboard.
  * (Optional in enterprise environments) Send webhook to SOAR or email notification to the SOC on-call rotation.

<img width="1920" height="1030" alt="Screenshot (22)" src="https://github.com/user-attachments/assets/a4ca26ef-17c5-4918-96b0-38009075d219" />
<img width="1920" height="390" alt="Screenshot (23)" src="https://github.com/user-attachments/assets/b1fdfe35-6434-4c95-bd6d-74615fa08fab" />


