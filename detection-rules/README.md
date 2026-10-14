# Detection Rule 1: Brute Force Attack

## The Threat
* **Signs of a brute force attack:** A high volume of failures originating from the same source followed by a success indicates a brute-force attack succeeded.
* **What to look for:**
  * **Event ID 4625:** An account `failed` to authenticate (wrong password).
  * **Event ID 4624:** An account `successfully` authenticated (correct password).
  * **Logon Type 3:** A `network logon` (occurs when a user or computer authenticates to a machine remotley over the network rather than through a local interactive session).
