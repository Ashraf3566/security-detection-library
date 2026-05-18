# Detection Rule : Brute Force Login Atttack


## Overview 

- **What it Detects:** 5+ failed logins against one account within 5 minutes.

- **MITRE ATT&CK Technique:** T1110.001 - Password Guessing.

- **Severity:** Medium.

- **Author:** Ashraf Khan Awaiz

## Detection Logic

### KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where TimeGenerated > ago (5m)
| where EventID == 4625
| summarise FailedAttempts = count () by TargetAccount
| where FailedAttempts >5
```

## Sample log

TimeGenerated: 2024-01-15T03:22:14Z
EventID: 4625
Account: john.smith@countoso.com
TargetAccount: john.smith 
WorkstationName: UNKNOWN
IpAddress: 185.220.101.45
LogonType: 3
FailureReason: Unknown user name or bad password

## Investigation Steps

1. Validate the alert - confirm 5+ failed login attempts against the sampe account within 5 minutes
2. Check for successful login - search for EventID 4624 from the same ip after the failiures
3. Enrich the source IP - check OSINT
4. Search for lateral movement - look for authentication events from this account on other machines
5. Contain if confirmed - reset credentials, block ip, disable account, escalate to customer

## False Positive Considerations

- User locking themselves out from their IP and location
- Password expiry causing repeated failures with old credentials
- Automated service accounts with hardcoded passwords after a rotation
- Password spraying will NOT be detected by this rule - it stays under the threshold per account

## References

- MITRE ATT&CK T1110.001
- Windows Event ID 4625
