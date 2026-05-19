# Detection Rule: MFA Abuse


## Overview

- **What it detects:** detects excessive failed attempts to bypass MFA, more than 10 failed MFA attempts within 10 minutes

- **MITRE ATT&CK Technique:** T1621

- **Severity:** High

- **Author:** Ashraf Khan Awaiz

## Detection Logic

```KQL

### KQL (Microsoft Sentinel)

signinlogs 
|where timegenerated  >ago (10m) 
|where resulttype != 0  
|summarize  failedattempts = count () by userprinciplename 
|where failedattempts >10  
```


## Sample Log

TimeGenerated: 22-04/2026 18:56
UserPrincipalName: "John Smith"
IPAddress: 185.222.101.45
Location: Russia
ResultType: 50074
ResultDescription: MFA required, user did not respond


## Investigation Steps

1. Validate - check sign-in logs
2. If failed or successful how many times
3. Is this usual for user
4. Does it exceed normal amount location
5. If successful - remediation, block account reset credentials, revoke tokens, block ip, check for lateral movement
6. If unsuccessful - reset password 

## False Positive Considerations


- Session timing out  
- Users forgetting credentials 
- Automated scripts - outdated login details
- Users travelling abroad triggering location anomalies.


## References

- MITRE ATT&CK T1621 - https://attack.mitre.org/techniques/T1621/
- Microsoft SigninLogs documentation


