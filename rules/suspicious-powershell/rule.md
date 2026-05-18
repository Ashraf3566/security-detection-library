# Detection Rule: Suspicious PowerShell

## Overview
- **What it detects:** detects PowerShell execution using suspicious flags including EncodedCommand, -ExecutionPolicy Bypass, and IEX downloads
- **MITRE ATT&CK Technique:** T1059.001 - PowerShell
- **Severity:** High
- **Author:** Ashraf Khan Awaiz

## Detection Logic


### KQL (Microsoft Sentinel)
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where CommandLine contains "-EncodedCommand"
    or CommandLine contains "-ExecutionPolicy Bypass"
    or CommandLine contains "IEX"
    or CommandLine contains "DownloadString"
```

## Sample Log

TimeGenerated: 2024-01-15T02:14:33Z
EventID: 4688
Account: CONTOSO\john.smith
ProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -EncodedCommand JABjAGwAaQBlAG4AdA==
ParentProcess: cmd.exe

## Investigation Steps

1. Validate the alert — confirm the CommandLine contains the suspicious flag that triggered the rule
2. Check the process tree — what spawned PowerShell? A legitimate parent like explorer.exe is less suspicious than winword.exe or mshta.exe
3. Confirm the user and machine — is this account expected to run PowerShell? Developer vs standard user changes the risk level significantly
4. Hash the process — get the SHA256 of the executed file and check against VirusTotal, AbuseIPDB, and other OSINT tools
5. Check for network connections — did the process make outbound connections immediately after? Look for DNS queries or HTTP requests to external IPs
6. Confirm with the user — did they intentionally run this command? A simple call can rule out a false positive immediately
7. Contain if malicious — isolate the machine, disable the account, escalate to L2 or incident response

## False Positive Considerations

Not every PowerShell alert is malicious. Common legitimate causes:

IT administrators running management scripts
Software deployment tools like SCCM or Ansible using PowerShell
Developers testing scripts on their own machines
Security tools that use PowerShell for scanning

The key is context — who ran it, from what machine, at what time, with what parent process.

## References

- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- Windows Event ID 4688: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688