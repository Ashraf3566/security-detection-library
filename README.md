# Security Detection Library

This is a personal library of detection rules written in KQL and SPL, mapped to MITRE ATT&CK techniques.

Built by me Ashraf Awaiz, SOC analyst transitioning into Cybersecurity Engineering.

## Purpose

Most detection rules live inside a SIEM where nobody outside
the team can see them. This library makes my detection logic
visible, documented, and portable.

Each rule includes:
- The detection query (KQL or SPL)
- The MITRE ATT&CK technique it covers
- A sample log showing what the alert looks like
- Investigation steps
- False positive considerations

## Rules

| Rule | Technique | Severity |
|------|-----------|----------|
| Brute Force Login | T1110 | High |
| Suspicious PowerShell | T1059.001 | High |
| MFA Abuse | T1621 | Medium |

## Structure

security-detection-library/
├── rules/
│   ├── brute-force-login/
│   ├── suspicious-powershell/
│   └── mfa-abuse/
└── templates/
    └── rule-template.md

## Author

Ashraf Khan Awaiz
SOC Analyst | Accenture
https://github.com/Ashraf3566
