# Windows Security Baseline Audit Toolkit

A defensive, read-only PowerShell toolkit for assessing core Windows security controls and configuration posture.

## Checks

- Microsoft Defender health
- Windows Firewall profiles
- BitLocker and TPM readiness
- Secure Boot status
- Local account and administrator exposure
- SMB protocol configuration
- PowerShell logging and execution policy
- Audit policy summary
- UAC and remote access settings

## Output

- CSV findings
- JSON evidence
- HTML executive report

## Run

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Windows_Security_Baseline_Audit_Toolkit.ps1
```

## Safety

Read-only. The toolkit reports configuration and does not modify security controls.
