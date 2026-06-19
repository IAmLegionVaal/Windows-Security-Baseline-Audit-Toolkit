# Controlled Live Validation

Run this from an authorized Windows endpoint. Administrator rights improve access to BitLocker, optional-feature, Defender, and firmware evidence.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-WindowsSecurityBaselineV2.ps1 `
  -Mode Live `
  -OutputPath .\artifacts\live-assessment `
  -OpenReport
```

## Expected outputs

- `assessment.json`
- `findings.csv`
- `report.html`

## Review checklist

- Confirm unavailable collectors are recorded in `CollectionNotes`.
- Validate Defender and Firewall state against Windows Security or policy management.
- Validate BitLocker and Secure Boot evidence independently.
- Review SMBv1, PowerShell logging, and RDP NLA findings against approved exceptions.
- Store only sanitized validation evidence in the repository.

The live collector is read-only and performs no remediation.
