# Windows Security Baseline Audit Toolkit

Defensive PowerShell tools for assessing core Windows security controls and applying selected baseline repairs.

## Audit

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Windows_Security_Baseline_Audit_Toolkit.ps1
```

## Repair

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Windows_Security_Baseline_Repair_Toolkit.ps1 -EnableFirewall -DryRun
```

Examples:

```powershell
.\Windows_Security_Baseline_Repair_Toolkit.ps1 -EnableFirewall
.\Windows_Security_Baseline_Repair_Toolkit.ps1 -EnableDefender
.\Windows_Security_Baseline_Repair_Toolkit.ps1 -DisableSmb1
.\Windows_Security_Baseline_Repair_Toolkit.ps1 -EnableUac
.\Windows_Security_Baseline_Repair_Toolkit.ps1 -EnablePowerShellLogging
```

The repair script captures firewall, Defender, SMB, UAC and PowerShell logging state before and after repair. It supports `-DryRun`, confirmation, logs and clear exit codes. Review compatibility before disabling SMB1 or enforcing additional logging.

## Author

Dewald Pretorius — L2 IT Support Engineer
