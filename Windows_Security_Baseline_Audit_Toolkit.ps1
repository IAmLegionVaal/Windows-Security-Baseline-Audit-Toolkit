#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputPath)

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Windows_Security_Baseline_Reports'
}
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string]$Control,[string]$Status,[string]$Observed,[string]$Recommendation)
    $findings.Add([PSCustomObject]@{
        Control=$Control; Status=$Status; Observed=$Observed; Recommendation=$Recommendation
    })
}

$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
Add-Finding 'Microsoft Defender Antivirus' $(if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {'Pass'} else {'Review'}) "Antivirus=$($defender.AntivirusEnabled); RealTime=$($defender.RealTimeProtectionEnabled); Signatures=$($defender.AntivirusSignatureVersion)" 'Ensure antivirus and real-time protection are enabled and signatures are current.'

$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in $profiles) {
    Add-Finding "Firewall profile: $($profile.Name)" $(if ($profile.Enabled) {'Pass'} else {'Review'}) "Enabled=$($profile.Enabled); Inbound=$($profile.DefaultInboundAction); Outbound=$($profile.DefaultOutboundAction)" 'Enable the firewall profile unless an approved compensating control exists.'
}

$tpm = Get-Tpm -ErrorAction SilentlyContinue
Add-Finding 'TPM readiness' $(if ($tpm.TpmPresent -and $tpm.TpmReady) {'Pass'} else {'Review'}) "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady)" 'Confirm TPM readiness on supported devices.'

$secureBoot = $null
try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch {}
Add-Finding 'Secure Boot' $(if ($secureBoot -eq $true) {'Pass'} elseif ($null -eq $secureBoot) {'Info'} else {'Review'}) "Enabled=$secureBoot" 'Enable Secure Boot on supported UEFI systems where required.'

$bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
foreach ($volume in $bitlocker) {
    Add-Finding "BitLocker: $($volume.MountPoint)" $(if ($volume.ProtectionStatus -eq 'On') {'Pass'} else {'Review'}) "Protection=$($volume.ProtectionStatus); Status=$($volume.VolumeStatus); Method=$($volume.EncryptionMethod)" 'Protect fixed operating-system volumes according to organizational policy.'
}

$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
Add-Finding 'Local Administrators membership' 'Info' "Member count=$(@($admins).Count)" 'Review each local administrator for business need and least privilege.'

$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
Add-Finding 'SMBv1 protocol' $(if ($smb1.State -eq 'Disabled') {'Pass'} else {'Review'}) "State=$($smb1.State)" 'Keep SMBv1 disabled unless a documented legacy exception exists.'

$psLogging = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
Add-Finding 'PowerShell script block logging' $(if ($psLogging.EnableScriptBlockLogging -eq 1) {'Pass'} else {'Review'}) "Enabled=$($psLogging.EnableScriptBlockLogging)" 'Enable script block logging through policy for monitored enterprise endpoints.'

$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
Add-Finding 'User Account Control' $(if ($uac.EnableLUA -eq 1) {'Pass'} else {'Review'}) "EnableLUA=$($uac.EnableLUA); ConsentPromptBehaviorAdmin=$($uac.ConsentPromptBehaviorAdmin)" 'Keep UAC enabled and configure elevation prompts according to policy.'

$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
Add-Finding 'Remote Desktop exposure' 'Info' "RemoteDesktopEnabled=$($rdp.fDenyTSConnections -eq 0)" 'Restrict Remote Desktop to approved systems and protected administrative paths.'

$auditText = auditpol.exe /get /category:* 2>$null
$auditText | Out-File (Join-Path $OutputPath "audit_policy_$stamp.txt") -Encoding UTF8
$admins | Select-Object Name,ObjectClass,PrincipalSource,SID | Export-Csv (Join-Path $OutputPath "local_administrators_$stamp.csv") -NoTypeInformation -Encoding UTF8
$profiles | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Export-Csv (Join-Path $OutputPath "firewall_profiles_$stamp.csv") -NoTypeInformation -Encoding UTF8
$findings | Export-Csv (Join-Path $OutputPath "security_findings_$stamp.csv") -NoTypeInformation -Encoding UTF8

$summary = [PSCustomObject]@{
    Computer=$env:COMPUTERNAME
    Pass=@($findings | Where-Object Status -eq 'Pass').Count
    Review=@($findings | Where-Object Status -eq 'Review').Count
    Info=@($findings | Where-Object Status -eq 'Info').Count
    Generated=Get-Date
}

@{Summary=$summary;Findings=$findings;Administrators=$admins;FirewallProfiles=$profiles} |
    ConvertTo-Json -Depth 8 |
    Set-Content (Join-Path $OutputPath "security_baseline_$stamp.json") -Encoding UTF8

$html = "<h1>Windows Security Baseline - $env:COMPUTERNAME</h1><p>Generated $(Get-Date)</p><h2>Summary</h2>$(@($summary)|ConvertTo-Html -Fragment)<h2>Findings</h2>$($findings|ConvertTo-Html -Fragment)"
$html | ConvertTo-Html -Title 'Windows Security Baseline Audit' |
    Set-Content (Join-Path $OutputPath "security_baseline_$stamp.html") -Encoding UTF8

$summary | Format-List
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
