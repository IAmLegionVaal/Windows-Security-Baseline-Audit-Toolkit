[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
 [switch]$EnableFirewall,
 [switch]$EnableDefender,
 [switch]$DisableSmb1,
 [switch]$EnableUac,
 [switch]$EnablePowerShellLogging,
 [switch]$DryRun,
 [switch]$Yes,
 [string]$OutputPath=(Join-Path $env:ProgramData 'WindowsSecurityBaselineRepair')
)
$ErrorActionPreference='Stop';$script:Failures=0;$script:Actions=0
$run=Join-Path $OutputPath (Get-Date -Format yyyyMMdd_HHmmss);New-Item -ItemType Directory $run -Force|Out-Null
$log=Join-Path $run 'repair.log';$before=Join-Path $run 'before.json';$after=Join-Path $run 'after.json'
function Log($m){"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"|Tee-Object -FilePath $log -Append}
function Admin{$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
function State{[pscustomobject]@{Collected=Get-Date;Firewall=Get-NetFirewallProfile|Select-Object Name,Enabled;Defender=Get-MpComputerStatus -ErrorAction SilentlyContinue|Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated;Smb=Get-SmbServerConfiguration|Select-Object EnableSMB1Protocol,EnableSMB2Protocol,EnableSecuritySignature,RequireSecuritySignature;Uac=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'|Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop;PowerShellLogging=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue}}
function Act($d,[scriptblock]$a){$script:Actions++;Log $d;if($DryRun){Log "DRY-RUN: $d";return};try{&$a;Log "SUCCESS: $d"}catch{$script:Failures++;Log "FAILED: $d - $($_.Exception.Message)"}}
State|ConvertTo-Json -Depth 6|Set-Content $before -Encoding UTF8
if(-not($EnableFirewall -or $EnableDefender -or $DisableSmb1 -or $EnableUac -or $EnablePowerShellLogging)){Write-Error 'Choose at least one repair action.';exit 2}
if(-not $DryRun -and -not(Admin)){Write-Error 'Run from elevated PowerShell.';exit 4}
if(-not $Yes -and -not $DryRun){if((Read-Host 'Apply selected Windows security baseline repairs? Type YES') -ne 'YES'){Log 'Cancelled.';exit 10}}
if($EnableFirewall){Act 'Enabling all Windows Firewall profiles' {Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True}}
if($EnableDefender){Act 'Enabling Microsoft Defender real-time monitoring' {Set-MpPreference -DisableRealtimeMonitoring $false}}
if($DisableSmb1){Act 'Disabling SMB1 server protocol and enabling SMB2' {Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $true -Force}}
if($EnableUac){Act 'Enabling User Account Control' {Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA 1;Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' PromptOnSecureDesktop 1}}
if($EnablePowerShellLogging){Act 'Enabling PowerShell script block logging' {New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force|Out-Null;Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1}}
Start-Sleep 2;State|ConvertTo-Json -Depth 6|Set-Content $after -Encoding UTF8
if($script:Failures){exit 20};Log "Repair completed. Actions: $script:Actions";exit 0
