Set-StrictMode -Version Latest

function New-WsbFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [Parameter(Mandatory)][ValidateRange(0,100)][int]$Confidence,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Impact,
        [Parameter(Mandatory)][string]$Remediation,
        [string]$Target = $env:COMPUTERNAME
    )

    [PSCustomObject]@{
        FindingId=[guid]::NewGuid().Guid
        ControlId=$ControlId
        Title=$Title
        Severity=$Severity
        Confidence=$Confidence
        Evidence=$Evidence
        Impact=$Impact
        Remediation=$Remediation
        Target=$Target
        ObservedAtUtc=[datetime]::UtcNow
    }
}

function Get-WsbScore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Findings)

    $weights = @{ Critical=25; High=15; Medium=8; Low=3; Informational=0 }
    $deduction = 0
    foreach ($finding in $Findings) {
        $deduction += $weights[$finding.Severity]
    }
    [math]::Max(0,100-$deduction)
}

function Invoke-WsbAssessment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Data)

    $findings = [System.Collections.Generic.List[object]]::new()

    if (-not $Data.Defender.RealTimeProtectionEnabled) {
        $findings.Add((New-WsbFinding -ControlId 'WIN-DEF-001' -Title 'Microsoft Defender real-time protection disabled' -Severity High -Confidence 99 -Evidence 'RealTimeProtectionEnabled=False' -Impact 'Malware may execute without real-time inspection.' -Remediation 'Restore the approved Defender policy and validate service health.'))
    }
    if (-not $Data.Firewall.AllProfilesEnabled) {
        $findings.Add((New-WsbFinding -ControlId 'WIN-FW-001' -Title 'One or more Windows Firewall profiles disabled' -Severity High -Confidence 98 -Evidence 'AllProfilesEnabled=False' -Impact 'Network exposure may increase on affected profiles.' -Remediation 'Enable the approved firewall profiles and review policy conflicts.'))
    }
    if (-not $Data.BitLocker.OsVolumeProtected) {
        $findings.Add((New-WsbFinding -ControlId 'WIN-BL-001' -Title 'Operating system volume not protected by BitLocker' -Severity High -Confidence 97 -Evidence 'OsVolumeProtected=False' -Impact 'Data may be exposed if the device is lost or storage is removed.' -Remediation 'Enable BitLocker using the approved recovery-key escrow process.'))
    }
    if (-not $Data.PowerShell.ScriptBlockLoggingEnabled) {
        $findings.Add((New-WsbFinding -ControlId 'WIN-PS-001' -Title 'PowerShell script block logging disabled' -Severity Medium -Confidence 95 -Evidence 'ScriptBlockLoggingEnabled=False' -Impact 'Security investigations may lack command execution evidence.' -Remediation 'Enable script block logging through approved policy and validate log forwarding.'))
    }

    $resultFindings = @($findings)
    [PSCustomObject]@{
        Score = Get-WsbScore -Findings $resultFindings
        Findings = $resultFindings
        Evidence = $Data
        AssessedAtUtc = [datetime]::UtcNow
    }
}

Export-ModuleMember -Function New-WsbFinding,Get-WsbScore,Invoke-WsbAssessment
