Set-StrictMode -Version Latest

function Get-WsbSeverityRank {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity)
    switch ($Severity) {
        'Critical' { 5 }
        'High' { 4 }
        'Medium' { 3 }
        'Low' { 2 }
        'Informational' { 1 }
    }
}

function New-WsbFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [Parameter(Mandatory)][ValidateRange(0,100)][int]$Confidence,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Impact,
        [Parameter(Mandatory)][string]$Recommendation,
        [string]$Target = $env:COMPUTERNAME
    )

    [PSCustomObject]@{
        FindingId      = [guid]::NewGuid().Guid
        ControlId      = $ControlId
        Domain         = $Domain
        Title          = $Title
        Severity       = $Severity
        SeverityRank   = Get-WsbSeverityRank -Severity $Severity
        Confidence     = $Confidence
        Target         = $Target
        Evidence       = $Evidence
        Impact         = $Impact
        Recommendation = $Recommendation
        ObservedAtUtc  = [datetime]::UtcNow
    }
}

function Import-WsbSyntheticData {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateScript({ Test-Path $_ -PathType Leaf })][string]$Path)
    Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

function Invoke-WsbAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Data,
        [string]$OutputPath
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if (-not $Data.Defender.RealtimeProtectionEnabled) {
        $findings.Add((New-WsbFinding -ControlId 'WSB-DEF-001' -Domain 'Defender' -Title 'Microsoft Defender real-time protection is disabled' -Severity Critical -Confidence 99 -Evidence 'RealtimeProtectionEnabled=False' -Impact 'Malicious files and processes may not be blocked at execution time.' -Recommendation 'Restore the approved Defender policy and investigate unauthorized security-control changes.' -Target $Data.ComputerName))
    }

    if (-not $Data.Firewall.DomainEnabled -or -not $Data.Firewall.PrivateEnabled -or -not $Data.Firewall.PublicEnabled) {
        $disabledProfiles = @()
        if (-not $Data.Firewall.DomainEnabled) { $disabledProfiles += 'Domain' }
        if (-not $Data.Firewall.PrivateEnabled) { $disabledProfiles += 'Private' }
        if (-not $Data.Firewall.PublicEnabled) { $disabledProfiles += 'Public' }
        $findings.Add((New-WsbFinding -ControlId 'WSB-FW-001' -Domain 'Firewall' -Title 'Windows Firewall profile disabled' -Severity High -Confidence 98 -Evidence ($disabledProfiles -join ', ') -Impact 'The endpoint may accept network traffic that should be blocked.' -Recommendation 'Enable the approved firewall profiles and review policy conflicts or local overrides.' -Target $Data.ComputerName))
    }

    if (-not $Data.BitLocker.OsVolumeProtected) {
        $findings.Add((New-WsbFinding -ControlId 'WSB-BL-001' -Domain 'BitLocker' -Title 'Operating system volume is not protected by BitLocker' -Severity High -Confidence 97 -Evidence 'OsVolumeProtected=False' -Impact 'Data may be exposed if the device or storage is lost or removed.' -Recommendation 'Apply the approved encryption policy and escrow recovery information through the authorized platform.' -Target $Data.ComputerName))
    }

    if (-not $Data.DeviceSecurity.SecureBootEnabled) {
        $findings.Add((New-WsbFinding -ControlId 'WSB-DS-001' -Domain 'DeviceSecurity' -Title 'Secure Boot is not enabled' -Severity Medium -Confidence 90 -Evidence 'SecureBootEnabled=False' -Impact 'The startup chain has reduced protection against unauthorized boot components.' -Recommendation 'Confirm hardware support and enable Secure Boot under the approved change process.' -Target $Data.ComputerName))
    }

    if (-not $Data.PowerShell.ScriptBlockLoggingEnabled) {
        $findings.Add((New-WsbFinding -ControlId 'WSB-PS-001' -Domain 'PowerShell' -Title 'PowerShell script block logging is disabled' -Severity Medium -Confidence 95 -Evidence 'ScriptBlockLoggingEnabled=False' -Impact 'Suspicious PowerShell activity may be harder to investigate.' -Recommendation 'Enable centralized PowerShell logging and verify event collection and retention.' -Target $Data.ComputerName))
    }

    if ($Data.Protocols.Smb1Enabled) {
        $findings.Add((New-WsbFinding -ControlId 'WSB-SMB-001' -Domain 'Protocols' -Title 'SMBv1 is enabled' -Severity High -Confidence 99 -Evidence 'Smb1Enabled=True' -Impact 'The endpoint is exposed to a deprecated protocol with significant security weaknesses.' -Recommendation 'Identify dependencies, remove them, and disable SMBv1 through approved policy.' -Target $Data.ComputerName))
    }

    if (-not $Data.RemoteAccess.RdpNlaRequired) {
        $findings.Add((New-WsbFinding -ControlId 'WSB-RDP-001' -Domain 'RemoteAccess' -Title 'Remote Desktop does not require Network Level Authentication' -Severity Medium -Confidence 96 -Evidence 'RdpNlaRequired=False' -Impact 'Remote Desktop exposes a larger pre-authentication attack surface.' -Recommendation 'Require Network Level Authentication and validate remote-access policy.' -Target $Data.ComputerName))
    }

    $sortProperties = @(
        @{ Expression = 'SeverityRank'; Descending = $true },
        @{ Expression = 'Confidence'; Descending = $true }
    )
    $sorted = @($findings | Sort-Object -Property $sortProperties)
    $maxScore = 100
    $deduction = 0
    foreach ($finding in $sorted) {
        $deduction += switch ($finding.Severity) {
            'Critical' { 30 }
            'High' { 15 }
            'Medium' { 8 }
            'Low' { 3 }
            default { 0 }
        }
    }
    $score = [math]::Max(0, $maxScore - $deduction)

    $result = [PSCustomObject]@{
        Summary = [PSCustomObject]@{
            ComputerName   = $Data.ComputerName
            AssessedAtUtc  = [datetime]::UtcNow
            SecurityScore  = $score
            FindingCount   = $sorted.Count
            Critical       = @($sorted | Where-Object Severity -eq 'Critical').Count
            High           = @($sorted | Where-Object Severity -eq 'High').Count
            Medium         = @($sorted | Where-Object Severity -eq 'Medium').Count
            Low            = @($sorted | Where-Object Severity -eq 'Low').Count
        }
        Findings = $sorted
        Evidence = $Data
    }

    if ($OutputPath) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        $result | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $OutputPath 'assessment.json') -Encoding UTF8
        $sorted | Export-Csv -Path (Join-Path $OutputPath 'findings.csv') -NoTypeInformation -Encoding UTF8
    }

    $result
}

Export-ModuleMember -Function Get-WsbSeverityRank,New-WsbFinding,Import-WsbSyntheticData,Invoke-WsbAssessment
