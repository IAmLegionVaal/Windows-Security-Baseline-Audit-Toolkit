[CmdletBinding()]
param(
    [string]$SyntheticDataPath = (Join-Path $PSScriptRoot 'sample-data\synthetic-endpoint.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'artifacts\latest-assessment')
)

$modulePath = Join-Path $PSScriptRoot 'modules\WinSecBaseline\WinSecBaseline.psd1'
Import-Module $modulePath -Force -ErrorAction Stop
$data = Import-WsbSyntheticData -Path $SyntheticDataPath
$result = Invoke-WsbAssessment -Data $data -OutputPath $OutputPath
$result.Summary | Format-List
$result.Findings | Format-Table Severity,Confidence,ControlId,Domain,Title -AutoSize
