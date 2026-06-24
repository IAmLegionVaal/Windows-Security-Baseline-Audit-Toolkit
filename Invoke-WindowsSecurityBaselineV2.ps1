[CmdletBinding()]
param(
    [ValidateSet('Synthetic','Live')][string]$Mode = 'Synthetic',
    [string]$SyntheticDataPath = (Join-Path $PSScriptRoot 'sample-data\synthetic-endpoint.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'artifacts\latest-assessment'),
    [switch]$OpenReport
)

$modulePath = Join-Path $PSScriptRoot 'modules\WinSecBaseline\WinSecBaseline.psd1'
Import-Module $modulePath -Force -ErrorAction Stop
$data = if ($Mode -eq 'Live') { Get-WsbLiveData } else { Import-WsbSyntheticData -Path $SyntheticDataPath }
$result = Invoke-WsbAssessment -Data $data -OutputPath $OutputPath
$result.Summary | Format-List
$result.Findings | Format-Table Severity,Confidence,ControlId,Domain,Title -AutoSize

$reportPath = Join-Path $OutputPath 'report.html'
if ($OpenReport -and (Test-Path $reportPath)) {
    Start-Process $reportPath
}
