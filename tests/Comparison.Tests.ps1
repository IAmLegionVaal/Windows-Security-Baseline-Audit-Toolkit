BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\modules\WinSecBaseline\WinSecBaseline.psd1'
    Import-Module $modulePath -Force
    $dataPath = Join-Path $PSScriptRoot '..\sample-data\synthetic-endpoint.json'
    $script:Data = Import-WsbSyntheticData -Path $dataPath
}

Describe 'Assessment comparison' {
    It 'exports comparison and reporting commands' {
        $commands = Get-Command -Module WinSecBaseline | Select-Object -ExpandProperty Name
        $commands | Should -Contain 'Compare-WsbAssessment'
        $commands | Should -Contain 'Get-WsbLiveData'
        $commands | Should -Contain 'New-WsbHtmlReport'
    }

    It 'reports an improved current assessment' {
        $baseline = Invoke-WsbAssessment -Data $script:Data
        $currentData = $script:Data | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $currentData.Protocols.Smb1Enabled = $false
        $current = Invoke-WsbAssessment -Data $currentData
        $comparison = Compare-WsbAssessment -Baseline $baseline -Current $current

        $comparison.Summary.ResolvedCount | Should -Be 1
        $comparison.Summary.SecurityScoreDelta | Should -Be 15
        $comparison.ResolvedFindings.ControlId | Should -Contain 'WSB-SMB-001'
    }
}
