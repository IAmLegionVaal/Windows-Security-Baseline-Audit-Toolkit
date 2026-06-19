BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\modules\WinSecBaseline\WinSecBaseline.psd1'
    Import-Module $modulePath -Force
    $dataPath = Join-Path $PSScriptRoot '..\sample-data\synthetic-endpoint.json'
    $script:Data = Import-WsbSyntheticData -Path $dataPath
}

Describe 'WinSecBaseline module' {
    It 'imports successfully' {
        Get-Module WinSecBaseline | Should -Not -BeNullOrEmpty
    }

    It 'creates normalized findings' {
        $finding = New-WsbFinding -ControlId TEST-001 -Domain Test -Title 'Synthetic control' -Severity Medium -Confidence 80 -Evidence Evidence -Impact Impact -Recommendation Recommendation -Target WS01
        $finding.SeverityRank | Should -Be 3
        $finding.ControlId | Should -Be 'TEST-001'
    }

    It 'produces expected synthetic findings and score' {
        $result = Invoke-WsbAssessment -Data $script:Data
        $result.Summary.FindingCount | Should -Be 5
        $result.Summary.High | Should -Be 3
        $result.Summary.Medium | Should -Be 2
        $result.Summary.SecurityScore | Should -Be 39
        $result.Findings.ControlId | Should -Contain 'WSB-SMB-001'
        $result.Findings.ControlId | Should -Contain 'WSB-BL-001'
    }

    It 'exports JSON and CSV evidence' {
        $outputPath = Join-Path $TestDrive 'assessment'
        Invoke-WsbAssessment -Data $script:Data -OutputPath $outputPath | Out-Null
        Test-Path (Join-Path $outputPath 'assessment.json') | Should -BeTrue
        Test-Path (Join-Path $outputPath 'findings.csv') | Should -BeTrue
    }
}