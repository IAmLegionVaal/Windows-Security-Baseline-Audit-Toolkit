@{
    RootModule        = ''
    NestedModules     = @('WinSecBaseline.psm1','WinSecBaseline.Comparison.psm1')
    ModuleVersion     = '2.2.1'
    GUID              = '39d58815-7d24-4f86-9695-6a24f1ac7993'
    Author            = 'Dewald Pretorius'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 Dewald Pretorius. All rights reserved.'
    Description       = 'Windows configuration assessment and comparison module.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'New-WsbFinding',
        'Get-WsbSeverityRank',
        'Import-WsbSyntheticData',
        'Get-WsbLiveData',
        'New-WsbHtmlReport',
        'Invoke-WsbAssessment',
        'Compare-WsbAssessment'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Windows','Configuration','Audit','PowerShell')
            ProjectUri = 'https://github.com/IAmLegionVaal/Windows-Security-Baseline-Audit-Toolkit'
        }
    }
}
