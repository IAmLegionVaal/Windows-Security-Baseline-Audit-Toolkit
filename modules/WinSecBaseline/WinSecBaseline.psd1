@{
    RootModule        = 'WinSecBaseline.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = '39d58815-7d24-4f86-9695-6a24f1ac7993'
    Author            = 'Dewald Pretorius'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 Dewald Pretorius. All rights reserved.'
    Description       = 'Enterprise Windows security baseline assessment framework.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('New-WsbFinding','Get-WsbSeverityRank','Import-WsbSyntheticData','Invoke-WsbAssessment')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('Windows','Security','Baseline','Audit','PowerShell'); ProjectUri = 'https://github.com/IAmLegionVaal/Windows-Security-Baseline-Audit-Toolkit' } }
}