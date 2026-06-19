@{
    RootModule = 'SecurityBaseline.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'f2c2c2cb-1f2f-4b16-8a57-9df84c0ee213'
    Author = 'Dewald Pretorius'
    Description = 'Enterprise Windows security baseline assessment framework.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('New-WsbFinding','Invoke-WsbAssessment','Get-WsbScore')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}