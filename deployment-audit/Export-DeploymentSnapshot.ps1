#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$Environment,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$HmacKeyEnvironmentVariable='DEPLOYMENT_AUDIT_HMAC_KEY'
)
$ErrorActionPreference='Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'DeploymentAudit.psm1') -Force -DisableNameChecking
    $snapshot=Invoke-AuditCollection -ManifestPath $Manifest -Environment $Environment -OutputPath $Output -HmacKeyEnvironmentVariable $HmacKeyEnvironmentVariable
    Write-Host "Snapshot: $Output | $($snapshot.records.Count) records"
    $incomplete=@($snapshot.records | Where-Object status -in @('Error','Partial')).Count
    if ($incomplete) { Write-Warning "$incomplete records incomplete; inspect report."; exit 3 }
    exit 0
} catch { Write-Error ('Export failed: '+$_.Exception.GetType().Name) -ErrorAction Continue; exit 4 }
