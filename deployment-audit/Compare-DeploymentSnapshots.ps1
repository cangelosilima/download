#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$Left,
    [string]$Right,
    [Parameter(Mandatory=$true)][string]$OutputHtml,
    [string]$OutputJson,
    [switch]$Open
)
$ErrorActionPreference='Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'DeploymentAudit.psm1') -Force -DisableNameChecking
    $policy=Read-AuditJson $Manifest; $a=Read-AuditJson $Left; $b=$null
    if ($Right) {$b=Read-AuditJson $Right}
    $report=Compare-AuditSnapshots $a $b $policy
    Write-AuditHtml $report $OutputHtml
    if ($OutputJson) {Write-AuditJson $report $OutputJson}
    Write-Host "Report: $OutputHtml"
    Write-Host ($report.summary | ConvertTo-Json -Compress)
    if ($Open) {Invoke-Item -LiteralPath $OutputHtml}
    exit $report.exitCode
} catch {Write-Error ('Comparison failed: '+$_.Exception.Message) -ErrorAction Continue; exit 4}
