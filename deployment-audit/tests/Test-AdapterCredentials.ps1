#requires -Version 5.1
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../DeploymentAudit.psm1') -Force -DisableNameChecking
$module=Get-Module DeploymentAudit
& $module {
    $key='DEPLOYMENT_AUDIT_SYNTHETIC_TEST_TOKEN'
    $previous=[Environment]::GetEnvironmentVariable($key)
    try {
        $script:AuditManifest=[pscustomobject]@{security=[pscustomobject]@{}}
        [Environment]::SetEnvironmentVariable($key,'synthetic-test-value')
        function Invoke-RestMethod {
            param($Uri,$Method,$TimeoutSec,$MaximumRedirection,$ErrorAction,$Headers)
            if ($Headers.Authorization -ne 'Bearer synthetic-test-value') {throw 'Incorrect adapter authorization'}
            [pscustomobject]@{schemaVersion='1.0';capturedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');complete=$true;fields=[pscustomobject]@{running=$true}}
        }
        $item=[pscustomobject]@{type='HttpJson';url='https://adapter.example.invalid/status';bearerTokenEnvironmentVariable=$key}
        $record=New-AuditRecord 'synthetic-adapter' 'HttpJson'
        Collect-JsonSource $record $item
        if (($record | ConvertTo-Json -Depth 20) -match 'synthetic-test-value') {throw 'Credential leaked into snapshot'}
        Write-Host 'PASS Adapter reads credential from environment without exporting it (HTTP mocked)'
        [Environment]::SetEnvironmentVariable($key,$null)
        $failed=$false
        try {Collect-JsonSource (New-AuditRecord 'missing-credential' 'HttpJson') $item} catch {
            if ($_.Exception.Message -ne 'Missing adapter credential') {throw}
            $failed=$true
        }
        if (-not $failed) {throw 'Missing adapter credential was accepted'}
        Write-Host 'PASS Missing adapter credential rejected'
    } finally {
        [Environment]::SetEnvironmentVariable($key,$previous)
        $script:AuditManifest=$null
    }
}
