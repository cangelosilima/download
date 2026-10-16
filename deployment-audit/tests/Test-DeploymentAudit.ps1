#requires -Version 5.1
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../DeploymentAudit.psm1') -Force -DisableNameChecking
$module=Get-Module DeploymentAudit
$script:count=0
function Assert-True([bool]$Condition,[string]$Message) {if (-not $Condition) {throw "FAILED: $Message"};$script:count++;Write-Host "PASS $Message"}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('audit-test-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $policy=[pscustomobject]@{schemaVersion='1.0';environments=@('DEV','OT');security=@{};collection=@{};items=@([pscustomobject]@{id='api';type='IIS';expected=@([pscustomobject]@{path='State';operator='Equals';value='Started'})});platformExpected=@();comparison=[pscustomobject]@{mappings=@([pscustomobject]@{item='api';path='Url';mode='Exact';canonical='<URL>';values=@{DEV='https://dev';OT='https://ot'};reason='Approved endpoint mapping'});ignore=@()}}
    $a=& $module {param($p) $script:AuditManifest=$p;New-AuditRecord 'api' 'IIS'} $policy
    $b=& $module {New-AuditRecord 'api' 'IIS'}
    & $module {param($a,$b)
        Add-AuditField $a 'Present' $true;Add-AuditField $b 'Present' $true
        Add-AuditField $a 'State' 'Started';Add-AuditField $b 'State' 'Stopped'
        Add-AuditField $a 'Url' 'https://dev';Add-AuditField $b 'Url' 'https://ot'
        Add-AuditField $a 'Config/Password' 'DO-NOT-EXPORT';Add-AuditField $b 'Config/Password' 'DO-NOT-EXPORT'
        Add-AuditField $a 'Nullable' $null
        Add-AuditField $a 'Typed' '1';Add-AuditField $b 'Typed' 1
        Add-AuditField $a 'Volatile' 2 $true;Add-AuditField $b 'Volatile' 99 $true
        Add-AuditField $a 'Hostile' '</script><img src=x onerror=alert(1)>';Add-AuditField $b 'Hostile' 'safe'
    } $a $b
    $stamp=[datetime]::UtcNow.ToString('o')
    $left=[pscustomobject]@{schemaVersion='1.0';environment='DEV';computerName='dev01';capturedAtUtc=$stamp;manifestHash='same';hmacKeyId=$null;records=@($a,(& $module {New-AuditRecord '_platform' 'Platform'}))}
    $right=[pscustomobject]@{schemaVersion='1.0';environment='OT';computerName='ot01';capturedAtUtc=$stamp;manifestHash='same';hmacKeyId=$null;records=@($b,(& $module {New-AuditRecord '_platform' 'Platform'}))}
    $report=Compare-AuditSnapshots $left $right $policy
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'Url' -and $_.status -eq 'Accepted'}).Count -eq 1) 'Scoped endpoint mapping'
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'State' -and $_.status -eq 'Drift'}).Count -eq 1) 'Runtime drift'
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'State' -and $_.status -eq 'Fail'}).Count -eq 1) 'Independent desired-state validation'
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'Config/Password' -and $_.status -eq 'Inconclusive'}).Count -eq 1) 'Redaction does not imply equality'
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'Nullable' -and $_.status -eq 'Drift'}).Count -eq 1) 'Null differs from missing'
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'Typed' -and $_.status -eq 'Drift'}).Count -eq 1) 'String and number differ'
    Assert-True (@($report.rows|Where-Object {$_.path -eq 'Volatile' -and $_.status -eq 'Informational'}).Count -eq 1) 'Volatile field preserved as information'
    Assert-True ((ConvertTo-Json $left -Depth 50) -notmatch 'DO-NOT-EXPORT') 'No plaintext secret exported'
    Write-AuditHtml $report (Join-Path $temp 'report.html')
    $html=[IO.File]::ReadAllText((Join-Path $temp 'report.html'))
    Assert-True (-not $html.Contains('</script><img')) 'HTML script injection escaped'
    Assert-True ($report.exitCode -eq 2) 'Failure exit code'
    $b.fields | Where-Object path -eq 'State' | ForEach-Object {$_.value='Started'}
    $a.fields | Where-Object path -eq 'State' | ForEach-Object {$_.value='Stopped'}
    $b.fields | Where-Object path -eq 'State' | ForEach-Object {$_.value='Stopped'}
    $r=Compare-AuditSnapshots $left $right $policy
    Assert-True (@($r.rows|Where-Object {$_.path -eq 'State' -and $_.status -eq 'Fail'}).Count -eq 2) 'Both equally wrong still fail'
    $b.status='Error';$r=Compare-AuditSnapshots $left $right $policy
    Assert-True (@($r.rows|Where-Object {$_.path -eq 'Nullable' -and $_.status -eq 'Inconclusive'}).Count -eq 1) 'Collection failure is not absence'
    $b.status='Collected'
    # HMAC must use a shared key and a matching identifier.
    $h1=& $module { $script:AuditHmacKey=[byte[]](1..32);$r=New-AuditRecord 'secret' 'Directory';Add-AuditField $r 'Password' 'abc';$r }
    $h2=& $module { $r=New-AuditRecord 'secret' 'Directory';Add-AuditField $r 'Password' 'abc';$script:AuditHmacKey=$null;$r }
    $left.records+=@($h1);$right.records+=@($h2);$left.hmacKeyId='key1';$right.hmacKeyId='key1'
    $r=Compare-AuditSnapshots $left $right $policy
    Assert-True (@($r.rows|Where-Object {$_.item -eq 'secret' -and $_.status -eq 'Equal'}).Count -eq 1) 'Same-key HMAC comparison'
    $right.hmacKeyId='key2';$r=Compare-AuditSnapshots $left $right $policy
    Assert-True (@($r.rows|Where-Object {$_.item -eq 'secret' -and $_.status -eq 'Inconclusive'}).Count -eq 1) 'Different HMAC key detected'
    $file=Join-Path $temp 'appsettings.json'
    [IO.File]::WriteAllText($file,'{ "Url":"https://example/a//b", /* comment */ "N":1, "A":[true,], // comment' + "`n" + '}')
    $parsed=Read-AuditJson $file
    Assert-True ($parsed.Url -ceq 'https://example/a//b' -and $parsed.A[0] -eq $true) 'JSON comments/trailing commas preserve strings'
    $xml=& $module {Read-SafeXml -Text '<configuration><appSettings><add key="Url" value="https://example"/><add key="Password" value="DO-NOT-EXPORT"/></appSettings></configuration>'}
    $xr=& $module {param($x) $r=New-AuditRecord 'xml' 'Directory';Add-XmlFields $r 'Config/web.config/configuration' $x.DocumentElement;$r} $xml
    Assert-True ((ConvertTo-Json $xr -Depth 50) -notmatch 'DO-NOT-EXPORT') 'XML secret key redacted'
    Assert-True (@($xr.fields | Where-Object path -like '*add(key=Url)/@value').Count -eq 1) 'Stable XML collection paths'
    $xxeBlocked=$false
    try { & $module {Read-SafeXml -Text '<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root>&x;</root>'} | Out-Null } catch {$xxeBlocked=$true}
    Assert-True $xxeBlocked 'XML external entities blocked'
    $dr=& $module {param($root) $script:AuditManifest=[pscustomobject]@{collection=@{maxConfigBytes=2097152};security=@{}};$r=New-AuditRecord 'files' 'Directory';Add-AppFiles $r $root ([pscustomobject]@{});$r} $temp
    Assert-True (@($dr.fields | Where-Object path -eq 'Config/appsettings.json/Url').Count -eq 1) 'Application directory config discovery'
    $aliased=& $module {param($root) $r=New-AuditRecord 'alias' 'Directory';Add-AppFiles $r $root ([pscustomobject]@{configFileAliases=@{'appsettings.json'='appsettings.logical.json'}});$r} $temp
    Assert-True (@($aliased.fields | Where-Object path -eq 'Config/appsettings.logical.json/Url').Count -eq 1) 'Environment file aliases'
    $cr=& $module {$r=New-AuditRecord 'connection' 'Directory';Add-ConnectionDetails $r 'appsettings.json' 'Main' 'Server=db-dev;Database=Orders;User ID=svc;Password=SYNTHETIC-DO-NOT-EXPORT';$r}
    Assert-True (@($cr.fields | Where-Object {$_.path -like '*/server' -and $_.value -eq 'db-dev'}).Count -eq 1) 'Nonsecret connection string metadata'
    Assert-True ((ConvertTo-Json $cr -Depth 50) -notmatch 'DO-NOT-EXPORT') 'Connection string password excluded'
    $missingPolicy=Read-AuditJson (Join-Path $PSScriptRoot '../manifest.example.json');Test-AuditManifest $missingPolicy 'OT'
    Assert-True ($true) 'Example manifest schema'
    $override=& $module {param($p) Resolve-AuditItem $p.items[0] 'OT'} $missingPolicy
    Assert-True ($override.site -ceq 'Trading-OT') 'Environment override resolution'
    $right.capturedAtUtc='2000-01-01T00:00:00Z';$r=Compare-AuditSnapshots $left $right $policy
    Assert-True (@($r.rows | Where-Object {$_.path -eq 'CapturedAtUtc' -and $_.status -eq 'Inconclusive'}).Count -eq 1) 'Stale snapshot detected'
    $right.records+=@($b);$duplicateBlocked=$false
    try {Compare-AuditSnapshots $left $right $policy|Out-Null} catch {$duplicateBlocked=$true}
    Assert-True $duplicateBlocked 'Duplicate record IDs rejected'
    Write-Host "All $script:count checks passed. Windows collectors require separate Windows smoke testing."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
