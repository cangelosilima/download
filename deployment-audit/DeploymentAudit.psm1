#requires -Version 5.1
# No module import performs collection or changes server configuration.
$ErrorActionPreference = 'Stop'

function Read-AuditJson {
    param([string]$Path)
    $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path)
    # JSON with comments/trailing commas: remove outside strings only.
    $b = New-Object Text.StringBuilder
    $inString = $false; $escape = $false
    for ($i=0; $i -lt $text.Length; $i++) {
        $c = $text[$i]
        if ($inString) {
            [void]$b.Append($c)
            if ($escape) { $escape=$false } elseif ($c -eq '\') { $escape=$true } elseif ($c -eq '"') { $inString=$false }
            continue
        }
        if ($c -eq '"') { $inString=$true; [void]$b.Append($c); continue }
        if ($c -eq '/' -and $i+1 -lt $text.Length -and $text[$i+1] -eq '/') {
            while ($i -lt $text.Length -and $text[$i] -ne "`n") { $i++ }; [void]$b.Append("`n"); continue
        }
        if ($c -eq '/' -and $i+1 -lt $text.Length -and $text[$i+1] -eq '*') {
            $i+=2
            while ($i+1 -lt $text.Length -and -not ($text[$i] -eq '*' -and $text[$i+1] -eq '/')) { $i++ }
            if ($i+1 -ge $text.Length) { throw 'Unterminated JSON comment' }
            $i++; [void]$b.Append(' '); continue
        }
        if ($c -eq ',') {
            $j=$i+1; while ($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])) { $j++ }
            # A second pass handles comments between comma and closing bracket.
        }
        [void]$b.Append($c)
    }
    $text=$b.ToString(); $b=New-Object Text.StringBuilder; $inString=$false; $escape=$false
    for ($i=0; $i -lt $text.Length; $i++) {
        $c=$text[$i]
        if ($inString) {
            [void]$b.Append($c)
            if ($escape) { $escape=$false } elseif ($c -eq '\') { $escape=$true } elseif ($c -eq '"') { $inString=$false }
        } else {
            if ($c -eq '"') { $inString=$true }
            if ($c -eq ',') {
                $j=$i+1; while ($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])) { $j++ }
                if ($j -lt $text.Length -and ($text[$j] -eq '}' -or $text[$j] -eq ']')) { continue }
            }
            [void]$b.Append($c)
        }
    }
    ConvertFrom-Json -InputObject $b.ToString() -ErrorAction Stop
}
function Write-AuditJson {
    param($Object,[string]$Path)
    $full=[IO.Path]::GetFullPath($Path); [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full))
    [IO.File]::WriteAllText($full, (ConvertTo-Json -InputObject $Object -Depth 90), (New-Object Text.UTF8Encoding($false)))
}
function Get-HashText {
    param([string]$Text)
    $h=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
}
function Get-PropertyValue {
    param($Object,[string]$Name,$Default=$null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } }
    elseif ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}
function Resolve-AuditItem {
    param($Item,[string]$Environment)
    $r=[ordered]@{}
    foreach ($p in $Item.PSObject.Properties) { if ($p.Name -ne 'environments') { $r[$p.Name]=$p.Value } }
    $override=Get-PropertyValue (Get-PropertyValue $Item 'environments') $Environment
    if ($override) { foreach ($p in $override.PSObject.Properties) { $r[$p.Name]=$p.Value } }
    [pscustomobject]$r
}
function Test-AuditManifest {
    param($Manifest,[string]$Environment)
    if ($Manifest.schemaVersion -ne '1.0') { throw 'Manifest schemaVersion must be 1.0' }
    if ($Environment -and $Environment -cnotin @($Manifest.environments)) { throw "Environment is not declared: $Environment" }
    if (-not $Manifest.items -and -not $Manifest.platformExpected) {throw 'Manifest must declare items or platform expectations'}
    $seen=@{}
    foreach ($item in @($Manifest.items)) {
        if (-not $item.id -or $item.id -eq '_platform' -or $seen.ContainsKey($item.id)) { throw 'Each item needs a unique, nonempty id (case insensitive).' }
        $seen[$item.id]=$true
        if ($item.type -notin @('IIS','Service','Task','MSMQ','Certificate','Directory','JsonFile','HttpJson')) { throw "Unsupported type: $($item.type)" }
    }
    foreach ($rule in @($Manifest.comparison.mappings)) {
        if ($rule -and ($rule.mode -notin @('Exact','LiteralReplace') -or -not $rule.reason -or -not $rule.canonical)) { throw 'Mappings require mode, reason and nonempty canonical.' }
    }
}
function New-AuditRecord {
    param([string]$Id,[string]$Type)
    [pscustomobject][ordered]@{id=$Id; type=$Type; status='Collected'; fields=(New-Object Collections.Generic.List[object]); issues=(New-Object Collections.Generic.List[object])}
}
function Add-AuditIssue {
    param($Record,[string]$Scope,[string]$Code='CollectionError')
    # Do not export exception messages: they may contain connection strings or credentials.
    $Record.issues.Add([pscustomobject]@{scope=$Scope; code=$Code})
    if ($Record.status -eq 'Collected') { $Record.status='Partial' }
}
function Escape-AuditSegment { param([string]$Value) $Value.Replace('~','~0').Replace('/','~1') }
function Add-AuditField {
    param($Record,[string]$Path,$Value,[bool]$Volatile=$false,[bool]$Sensitive=$false)
    if (@($Record.fields | Where-Object { $_.path -ceq $Path }).Count) { throw "Duplicate field: $Path" }
    if ($Value -is [Enum] -or $Value -is [TimeSpan]) { $Value=[string]$Value }
    $kind=if ($null -eq $Value) {'Null'} elseif ($Value -is [bool]) {'Boolean'} elseif ($Value -is [ValueType] -and $Value -isnot [datetime]) {'Number'} else {'String'}
    if ($Value -is [datetime]) { $Value=$Value.ToUniversalTime().ToString('o') }
    if ($kind -eq 'String' -and $null -ne $Value) { $Value=[string]$Value }
    $patterns=@('(?i)(password|passwd|pwd|secret|token|api[-_]?key|private[-_]?key|credential|authorization|connectionstrings|connectionstring|arguments|commandline)')
    if ($script:AuditManifest) { $patterns+=@($script:AuditManifest.security.sensitivePathRegex) }
    foreach ($pattern in $patterns) { if ($pattern -and $Path -match $pattern) { $Sensitive=$true } }
    if ($Value -is [string] -and $Value -match '(?i)(password\s*=|pwd\s*=|[?&](token|key|sig|secret)=|://[^/\s]+:[^/@\s]+@|Bearer\s+)') { $Sensitive=$true }
    $protection='None'
    if ($Sensitive) {
        if ($script:AuditHmacKey) {
            $h=New-Object Security.Cryptography.HMACSHA256
            try { $h.Key=$script:AuditHmacKey; $Value=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Compress))))).Replace('-','').ToLowerInvariant() } finally { $h.Dispose() }
            $protection='HMAC-SHA256'
        } else { $Value='[REDACTED]'; $protection='Redacted' }
    }
    $Record.fields.Add([pscustomobject][ordered]@{path=$Path; value=$Value; valueType=$kind; protection=$protection; volatile=$Volatile})
}
function Add-FlatObject {
    param($Record,[string]$Path,$Value,[int]$Depth=0)
    if ($Depth -gt 60) { throw 'Maximum configuration depth exceeded' }
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { Add-AuditField $Record $Path $Value; return }
    if ($Value -is [Collections.IDictionary]) {
        if ($Value.Count -eq 0) { Add-AuditField $Record "$Path/~emptyObject" $true }
        foreach ($key in $Value.Keys) { Add-FlatObject $Record "$Path/$(Escape-AuditSegment $key)" $Value[$key] ($Depth+1) }
    } elseif ($Value -is [Collections.IEnumerable]) {
        $n=0; foreach ($v in $Value) { Add-FlatObject $Record "$Path/$n" $v ($Depth+1); $n++ }
        Add-AuditField $Record "$Path/~arrayLength" $n
    } else {
        $props=@($Value.PSObject.Properties)
        if (-not $props.Count) { Add-AuditField $Record "$Path/~emptyObject" $true }
        foreach ($p in $props) { Add-FlatObject $Record "$Path/$(Escape-AuditSegment $p.Name)" $p.Value ($Depth+1) }
    }
}
function Read-SafeXml {
    param([string]$Path,[string]$Text)
    $settings=New-Object Xml.XmlReaderSettings; $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null
    if ($Path) { $reader=[Xml.XmlReader]::Create($Path,$settings) } else { $reader=[Xml.XmlReader]::Create((New-Object IO.StringReader($Text)),$settings) }
    try { $doc=New-Object Xml.XmlDocument; $doc.XmlResolver=$null; $doc.Load($reader); return ,$doc } finally { $reader.Dispose() }
}
function Add-XmlFields {
    param($Record,[string]$Path,[Xml.XmlElement]$Node)
    foreach ($attr in $Node.Attributes) { Add-AuditField $Record "$Path/@$(Escape-AuditSegment $attr.Name)" $attr.Value }
    $children=@($Node.ChildNodes | Where-Object { $_ -is [Xml.XmlElement] })
    if (-not $children.Count) { Add-AuditField $Record "$Path/#text" $Node.InnerText; return }
    # Preserve element order as separate evidence: some .NET collections are order sensitive.
    $order=@($children | ForEach-Object {
        $label=$_.Name
        foreach ($key in @('key','name','path','id')) {if ($_.HasAttribute($key)) {$label+='('+ $key +'='+ $_.GetAttribute($key) +')';break}}
        $label
    })
    Add-AuditField $Record "$Path/~elementOrder" ($order -join "`n")
    # key/name/path identify entries; unnamed siblings retain their ordinal.
    $seen=@{}
    foreach ($child in $children) {
        $segment=$child.Name; $identity=$null
        foreach ($key in @('key','name','path','id')) { if ($child.HasAttribute($key)) { $identity="$key=$($child.GetAttribute($key))"; break } }
        if ($null -ne $identity) { $segment+='('+ $identity +')' }
        else { if (-not $seen.ContainsKey($segment)) {$seen[$segment]=0}; $seen[$segment]++; $segment+='('+ $seen[$child.Name] +')' }
        Add-XmlFields $Record "$Path/$(Escape-AuditSegment $segment)" $child
    }
}
function Add-AuditAcl {
    param($Record,[string]$Path,[string]$Prefix='Acl')
    try {
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        Add-AuditField $Record "$Prefix/Owner" $acl.Owner
        Add-AuditField $Record "$Prefix/Protected" $acl.AreAccessRulesProtected
        Add-AuditField $Record "$Prefix/Sddl" $acl.Sddl
        $rules=@($acl.Access | ForEach-Object {
            "$($_.IdentityReference.Value)|$($_.AccessControlType)|$($_.FileSystemRights)|$($_.InheritanceFlags)|$($_.PropagationFlags)|$($_.IsInherited)"
        } | Sort-Object)
        Add-AuditField $Record "$Prefix/Rules" ($rules -join "`n")
    } catch { Add-AuditIssue $Record $Prefix 'AclUnavailable' }
}
function Get-AppRoot {
    param([string]$CommandLine,[string]$Override)
    if ($Override) { return [Environment]::ExpandEnvironmentVariables($Override) }
    $line=[Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    # DLL hosting via dotnet; quoted and unquoted absolute paths supported.
    if ($line -match '(?i)^"?[^\r\n]*?dotnet(?:\.exe)?"?\s+(?:exec\s+)?(?:"(?<dll>[^"]+\.dll)"|(?<dll>\S+\.dll))') {
        if ([IO.Path]::IsPathRooted($Matches.dll)) { return Split-Path -Parent $Matches.dll }
        return $null # Relative host arguments cannot safely determine the working directory.
    }
    if ($line -match '^"(?<exe>[^"]+)"') { return Split-Path -Parent $Matches.exe }
    if ($line -match '^(?<exe>[^\s]+\.exe)(?:\s|$)') { return Split-Path -Parent $Matches.exe }
    return $null # Unquoted paths with spaces are ambiguous; require applicationRoot.
}
function Add-ConnectionDetails {
    param($Record,[string]$File,[string]$Name,$ConnectionString)
    if ($ConnectionString -isnot [string]) {return}
    try {
        $builder=New-Object System.Data.Common.DbConnectionStringBuilder
        $builder.set_ConnectionString($ConnectionString)
        $allow=@('server','data source','address','addr','network address','database','initial catalog','integrated security','trusted_connection','encrypt','trustservercertificate','port','host','service name','user id','uid','username','application name','connect timeout','connection timeout','pooling','min pool size','max pool size','multipleactiveresultsets')
        foreach ($key in $builder.Keys) {
            if ($key.ToLowerInvariant() -in $allow) {Add-AuditField $Record "ConnectionDetails/$(Escape-AuditSegment $File)/$(Escape-AuditSegment $Name)/$(Escape-AuditSegment $key.ToLowerInvariant())" $builder[$key]}
        }
    } catch {Add-AuditIssue $Record 'ConnectionDetails' 'ConnectionStringDetailsUnavailable'}
}
function Add-AppFiles {
    param($Record,[string]$Root,$Item)
    if (-not $Root) { Add-AuditIssue $Record 'Deployment/Root' 'ApplicationRootUnresolved'; return }
    $Root=[Environment]::ExpandEnvironmentVariables($Root)
    Add-AuditField $Record 'Deployment/Root' $Root
    if (-not (Test-Path -LiteralPath $Root -PathType Container -ErrorAction Stop)) { Add-AuditIssue $Record 'Deployment/Root' 'DirectoryMissing'; return }
    Add-AuditAcl $Record $Root 'Deployment/Acl'
    $patterns=@('appsettings*.json','*.config','*.runtimeconfig.json') + @($Item.configPatterns)
    $files=@{}; $max=Get-PropertyValue $script:AuditManifest.collection 'maxConfigBytes' 2097152
    try {
        $dirs=New-Object Collections.Generic.Queue[string];$dirs.Enqueue($Root)
        $maxFiles=Get-PropertyValue $script:AuditManifest.collection 'maxConfigFiles' 1000
        while ($dirs.Count -gt 0) {
            $dir=$dirs.Dequeue()
            foreach ($entry in Get-ChildItem -LiteralPath $dir -ErrorAction Stop) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Add-AuditIssue $Record 'Config' 'ReparsePointSkipped';continue
                }
                if ($entry.PSIsContainer) {if ($Item.recurseConfig) {$dirs.Enqueue($entry.FullName)};continue}
                foreach ($pattern in $patterns) {if ($pattern -and $entry.Name -like $pattern) {$files[$entry.FullName]=$entry;break}}
                if ($files.Count -gt $maxFiles) {throw 'Configuration file limit exceeded'}
            }
        }
    } catch { Add-AuditIssue $Record 'Config' 'DirectoryEnumerationFailed' }
    $queue=New-Object Collections.Generic.Queue[string]
    foreach ($file in $files.Values) { $queue.Enqueue($file.FullName) }
    $visited=@{}; $rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    while ($queue.Count -gt 0) {
        $path=$queue.Dequeue(); if ($visited.ContainsKey($path)) { continue }; $visited[$path]=$true
        $relative=$path.Substring($rootFull.Length).Replace('\','/')
        $logical=Get-PropertyValue $Item.configFileAliases $relative $relative
        $prefix='Config/'+(Escape-AuditSegment $logical)
        Add-AuditField $Record ('ConfigSources/'+(Escape-AuditSegment $logical)) $relative
        try {
            $f=Get-Item -LiteralPath $path -ErrorAction Stop
            if (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Add-AuditIssue $Record $prefix 'ReparsePointSkipped'; continue }
            if ($f.Length -gt $max) { Add-AuditIssue $Record $prefix 'FileSizeLimit'; continue }
            Add-AuditField $Record "$prefix/~present" $true
            Add-AuditAcl $Record $path "ConfigAcl/$(Escape-AuditSegment $logical)"
            if ($f.Extension -ieq '.json') {
                $data=Read-AuditJson $path; Add-FlatObject $Record $prefix $data
                if ($data.ConnectionStrings) {foreach ($p in $data.ConnectionStrings.PSObject.Properties) {Add-ConnectionDetails $Record $logical $p.Name $p.Value}}
            }
            else {
                $xml=Read-SafeXml -Path $path
                Add-XmlFields $Record "$prefix/$($xml.DocumentElement.Name)" $xml.DocumentElement
                foreach ($n in $xml.SelectNodes('//connectionStrings/add[@connectionString]')) {Add-ConnectionDetails $Record $logical $n.GetAttribute('name') $n.GetAttribute('connectionString')}
                foreach ($node in $xml.SelectNodes('//*[@configSource or @file]')) {
                    if ($node.HasAttribute('configProtectionProvider')) { Add-AuditIssue $Record $prefix 'EncryptedSectionNotDecrypted' }
                    foreach ($attrName in @('configSource','file')) {
                        $ref=$node.GetAttribute($attrName); if (-not $ref) { continue }
                        $external=[IO.Path]::GetFullPath((Join-Path $f.DirectoryName $ref))
                        if (-not $external.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)) { Add-AuditIssue $Record $prefix 'ExternalConfigOutsideRoot'; continue }
                        $queue.Enqueue($external)
                    }
                }
                foreach ($node in $xml.SelectNodes('//*[@configProtectionProvider]')) { Add-AuditIssue $Record $prefix 'EncryptedSectionNotDecrypted' }
            }
        } catch { Add-AuditIssue $Record $prefix 'ConfigReadOrParseFailed' }
    }
    Add-AuditField $Record 'Deployment/ConfigFilesFound' $visited.Count
    if ($visited.Count -eq 0 -and -not $Item.allowNoConfig) { Add-AuditIssue $Record 'Config' 'NoConfigurationFiles' }
    foreach ($relative in @($Item.binaryFiles)) {
        if (-not $relative) { continue }
        try {
            $path=[IO.Path]::GetFullPath((Join-Path $Root $relative))
            if (-not $path.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)) { throw 'Binary outside root' }
            $f=Get-Item -LiteralPath $path -ErrorAction Stop
            $prefix='Binary/'+(Escape-AuditSegment $relative)
            Add-AuditField $Record "$prefix/FileVersion" $f.VersionInfo.FileVersion
            Add-AuditField $Record "$prefix/ProductVersion" $f.VersionInfo.ProductVersion
            Add-AuditField $Record "$prefix/SHA256" (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        } catch { Add-AuditIssue $Record "Binary/$relative" 'BinaryReadFailed' }
    }
}
function Add-SelectedProperties {
    param($Record,[string]$Prefix,$Object,[string[]]$Names,[bool]$Volatile=$false)
    foreach ($name in $Names) {
        if ($null -ne $Object -and $Object.PSObject.Properties[$name]) { Add-AuditField $Record "$Prefix/$name" $Object.$name $Volatile }
        else {Add-AuditIssue $Record "$Prefix/$name" 'PropertyUnavailable'}
    }
}
function Add-HealthProbe {
    param($Record,$Health)
    if (-not $Health -or -not $Health.url) { return }
    Add-AuditField $Record 'Health/Url' $Health.url
    try {
        $p=@{Uri=$Health.url;Method='Get';UseBasicParsing=$true;TimeoutSec=15;MaximumRedirection=0;ErrorAction='Stop'}
        if ($Health.useDefaultCredentials) { $p.UseDefaultCredentials=$true }
        $response=Invoke-WebRequest @p
        Add-AuditField $Record 'Health/StatusCode' ([int]$response.StatusCode)
        $accepted=@(Get-PropertyValue $Health 'expectedStatusCodes' @(200))
        Add-AuditField $Record 'Health/Success' ([int]$response.StatusCode -in $accepted)
    } catch { Add-AuditField $Record 'Health/Success' $false; Add-AuditIssue $Record 'Health' 'HttpOrTlsFailure' }
}
function Collect-Service {
    param($Record,$Item)
    $services=@(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -ieq $Item.name })
    Add-AuditField $Record 'Present' ($services.Count -eq 1)
    if ($services.Count -ne 1) { $Record.status='Missing'; return }
    $s=$services[0]
    Add-SelectedProperties $Record 'Service' $s @('Name','DisplayName','State','StartMode','StartName','ServiceType','ExitCode')
    Add-SelectedProperties $Record 'Service' $s @('ProcessId') $true
    $reg=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -ErrorAction Stop
    Add-AuditField $Record 'Service/DelayedAutoStart' ([bool]$reg.DelayedAutoStart)
    Add-AuditField $Record 'Service/Dependencies' (@($reg.DependOnService | Sort-Object) -join "`n")
    foreach ($entry in @($reg.Environment)) {
        if ($entry -match '^([^=]+)=(.*)$') { Add-AuditField $Record "Service/Environment/$(Escape-AuditSegment $Matches[1])" $Matches[2] }
    }
    try {
        $sddl=& "$env:SystemRoot\System32\sc.exe" sdshow $s.Name 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'sc failed' }
        Add-AuditField $Record 'Service/Sddl' (($sddl | Where-Object { $_ -match '^[OGDS]:' }) -join '')
    } catch { Add-AuditIssue $Record 'Service/Sddl' 'SecurityDescriptorUnavailable' }
    # PathName may contain command-line credentials; protect entire field.
    Add-AuditField $Record 'Service/CommandLine' $s.PathName $false $true
    Add-AppFiles $Record (Get-AppRoot $s.PathName $Item.applicationRoot) $Item
    Add-HealthProbe $Record $Item.health
}
function Collect-IIS {
    param($Record,$Item)
    $dll=Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $dll)) { throw 'IIS management API unavailable' }
    Add-Type -Path $dll -ErrorAction Stop
    $manager=New-Object Microsoft.Web.Administration.ServerManager
    try {
        $site=$manager.Sites[$Item.site]
        $app=$null; if ($site) { $app=$site.Applications[$Item.applicationPath] }
        Add-AuditField $Record 'Present' ($null -ne $app)
        if (-not $app) { $Record.status='Missing'; return }
        Add-AuditField $Record 'IIS/Site' $site.Name
        Add-AuditField $Record 'IIS/SiteState' ([string]$site.State)
        Add-AuditField $Record 'IIS/ApplicationPath' $app.Path
        Add-AuditField $Record 'IIS/Pool' $app.ApplicationPoolName
        Add-AuditField $Record 'IIS/EnabledProtocols' $app.EnabledProtocols
        $pool=$manager.ApplicationPools[$app.ApplicationPoolName]
        if ($null -eq $pool) { Add-AuditIssue $Record 'IIS/Pool' 'PoolMissing' }
        else {
            Add-AuditField $Record 'IIS/PoolState' ([string]$pool.State)
            Add-SelectedProperties $Record 'IIS/PoolSettings' $pool @('ManagedRuntimeVersion','ManagedPipelineMode','Enable32BitAppOnWin64','AutoStart','StartMode')
            Add-SelectedProperties $Record 'IIS/ProcessModel' $pool.ProcessModel @('IdentityType','UserName','LoadUserProfile','IdleTimeout','MaxProcesses','PingInterval','PingingEnabled')
            $identity=switch ([string]$pool.ProcessModel.IdentityType) {
                'ApplicationPoolIdentity' { 'IIS AppPool\'+$pool.Name }
                'SpecificUser' {$pool.ProcessModel.UserName}
                'LocalSystem' {'NT AUTHORITY\SYSTEM'}
                'LocalService' {'NT AUTHORITY\LOCAL SERVICE'}
                'NetworkService' {'NT AUTHORITY\NETWORK SERVICE'}
            }
            Add-AuditField $Record 'IIS/Identity' $identity
            Add-AuditField $Record 'IIS/Recycling/RegularInterval' ([string]$pool.Recycling.PeriodicRestart.Time)
            Add-AuditField $Record 'IIS/Recycling/Schedule' (@($pool.Recycling.PeriodicRestart.Schedule | ForEach-Object { [string]$_.Value } | Sort-Object) -join "`n")
            try { foreach ($e in $pool.GetCollection('environmentVariables')) { Add-AuditField $Record "IIS/Environment/$(Escape-AuditSegment $e.GetAttributeValue('name'))" $e.GetAttributeValue('value') } } catch { Add-AuditIssue $Record 'IIS/Environment' 'PoolEnvironmentUnavailable' }
        }
        $bindingOrdinal=@{}
        foreach ($binding in @($site.Bindings | Sort-Object Protocol,BindingInformation)) {
            # Bindings indexed by protocol + sorted ordinal; entire binding info remains visible for scoped mappings.
            if (-not $bindingOrdinal.ContainsKey($binding.Protocol)) {$bindingOrdinal[$binding.Protocol]=0}
            $key='IIS/Bindings/'+$binding.Protocol+'/'+$bindingOrdinal[$binding.Protocol]
            $bindingOrdinal[$binding.Protocol]++
            Add-AuditField $Record "$key/BindingInformation" $binding.BindingInformation
            if ($binding.Protocol -eq 'https') {
                $thumb=([BitConverter]::ToString($binding.CertificateHash)).Replace('-','')
                Add-AuditField $Record "$key/Thumbprint" $thumb
                Add-AuditField $Record "$key/Store" $binding.CertificateStoreName
                Add-AuditField $Record "$key/SslFlags" ([string]$binding.SslFlags)
            }
        }
        foreach ($vdir in $app.VirtualDirectories) {
            Add-AuditField $Record "IIS/VirtualDirectories/$(Escape-AuditSegment $vdir.Path)/PhysicalPath" $vdir.PhysicalPath
            Add-AuditField $Record "IIS/VirtualDirectories/$(Escape-AuditSegment $vdir.Path)/UserName" $vdir.UserName
        }
        # Effective inherited IIS settings, selected allowlist (never dump applicationHost.config).
        $wc=$manager.GetWebConfiguration($site.Name,$app.Path)
        foreach ($sectionPath in @('system.webServer/security/authentication/anonymousAuthentication','system.webServer/security/authentication/windowsAuthentication','system.webServer/security/authentication/basicAuthentication')) {
            try { $section=$wc.GetSection($sectionPath); Add-AuditField $Record "IIS/Effective/$sectionPath/enabled" $section.GetAttributeValue('enabled') } catch { Add-AuditIssue $Record "IIS/Effective/$sectionPath" 'SectionUnavailable' }
        }
        try { Add-AuditField $Record 'IIS/Effective/sslFlags' ([string]$wc.GetSection('system.webServer/security/access').GetAttributeValue('sslFlags')) } catch { Add-AuditIssue $Record 'IIS/Effective/sslFlags' 'SectionUnavailable' }
        $root=$app.VirtualDirectories['/'].PhysicalPath
        if ($Item.applicationRoot) { $root=$Item.applicationRoot }
        Add-AppFiles $Record ([Environment]::ExpandEnvironmentVariables($root)) $Item
        Add-HealthProbe $Record $Item.health
    } finally { $manager.Dispose() }
}
function Collect-Task {
    param($Record,$Item)
    Import-Module ScheduledTasks -ErrorAction Stop
    $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ieq $Item.name -and $_.TaskPath -ieq $Item.taskPath })
    Add-AuditField $Record 'Present' ($tasks.Count -eq 1)
    if ($tasks.Count -ne 1) { $Record.status='Missing'; return }
    $task=$tasks[0]
    Add-AuditField $Record 'Task/State' ([string]$task.State) $true
    Add-AuditField $Record 'Task/Enabled' $task.Settings.Enabled
    Add-SelectedProperties $Record 'Task/Principal' $task.Principal @('UserId','GroupId','LogonType','RunLevel')
    $xml=Read-SafeXml -Text (Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
    foreach ($node in $xml.DocumentElement.ChildNodes) {
        if ($node -is [Xml.XmlElement] -and $node.LocalName -in @('Triggers','Settings','Actions','Principals')) { Add-XmlFields $Record "Task/Definition/$($node.LocalName)" $node }
    }
    $info=Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
    Add-SelectedProperties $Record 'Task/Runtime' $info @('LastTaskResult','LastRunTime','NextRunTime','NumberOfMissedRuns') $true
    try {
        $scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
        $registered=$scheduler.GetFolder($task.TaskPath).GetTask($task.TaskName)
        Add-AuditField $Record 'Task/Sddl' $registered.GetSecurityDescriptor(7)
    } catch { Add-AuditIssue $Record 'Task/Sddl' 'SecurityDescriptorUnavailable' }
    $root=$Item.applicationRoot
    if (-not $root -and @($task.Actions).Count -eq 1) {
        $action=$task.Actions[0]
        if ($action.WorkingDirectory) { $root=[Environment]::ExpandEnvironmentVariables($action.WorkingDirectory) }
        elseif ([IO.Path]::GetFileNameWithoutExtension($action.Execute) -notin @('powershell','pwsh','cmd','wscript','cscript')) { $root=Get-AppRoot ('"'+$action.Execute+'" '+$action.Arguments) $null }
    }
    if ($root -or $Item.collectConfig) { Add-AppFiles $Record $root $Item }
}
function Collect-MSMQ {
    param($Record,$Item)
    Import-Module MSMQ -ErrorAction Stop
    $queues=@(Get-MsmqQueue -QueueType $Item.queueType -ErrorAction Stop | Where-Object { ([string]$_.QueueName -replace '^[^\\]+\\(?=private\$\\)','') -ieq ([string]$Item.name -replace '^[^\\]+\\(?=private\$\\)','') })
    Add-AuditField $Record 'Present' ($queues.Count -eq 1)
    if ($queues.Count -ne 1) { $Record.status='Missing'; return }
    $q=$queues[0]
    Add-SelectedProperties $Record 'Queue' $q @('QueueName','Path','Transactional','Label','UseJournalQueue','MaximumQueueSize','MaximumJournalSize','Authenticate','PrivacyLevel')
    Add-SelectedProperties $Record 'Queue' $q @('MessageCount','JournalMessageCount') $true
    $service=Get-Service -Name MSMQ -ErrorAction Stop
    Add-AuditField $Record 'Queue/ServiceState' ([string]$service.Status)
    try {
        $acl=@($q | Get-MsmqQueueACL -ErrorAction Stop)
        # Serialized primitive ACL properties only; do not invoke any queue read/receive operation.
        $rows=@($acl | ForEach-Object { ($_ | Select-Object * -ExcludeProperty PSComputerName,RunspaceId,PSShowComputerName | ConvertTo-Json -Depth 8 -Compress) } | Sort-Object)
        Add-AuditField $Record 'Queue/Acl' ($rows -join "`n")
    } catch { Add-AuditIssue $Record 'Queue/Acl' 'AclUnavailable' }
}
function Collect-Certificate {
    param($Record,$Item)
    $thumb=($Item.thumbprint -replace '\s','').ToUpperInvariant()
    if ($thumb -notmatch '^[A-F0-9]{40}$') { throw 'Certificate thumbprint must have 40 hexadecimal digits' }
    $cert=Get-ChildItem -LiteralPath "Cert:\LocalMachine\$($Item.store)" -ErrorAction Stop | Where-Object Thumbprint -EQ $thumb | Select-Object -First 1
    Add-AuditField $Record 'Present' ($null -ne $cert)
    if (-not $cert) { $Record.status='Missing'; return }
    Add-SelectedProperties $Record 'Certificate' $cert @('Subject','Issuer','Thumbprint','HasPrivateKey','NotBefore','NotAfter')
    Add-AuditField $Record 'Certificate/ValidNow' ($cert.NotBefore -le (Get-Date) -and $cert.NotAfter -gt (Get-Date))
    Add-AuditField $Record 'Certificate/DaysRemaining' ([int][Math]::Floor(($cert.NotAfter-(Get-Date)).TotalDays)) $true
    Add-AuditField $Record 'Certificate/DnsNames' (@($cert.DnsNameList | ForEach-Object { $_.Unicode } | Sort-Object) -join "`n")
    Add-AuditField $Record 'Certificate/Eku' (@($cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value } | Sort-Object) -join "`n")
    if ($cert.HasPrivateKey) {
        $key=$null
        try {
            $key=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            $path=$null
            if ($key -is [Security.Cryptography.RSACryptoServiceProvider]) { $path=Join-Path $env:ProgramData ('Microsoft\Crypto\RSA\MachineKeys\'+$key.CspKeyContainerInfo.UniqueKeyContainerName) }
            elseif ($key -is [Security.Cryptography.RSACng]) { $path=Join-Path $env:ProgramData ('Microsoft\Crypto\Keys\'+$key.Key.UniqueName) }
            if ($path -and (Test-Path -LiteralPath $path)) { Add-AuditAcl $Record $path 'Certificate/PrivateKeyAcl' }
            else { Add-AuditIssue $Record 'Certificate/PrivateKeyAcl' 'KeyProviderNotFileBackedOrUnsupported' }
        } catch { Add-AuditIssue $Record 'Certificate/PrivateKeyAcl' 'PrivateKeyAclUnavailable' }
        finally { if ($key) {$key.Dispose()} }
    }
}
function Collect-JsonSource {
    param($Record,$Item)
    if ($Item.type -eq 'JsonFile') {
        $path=[Environment]::ExpandEnvironmentVariables($Item.path)
        $present=Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop
        Add-AuditField $Record 'Present' $present
        if (-not $present) { $Record.status='Missing'; return }
        $data=Read-AuditJson $path
    } else {
        $uri=[uri]$Item.url
        if ($uri.Scheme -ne 'https' -and $uri.Host -notin @('localhost','127.0.0.1','::1')) { throw 'Remote adapters require HTTPS' }
        $p=@{Uri=$Item.url;Method='Get';TimeoutSec=20;MaximumRedirection=0;ErrorAction='Stop'}
        if ($Item.useDefaultCredentials) { $p.UseDefaultCredentials=$true }
        if ($Item.bearerTokenEnvironmentVariable) {
            $token=[Environment]::GetEnvironmentVariable($Item.bearerTokenEnvironmentVariable)
            if (-not $token) { throw 'Missing adapter credential' }
            $p.Headers=@{Authorization='Bearer '+$token}
        }
        $data=Invoke-RestMethod @p
        Add-AuditField $Record 'Present' $true
    }
    # Require canonical envelope for state, freshness and completeness. Never accept an old export as live evidence.
    if ($data.schemaVersion -ne '1.0' -or -not $data.capturedAtUtc -or -not $data.fields -or $data.complete -isnot [bool]) { throw 'Adapter envelope invalid' }
    $captured=[DateTimeOffset]::Parse($data.capturedAtUtc)
    $age=([DateTimeOffset]::UtcNow-$captured).TotalMinutes
    Add-AuditField $Record 'Adapter/AgeMinutes' ([Math]::Round($age,2)) $true
    $fresh=$age -ge -5 -and $age -le (Get-PropertyValue $Item 'maxAgeMinutes' 30)
    Add-AuditField $Record 'Adapter/Fresh' $fresh
    Add-AuditField $Record 'Adapter/Complete' ([bool]$data.complete)
    if (-not $fresh) { Add-AuditIssue $Record 'Adapter' 'StaleEvidence' }
    if (-not $data.complete) { Add-AuditIssue $Record 'Adapter' 'IncompleteEvidence' }
    Add-FlatObject $Record 'Adapter/Fields' $data.fields
}
function Collect-Platform {
    param($Record,$Manifest)
    try {
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        Add-SelectedProperties $Record 'OS' $os @('Caption','Version','BuildNumber','OSArchitecture')
        Add-SelectedProperties $Record 'OS' $os @('LastBootUpTime') $true
    } catch { Add-AuditIssue $Record 'OS' }
    if ($Manifest.collection.windowsFeatures) {
        try {
            Import-Module ServerManager -ErrorAction Stop
            foreach ($feature in Get-WindowsFeature -ErrorAction Stop) { Add-AuditField $Record "Features/$($feature.Name)" ([string]$feature.InstallState) }
        } catch { Add-AuditIssue $Record 'Features' 'WindowsFeaturesUnavailable' }
    }
    if ($Manifest.collection.software) {
        # Registry inventory avoids Win32_Product MSI consistency checks and repairs.
        foreach ($view in @('Registry64','Registry32')) {
            $base=$null; $key=$null
            try {
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::$view)
                $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                foreach ($name in $key.GetSubKeyNames()) {
                    $sub=$key.OpenSubKey($name)
                    try {
                        $display=[string]$sub.GetValue('DisplayName'); if (-not $display) {continue}
                        $prefix="Software/$view/$(Escape-AuditSegment $display)/$(Escape-AuditSegment $name)"
                        foreach ($valueName in @('DisplayName','DisplayVersion','Publisher','InstallLocation')) { Add-AuditField $Record "$prefix/$valueName" $sub.GetValue($valueName) }
                    } finally { if ($sub) {$sub.Dispose()} }
                }
            } catch { Add-AuditIssue $Record "Software/$view" 'SoftwareInventoryUnavailable' }
            finally { if ($key) {$key.Dispose()}; if ($base) {$base.Dispose()} }
        }
    }
    if ($Manifest.collection.frameworks) {
        foreach ($view in @('Registry64','Registry32')) {
            $base=$null
            try {
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::$view)
                foreach ($version in @('v4\Full','v4\Client','v3.5','v3.0\Setup','v2.0.50727')) {
                    $key=$base.OpenSubKey('SOFTWARE\Microsoft\NET Framework Setup\NDP\'+$version)
                    if ($key) { try { foreach ($n in @('Install','Version','Release','SP')) { $v=$key.GetValue($n); if ($null -ne $v) {Add-AuditField $Record "Framework/$view/$(Escape-AuditSegment ($version.Replace('\','/')))/$n" $v} } } finally {$key.Dispose()} }
                }
            } catch { Add-AuditIssue $Record "Framework/$view" }
            finally { if ($base) {$base.Dispose()} }
        }
        $roots=@([pscustomobject]@{arch='x64';path=(Join-Path $env:ProgramFiles 'dotnet')},[pscustomobject]@{arch='x86';path=(Join-Path ${env:ProgramFiles(x86)} 'dotnet')})
        foreach ($r in $roots) {
            try {
                if (-not (Test-Path -LiteralPath $r.path)) { continue }
                foreach ($runtime in @(Get-ChildItem -LiteralPath (Join-Path $r.path 'shared') -Directory -ErrorAction SilentlyContinue)) {
                    foreach ($version in Get-ChildItem -LiteralPath $runtime.FullName -Directory -ErrorAction Stop) { Add-AuditField $Record "DotNet/$($r.arch)/Runtimes/$($runtime.Name)/$($version.Name)" $true }
                }
                $sdkPath=Join-Path $r.path 'sdk'
                if (Test-Path -LiteralPath $sdkPath) { foreach ($sdk in Get-ChildItem -LiteralPath $sdkPath -Directory -ErrorAction Stop) { Add-AuditField $Record "DotNet/$($r.arch)/SDK/$($sdk.Name)" $true } }
            } catch { Add-AuditIssue $Record "DotNet/$($r.arch)" }
        }
        # Detect installed ANCM binary independently of an app pool CLR setting.
        foreach ($path in @((Join-Path $env:ProgramFiles 'IIS\Asp.Net Core Module\V2\aspnetcorev2.dll'),(Join-Path ${env:ProgramFiles(x86)} 'IIS\Asp.Net Core Module\V2\aspnetcorev2.dll'))) {
            if (Test-Path -LiteralPath $path) { $arch=if ($path.StartsWith(${env:ProgramFiles(x86)})) {'x86'} else {'x64'}; Add-AuditField $Record "IIS/ANCM/$arch/FileVersion" (Get-Item -LiteralPath $path).VersionInfo.FileVersion }
        }
    }
    foreach ($name in @($Manifest.collection.machineEnvironmentVariables)) { if ($name) {Add-AuditField $Record "MachineEnvironment/$(Escape-AuditSegment $name)" ([Environment]::GetEnvironmentVariable($name,'Machine'))} }
    foreach ($group in @($Manifest.collection.localGroups)) {
        if (-not $group) { continue }
        try { $members=@(Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object { "$($_.Name)|$($_.SID.Value)" } | Sort-Object); Add-AuditField $Record "LocalGroups/$(Escape-AuditSegment $group)/Members" ($members -join "`n") }
        catch { Add-AuditIssue $Record "LocalGroups/$group" 'GroupMembershipUnavailable' }
    }
    if ($Manifest.collection.userRights) {
        $temp=Join-Path ([IO.Path]::GetTempPath()) ('deployment-audit-'+[guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($temp)
        try {
            $cfg=Join-Path $temp 'rights.inf'; $log=Join-Path $temp 'export.log'
            & "$env:SystemRoot\System32\secedit.exe" /export /mergedpolicy /cfg $cfg /areas USER_RIGHTS /log $log /quiet | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Policy export failed' }
            foreach ($line in Get-Content -LiteralPath $cfg) {
                if ($line -match '^(Se\w+)\s*=\s*(.*)$') { Add-AuditField $Record "UserRights/$($Matches[1])" ((@($Matches[2] -split ',' | ForEach-Object {$_.Trim()} | Sort-Object)) -join ',') }
            }
        } catch { Add-AuditIssue $Record 'UserRights' 'PolicyExportUnavailable' }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
function Invoke-AuditCollection {
    [CmdletBinding()]
    param([string]$ManifestPath,[string]$Environment,[string]$OutputPath,[string]$HmacKeyEnvironmentVariable='DEPLOYMENT_AUDIT_HMAC_KEY')
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Collector requires 64-bit Windows PowerShell 5.1 (powershell.exe).' }
    $manifest=Read-AuditJson $ManifestPath; Test-AuditManifest $manifest $Environment
    $script:AuditManifest=$manifest; $script:AuditHmacKey=$null; $keyId=$null
    $encoded=[Environment]::GetEnvironmentVariable($HmacKeyEnvironmentVariable)
    if ($encoded) {
        $script:AuditHmacKey=[Convert]::FromBase64String($encoded)
        if ($script:AuditHmacKey.Length -lt 32) { throw 'HMAC key must be at least 32 random bytes, Base64 encoded.' }
        $keyId=Get-HashText ('deployment-audit-key-id:'+ $encoded)
    }
    $records=New-Object Collections.Generic.List[object]
    try {
        foreach ($entry in @($manifest.items)) {
            $item=Resolve-AuditItem $entry $Environment
            if ($item.enabled -eq $false) { continue }
            Write-Verbose "Collecting $($item.type): $($item.id)"
            $record=New-AuditRecord $item.id $item.type
            try {
                switch ($item.type) {
                    'Service' {Collect-Service $record $item}
                    'IIS' {Collect-IIS $record $item}
                    'Task' {Collect-Task $record $item}
                    'MSMQ' {Collect-MSMQ $record $item}
                    'Certificate' {Collect-Certificate $record $item}
                    'Directory' {
                        $path=[Environment]::ExpandEnvironmentVariables($item.path)
                        $present=Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
                        Add-AuditField $record 'Present' $present
                        if ($present) { Add-AuditField $record 'Directory/Path' $path; Add-AuditAcl $record $path 'Directory/Acl' } else {$record.status='Missing'}
                    }
                    {$_ -in 'JsonFile','HttpJson'} {Collect-JsonSource $record $item}
                }
            } catch { $record.status='Error'; Add-AuditIssue $record 'Collector' ($_.Exception.GetType().Name) }
            $records.Add($record)
        }
        $platform=New-AuditRecord '_platform' 'Platform'
        try {Collect-Platform $platform $manifest} catch {$platform.status='Error';Add-AuditIssue $platform 'Platform' ($_.Exception.GetType().Name)}
        $records.Add($platform)
        $snapshot=[pscustomobject][ordered]@{
            schemaVersion='1.0'; toolVersion='1.0.0'; capturedAtUtc=[DateTime]::UtcNow.ToString('o'); environment=$Environment
            computerName=$env:COMPUTERNAME; manifestHash=(Get-HashText ([IO.File]::ReadAllText((Resolve-Path $ManifestPath).Path)))
            hmacKeyId=$keyId; records=@($records.ToArray())
        }
        Write-AuditJson $snapshot $OutputPath
        return $snapshot
    } finally { if ($script:AuditHmacKey) {[Array]::Clear($script:AuditHmacKey,0,$script:AuditHmacKey.Length)}; $script:AuditHmacKey=$null; $script:AuditManifest=$null }
}
function Get-AuditFieldMap {
    param($Record)
    $dict=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    if ($Record) { foreach ($f in $Record.fields) { if ($dict.ContainsKey($f.path)) {throw 'Duplicate snapshot field'}; $dict.Add($f.path,$f) } }
    return ,$dict
}
function Convert-AuditScalar {
    param($Value)
    ConvertTo-Json -InputObject $Value -Compress -Depth 10
}
function Get-NormalizedAuditValue {
    param($Field,[string]$ItemId,[string]$Environment,$Comparison)
    $value=$Field.value; $reasons=New-Object Collections.Generic.List[string]
    if ($Field.protection -eq 'None') {
        foreach ($rule in @($Comparison.mappings)) {
            if (-not $rule -or $ItemId -notlike $rule.item -or $Field.path -notlike $rule.path) {continue}
            $from=Get-PropertyValue $rule.values $Environment
            if ($null -eq $from -or [string]$from -eq '') {continue}
            if ($rule.mode -eq 'Exact' -and (Convert-AuditScalar $value) -ceq (Convert-AuditScalar $from)) { $value=$rule.canonical; $reasons.Add($rule.reason) }
            elseif ($rule.mode -eq 'LiteralReplace' -and $value -is [string] -and $value.Contains([string]$from)) { $value=$value.Replace([string]$from,[string]$rule.canonical); $reasons.Add($rule.reason) }
        }
    }
    [pscustomobject]@{value=$value; reasons=@($reasons.ToArray())}
}
function New-AuditRow {
    param([string]$Category,[string]$Status,[string]$Item,[string]$Path,$Left,$Right,[string]$Reason)
    [pscustomobject][ordered]@{category=$Category;status=$Status;item=$Item;path=$Path;left=$Left;right=$Right;reason=$Reason}
}
function Test-AuditExpectations {
    param($Snapshot,$Manifest)
    $specs=New-Object Collections.Generic.List[object]
    foreach ($entry in @($Manifest.items)) {
        $item=Resolve-AuditItem $entry $Snapshot.environment
        if ($item.enabled -eq $false) {continue}
        $specs.Add([pscustomobject]@{id=$item.id; expected=@($item.expected); type=$item.type; health=$item.health})
    }
    $specs.Add([pscustomobject]@{id='_platform';expected=@($Manifest.platformExpected);type='Platform';health=$null})
    foreach ($item in $specs) {
        $record=@($Snapshot.records | Where-Object id -CEQ $item.id) | Select-Object -First 1
        if (-not $record) { New-AuditRow 'Validation' 'Inconclusive' $item.id 'Record' $Snapshot.environment $null 'Item not collected'; continue }
        $map=Get-AuditFieldMap $record
        if ($item.type -ne 'Platform') {
            if (-not $map.ContainsKey('Present')) { New-AuditRow 'Validation' 'Inconclusive' $item.id 'Present' $Snapshot.environment $null 'Presence could not be determined' }
            elseif (-not $map['Present'].value) { New-AuditRow 'Validation' 'Fail' $item.id 'Present' $Snapshot.environment $false 'Required item missing' }
            else { New-AuditRow 'Validation' 'Pass' $item.id 'Present' $Snapshot.environment $true 'Required item found' }
        }
        if ($record.status -in @('Error','Partial')) { New-AuditRow 'Validation' 'Inconclusive' $item.id 'Collection' $Snapshot.environment $record.status 'Incomplete collection' }
        foreach ($issue in $record.issues) { New-AuditRow 'Coverage' 'Inconclusive' $item.id $issue.scope $Snapshot.environment $null $issue.code }
        $checks=@($item.expected)
        if ($item.health) { $checks+= [pscustomobject]@{path='Health/Success';operator='Equals';value=$true} }
        foreach ($check in $checks) {
            if (-not $check) {continue}
            $matches=@($record.fields | Where-Object {$_.path -like $check.path})
            $reason="Expected $($check.operator): $(Convert-AuditScalar $check.value)"
            if (-not $matches.Count) {
                $state=if ($record.status -eq 'Collected' -or $record.status -eq 'Missing') {'Fail'} else {'Inconclusive'}
                New-AuditRow 'Validation' $state $item.id $check.path $Snapshot.environment $null 'Expected field not found'; continue
            }
            foreach ($field in $matches) {
                if ($field.protection -ne 'None') { New-AuditRow 'Validation' 'Inconclusive' $item.id $field.path $Snapshot.environment '[PROTECTED]' 'Plaintext validation of protected fields is disabled'; continue }
                $ok=$false
                try {
                    switch ($check.operator) {
                        'Exists' {$ok=$true}
                        'Equals' {$ok=(Convert-AuditScalar $field.value) -ceq (Convert-AuditScalar $check.value)}
                        'OneOf' {$ok=@($check.value | Where-Object {(Convert-AuditScalar $_) -ceq (Convert-AuditScalar $field.value)}).Count -gt 0}
                        'Contains' {$ok=([string]$field.value).Contains([string]$check.value)}
                        'Regex' {$ok=[regex]::IsMatch([string]$field.value,[string]$check.value)}
                        'Min' {$ok=[double]$field.value -ge [double]$check.value}
                        'Max' {$ok=[double]$field.value -le [double]$check.value}
                        'MinVersion' {$ok=[version]$field.value -ge [version]$check.value}
                        default {throw 'Unknown operator'}
                    }
                    $status=if ($ok) {'Pass'} else {'Fail'}
                    New-AuditRow 'Validation' $status $item.id $field.path $Snapshot.environment $field.value $reason
                } catch { New-AuditRow 'Validation' 'Inconclusive' $item.id $field.path $Snapshot.environment $field.value 'Invalid validation operator/value' }
            }
        }
    }
}
function Compare-AuditSnapshots {
    param($Left,$Right,$Manifest)
    if ($Left.schemaVersion -ne '1.0' -or ($Right -and $Right.schemaVersion -ne '1.0')) {throw 'Unsupported snapshot version'}
    Test-AuditManifest $Manifest $Left.environment
    $rows=New-Object Collections.Generic.List[object]
    foreach ($snapshot in @($Left,$Right)) {
        if (-not $snapshot) {continue}
        $recordIds=@{}
        foreach ($record in @($snapshot.records)) {
            if (-not $record.id -or $recordIds.ContainsKey($record.id)) {throw 'Missing or duplicate record id'}
            $recordIds[$record.id]=$true
        }
        try {
            $age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($snapshot.capturedAtUtc)).TotalHours
            $maxAge=Get-PropertyValue $Manifest.comparison 'maxSnapshotAgeHours' 24
            if ($age -lt -0.1 -or $age -gt $maxAge) {$rows.Add((New-AuditRow 'Coverage' 'Inconclusive' '_snapshot' 'CapturedAtUtc' $snapshot.environment $snapshot.capturedAtUtc 'Snapshot outside allowed time window'))}
        } catch {$rows.Add((New-AuditRow 'Coverage' 'Inconclusive' '_snapshot' 'CapturedAtUtc' $snapshot.environment $null 'Invalid snapshot timestamp'))}
    }
    foreach ($r in @(Test-AuditExpectations $Left $Manifest)) {$rows.Add($r)}
    if ($Right) {
        Test-AuditManifest $Manifest $Right.environment
        foreach ($r in @(Test-AuditExpectations $Right $Manifest)) {$rows.Add($r)}
        if ($Left.manifestHash -cne $Right.manifestHash) { $rows.Add((New-AuditRow 'Coverage' 'Inconclusive' '_snapshot' 'ManifestHash' $Left.manifestHash $Right.manifestHash 'Snapshots collected using different manifests')) }
        $ids=@(@($Left.records.id)+@($Right.records.id) | Sort-Object -Unique)
        foreach ($id in $ids) {
            $a=@($Left.records | Where-Object id -CEQ $id) | Select-Object -First 1
            $b=@($Right.records | Where-Object id -CEQ $id) | Select-Object -First 1
            if (-not $a -or -not $b) { $rows.Add((New-AuditRow 'Comparison' 'Inconclusive' $id 'Record' ([bool]$a) ([bool]$b) 'Item not collected on both sides')); continue }
            $am=Get-AuditFieldMap $a; $bm=Get-AuditFieldMap $b
            $paths=New-Object 'Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
            foreach ($p in $am.Keys) {[void]$paths.Add($p)}; foreach ($p in $bm.Keys) {[void]$paths.Add($p)}
            foreach ($path in $paths) {
                $af=$null; $bf=$null; if ($am.ContainsKey($path)) {$af=$am[$path]}; if ($bm.ContainsKey($path)) {$bf=$bm[$path]}
                $av=if ($af) {$af.value} else {'[FIELD ABSENT]'}; $bv=if ($bf) {$bf.value} else {'[FIELD ABSENT]'}
                $status='Equal'; $reason='Equal values'
                if (-not $af -or -not $bf) {
                    $status=if ($a.status -in @('Partial','Error') -or $b.status -in @('Partial','Error')) {'Inconclusive'} else {'Drift'}
                    $reason='Field exists on only one side'
                } elseif (@($Manifest.comparison.ignore | Where-Object { $_ -and $id -like $_.item -and $path -like $_.path }).Count) {
                    $status='Ignored';$reason=(@($Manifest.comparison.ignore | Where-Object { $_ -and $id -like $_.item -and $path -like $_.path }).reason -join '; ')
                } elseif ($af.protection -eq 'Redacted' -or $bf.protection -eq 'Redacted') {$status='Inconclusive';$reason='Secret redacted; equality cannot be asserted'}
                elseif ($af.protection -ne $bf.protection) {$status='Inconclusive';$reason='Different protection modes'}
                elseif ($af.protection -eq 'HMAC-SHA256' -and (-not $Left.hmacKeyId -or $Left.hmacKeyId -cne $Right.hmacKeyId)) {$status='Inconclusive';$reason='HMAC keys differ or identifier missing'}
                elseif ($af.volatile -or $bf.volatile) {$status='Informational';$reason='Runtime metric; validate explicitly if required'}
                else {
                    $ignore=@($Manifest.comparison.ignore | Where-Object { $_ -and $id -like $_.item -and $path -like $_.path })
                    if ($ignore.Count) { $status='Ignored';$reason=($ignore.reason -join '; ') }
                    else {
                        $an=Get-NormalizedAuditValue $af $id $Left.environment $Manifest.comparison
                        $bn=Get-NormalizedAuditValue $bf $id $Right.environment $Manifest.comparison
                        if ((Convert-AuditScalar $an.value) -cne (Convert-AuditScalar $bn.value) -or $af.valueType -cne $bf.valueType) { $status='Drift';$reason='Values differ after scoped mappings' }
                        elseif ((Convert-AuditScalar $av) -cne (Convert-AuditScalar $bv)) {$status='Accepted';$reason=(@($an.reasons)+@($bn.reasons) | Select-Object -Unique) -join '; '}
                    }
                }
                if ($af -and $af.protection -ne 'None') {$av='[PROTECTED]'}
                if ($bf -and $bf.protection -ne 'None') {$bv='[PROTECTED]'}
                $rows.Add((New-AuditRow 'Comparison' $status $id $path $av $bv $reason))
            }
        }
    }
    $summary=[ordered]@{}
    foreach ($state in @('Drift','Fail','Inconclusive','Accepted','Equal','Pass','Ignored','Informational')) {$summary[$state]=@($rows | Where-Object status -eq $state).Count}
    $exitCode=if ($summary.Fail -gt 0 -or $summary.Drift -gt 0) {2} elseif ($summary.Inconclusive -gt 0) {3} else {0}
    [pscustomobject][ordered]@{schemaVersion='1.0';generatedAtUtc=[datetime]::UtcNow.ToString('o');left=@{environment=$Left.environment;computer=$Left.computerName;capturedAtUtc=$Left.capturedAtUtc};right=$(if ($Right) {@{environment=$Right.environment;computer=$Right.computerName;capturedAtUtc=$Right.capturedAtUtc}} else {$null});summary=$summary;exitCode=$exitCode;rows=@($rows.ToArray())}
}
function Write-AuditHtml {
    param($Report,[string]$Path)
    $template=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'report-template.html'))
    # Escape script delimiters, HTML and Unicode line separators in JSON embedded as inert data.
    $json=(ConvertTo-Json -InputObject $Report -Depth 90 -Compress).Replace('&','\u0026').Replace('<','\u003c').Replace('>','\u003e').Replace([string][char]0x2028,'\u2028').Replace([string][char]0x2029,'\u2029')
    $html=$template.Replace('__AUDIT_DATA__',$json)
    $full=[IO.Path]::GetFullPath($Path); [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full))
    [IO.File]::WriteAllText($full,$html,(New-Object Text.UTF8Encoding($false)))
}
Export-ModuleMember -Function Invoke-AuditCollection,Compare-AuditSnapshots,Write-AuditHtml,Read-AuditJson,Write-AuditJson,Test-AuditManifest
