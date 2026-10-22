#requires -Version 5.1
<#
Codex Proxy Repair 2.0.0 | Windows 10/11 | PowerShell 5.1+
No elevation, downloads, authentication access, or application termination.
Dot sourcing loads functions without executing the tool.
#>
[CmdletBinding()]
param(
    [ValidateSet('Repair','Diagnose','Restore')][string]$Mode = 'Repair',
    [string]$ProxyUrl,
    [ValidateRange(3,30)][int]$TimeoutSec = 10,
    [string]$BackupDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Version = '2.0.0'
$script:Root = $PSScriptRoot
$script:Keys = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')
$script:Log = New-Object 'System.Collections.Generic.List[string]'
$script:Utf8 = New-Object Text.UTF8Encoding($false, $true)

function Write-Status([string]$Message) {
    Write-Host $Message
    $script:Log.Add($Message)
}

function Get-UserProxyValue([string]$Key) { return [Environment]::GetEnvironmentVariable($Key,'User') }
function Set-UserProxyValue([string]$Key,$Value) { [Environment]::SetEnvironmentVariable($Key,$Value,'User') }

function Initialize-WindowsEnvironment {
    # A broken Codex shell allowlist can even remove SystemRoot from this process.
    $windowsDir = [Environment]::GetEnvironmentVariable('SystemRoot','Machine')
    if (-not $windowsDir) { $windowsDir = [Environment]::GetFolderPath('Windows') }
    if (-not $windowsDir -or -not [IO.Directory]::Exists($windowsDir)) {
        throw '无法确定 Windows 安装目录。请直接在 Windows 中运行本工具。'
    }
    $defaults = @{
        SystemRoot = $windowsDir; windir = $windowsDir
        SystemDrive = [IO.Path]::GetPathRoot($windowsDir).TrimEnd('\')
        ComSpec = (Join-Path $windowsDir 'System32\cmd.exe'); OS = 'Windows_NT'
    }
    foreach ($key in $defaults.Keys) {
        if (-not [Environment]::GetEnvironmentVariable($key,'Process')) {
            [Environment]::SetEnvironmentVariable($key,$defaults[$key],'Process')
        }
    }
}

function Test-LoopbackHost([string]$HostName) {
    if ($HostName -ieq 'localhost') { return $true }
    $address = $null
    return ([Net.IPAddress]::TryParse($HostName.Trim('[',']'),[ref]$address) -and [Net.IPAddress]::IsLoopback($address))
}

function ConvertTo-LocalHttpProxy([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $valueTrimmed = $Value.Trim()
    if ($valueTrimmed -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $valueTrimmed = 'http://' + $valueTrimmed }
    $uri = $null
    if (-not [uri]::TryCreate($valueTrimmed,[UriKind]::Absolute,[ref]$uri)) { return $null }
    if ($uri.Scheme -ne 'http' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
        $uri.AbsolutePath -ne '/' -or $uri.Port -lt 1 -or $uri.Port -gt 65535 -or
        $valueTrimmed -match '[\s"<>|&]') { return $null }
    if (-not (Test-LoopbackHost $uri.Host)) { return $null }
    if ($uri.Host.Contains(':')) { return ('http://[::1]:' + $uri.Port) }
    return $uri.GetLeftPart([UriPartial]::Authority)
}

function Test-LocalProxyAddress([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $uri = $null
    $valueTrimmed = $Value.Trim()
    if ($valueTrimmed -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $valueTrimmed = 'http://' + $valueTrimmed }
    return ([uri]::TryCreate($valueTrimmed,[UriKind]::Absolute,[ref]$uri) -and
        -not $uri.UserInfo -and (Test-LoopbackHost $uri.Host))
}

function Get-ProxyLabel([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '(未设置)' }
    $uri = $null
    $text = $Value.Trim()
    if ($text -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $text = 'http://' + $text }
    if ([uri]::TryCreate($text,[UriKind]::Absolute,[ref]$uri) -and
        (Test-LoopbackHost $uri.Host) -and -not $uri.UserInfo) {
        return ('{0}://{1}:{2}' -f $uri.Scheme,$uri.Host,$uri.Port)
    }
    return '(远程、认证或无法识别的配置；内容已隐藏)'
}

function Test-ProxyPort([string]$Address) {
    $endpoint = [uri]$Address
    $client = New-Object Net.Sockets.TcpClient
    $pending = $null
    try {
        $pending = $client.BeginConnect($endpoint.DnsSafeHost,$endpoint.Port,$null,$null)
        if (-not $pending.AsyncWaitHandle.WaitOne(500)) { return $false }
        $client.EndConnect($pending)
        return $client.Connected
    } catch { return $false }
    finally {
        $client.Close()
        if ($pending) { $pending.AsyncWaitHandle.Close() }
    }
}

function Invoke-ProxyProbe([string]$Address,[string]$Url,[int]$Seconds = 10) {
    $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not [IO.File]::Exists($curlPath)) { throw '系统缺少 curl.exe；未修改配置。请使用带系统 curl 的 Windows 10/11。' }
    $arguments = @('-q','--silent','--show-error','--connect-timeout','4','--max-time',
        [string]$Seconds,'--proxy',$Address,'--noproxy','codex-network-probe.invalid',
        '--output','NUL','--write-out','PROBE:%{http_code}:%{http_connect}','--url',$Url)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $curlPath
    $start.Arguments = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit(($Seconds + 3) * 1000)
        if (-not $finished) { $process.Kill(); $process.WaitForExit() }
        $stdout = $stdoutTask.Result
        [void]$stderrTask.Result
        $exitCode = $process.ExitCode
        if (-not $finished) { $exitCode = 28 }
        $http = 0; $connect = 0
        if ($stdout -match 'PROBE:(\d{3}):(\d{3})') { $http = [int]$Matches[1]; $connect = [int]$Matches[2] }
        $transport = $exitCode -eq 0 -and $connect -eq 200
        return [pscustomobject]@{ Http=$http; Connect=$connect; Exit=$exitCode; Transport=$transport }
    } finally { $process.Dispose() }
}

function Test-ProxyRoute([string]$Address,[int]$Seconds = 10) {
    $primary = Invoke-ProxyProbe $Address 'https://chatgpt.com/backend-api/codex/responses' $Seconds
    Write-Status ('  Codex: HTTP={0} CONNECT={1} curl={2}' -f $primary.Http,$primary.Connect,$primary.Exit)
    # GET without credentials is expected to return 401 or 405 on this POST endpoint.
    $ok = $primary.Transport -and (($primary.Http -ge 200 -and $primary.Http -lt 400) -or $primary.Http -in @(401,405))
    if ($ok) { return $true }
    if ($primary.Http -eq 403 -and $primary.Transport) {
        Write-Status '  已建立 TLS，但站点返回 403；不把它自动判为可用线路。可更换节点后重试。'
    } elseif ($primary.Exit -eq 60) {
        Write-Status '  TLS 证书验证失败；不会关闭证书校验。'
    } elseif ($primary.Connect -eq 407) {
        Write-Status '  该代理要求身份认证，本工具不自动处理。'
    } else { Write-Status '  HTTPS 转发未通过，检查代理节点、协议或网络。' }
    return $false
}

function Get-CodexHome {
    foreach ($scope in @('User','Process')) {
        $value = [Environment]::GetEnvironmentVariable('CODEX_HOME',$scope)
        if ($value) { return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($value)) }
    }
    return Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'
}

function Get-TextDocument([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $encoding = $script:Utf8
    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        $encoding = New-Object Text.UTF8Encoding($true,$true); $offset = 3
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
        $encoding = New-Object Text.UnicodeEncoding($false,$true,$true); $offset = 2
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 254 -and $bytes[1] -eq 255) {
        $encoding = New-Object Text.UnicodeEncoding($true,$true,$true); $offset = 2
    }
    $text = $encoding.GetString($bytes,$offset,$bytes.Length-$offset)
    return [pscustomobject]@{ Path=$Path; Text=$text; Bytes=$bytes; Encoding=$encoding }
}

function ConvertTo-DocumentBytes($Document,[string]$Text) {
    return ,([byte[]]($Document.Encoding.GetPreamble() + $Document.Encoding.GetBytes($Text)))
}

function Get-EnvProxyEntries([string]$Text) {
    $pattern = '(?im)^[ \t]*(?:export[ \t]+)?(?<key>HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)[ \t]*=[ \t]*(?<value>[^\r\n]*)'
    foreach ($match in [regex]::Matches($Text,$pattern)) {
        $value = $match.Groups['value'].Value.Trim()
        if ($value.StartsWith('"') -or $value.StartsWith("'")) {
            $quote = $value.Substring(0,1)
            $end = $value.IndexOf($quote,1)
            if ($end -gt 0) { $value = $value.Substring(1,$end-1) }
        } else { $value = ($value -replace '\s+#.*$','').Trim() }
        [pscustomobject]@{ Key=$match.Groups['key'].Value; Value=$value; Match=$match }
    }
}

function Get-CandidateAddresses([string]$Explicit,[string]$CodexHome) {
    $values = New-Object 'System.Collections.Generic.List[string]'
    if ($Explicit) {
        $address = ConvertTo-LocalHttpProxy $Explicit
        if (-not $address) { throw '-ProxyUrl 仅支持无认证的本机 HTTP/Mixed 代理，例如 http://127.0.0.1:7897。' }
        $values.Add($address)
    } else {
        foreach ($scope in @('User','Process','Machine')) {
            foreach ($key in @('HTTPS_PROXY','HTTP_PROXY','ALL_PROXY')) {
                $address = ConvertTo-LocalHttpProxy ([Environment]::GetEnvironmentVariable($key,$scope))
                if ($address) { $values.Add($address) }
            }
        }
        $dotEnv = Join-Path $CodexHome '.env'
        if ([IO.File]::Exists($dotEnv)) {
            foreach ($entry in @(Get-EnvProxyEntries (Get-TextDocument $dotEnv).Text)) {
                if ($entry.Key -ine 'NO_PROXY') {
                    $address = ConvertTo-LocalHttpProxy $entry.Value
                    if ($address) { $values.Add($address) }
                }
            }
        }
        $roaming = [Environment]::GetFolderPath('ApplicationData')
        foreach ($relative in @('io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml',
            'io.github.clash-verge-rev.clash-verge-rev\verge.yaml','clash-verge\clash-verge.yaml',
            'clash\config.yaml','clash_win\config.yaml')) {
            $path = Join-Path $roaming $relative
            if (-not [IO.File]::Exists($path)) { continue }
            foreach ($line in [IO.File]::ReadLines($path)) {
                if ($line -match '^(?:mixed-port|port|verge_mixed_port|verge_port):\s*(\d{1,5})\s*(?:#.*)?$') {
                    $port = [int]$Matches[1]
                    if ($port -gt 0 -and $port -le 65535) { $values.Add(('http://127.0.0.1:' + $port)) }
                }
            }
        }
        $internet = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($internet -and $internet.PSObject.Properties['ProxyEnable'] -and $internet.ProxyEnable -eq 1 -and $internet.PSObject.Properties['ProxyServer']) {
            foreach ($part in ([string]$internet.ProxyServer -split ';')) {
                $address = ConvertTo-LocalHttpProxy ($part -replace '^(?:http|https)=','')
                if ($address) { $values.Add($address) }
            }
        }
        # Identify uncommon ports owned by known local proxy programs, when available.
        try {
            $proxyIds = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.ProcessName -match '^(mihomo.*|clash.*|sing-box|xray|v2ray|v2rayN|nekoray|hiddify.*)$'
            } | ForEach-Object { $_.Id })
            if ($proxyIds.Count -gt 0) {
                $netstat = Join-Path $env:SystemRoot 'System32\netstat.exe'
                foreach ($line in @(& $netstat -ano -p tcp 2>$null)) {
                    if ($line -match '^\s*TCP\s+(127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\[::\]):(\d+)\s+\S+:0\s+\S+\s+(\d+)\s*$') {
                        if ([int]$Matches[3] -in $proxyIds) {
                            $hostAddress = '127.0.0.1'
                            if ($Matches[1] -eq '[::1]') { $hostAddress = '[::1]' }
                            $values.Add(('http://{0}:{1}' -f $hostAddress,$Matches[2]))
                        }
                    }
                }
            }
        } catch { Write-Status '可选的进程端口检测不可用，继续检测环境变量和常用端口。' }
        foreach ($port in @(7897,7890,7899,10809,2080,20171,17890,8080,1080)) {
            $values.Add(('http://127.0.0.1:' + $port))
        }
    }
    $seen = @{}
    foreach ($value in $values) { if (-not $seen.ContainsKey($value)) { $seen[$value]=$true; $value } }
}

function Repair-NoProxy([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'localhost,127.0.0.1,::1' }
    $kept = New-Object 'System.Collections.Generic.List[string]'
    foreach ($token in ($Value -split ',')) {
        $part = $token.Trim()
        if (-not $part) { continue }
        $domain = $part.ToLowerInvariant().TrimStart('.')
        if ($domain -eq '*') { continue }
        if ($domain -match ':\d+$') { $domain = $domain -replace ':\d+$','' }
        if ($domain.StartsWith('*.')) { $domain = $domain.Substring(2) }
        $bypasses = $false
        foreach ($hostName in @('chatgpt.com','api.openai.com','auth.openai.com','ws.chatgpt.com')) {
            if ($hostName -eq $domain -or $hostName.EndsWith('.' + $domain)) { $bypasses=$true }
        }
        if (-not $bypasses -and -not $kept.Contains($part)) { $kept.Add($part) }
    }
    foreach ($local in @('localhost','127.0.0.1','::1')) { if (-not $kept.Contains($local)) { $kept.Add($local) } }
    return $kept -join ','
}

function Update-ShellAllowlist([string]$Text) {
    $section = [regex]::Match($Text,'(?ms)^\[shell_environment_policy\][ \t]*(?:#[^\r\n]*)?\r?\n(?<body>.*?)(?=^\[|\z)')
    if (-not $section.Success) { return $Text }
    $body = $section.Groups['body'].Value
    if ($body -match '(?m)^\s*inherit\s*=\s*["'']none["'']') {
        throw 'Codex 设置了 inherit="none"；为保留自定义隔离策略，未自动修改，请手动检查 shell_environment_policy。'
    }
    $match = [regex]::Match($body,'(?ms)^include_only[ \t]*=[ \t]*\[(?<items>.*?)\]')
    if (-not $match.Success) { return $Text }
    $itemsText = [regex]::Replace($match.Groups['items'].Value,'(?m)#[^\r\n]*','')
    $tokens = @([regex]::Matches($itemsText,'["''](?<key>[A-Za-z0-9_*?]+)["'']') | ForEach-Object { $_.Groups['key'].Value })
    $remaining = [regex]::Replace($itemsText,'["''][A-Za-z0-9_*?]+["'']','') -replace '[\s,]',''
    if ($remaining) { throw 'Codex 环境白名单使用了复杂 TOML 语法；未自动改写，请手动检查。' }
    $required = @('SystemRoot','windir','SystemDrive','ComSpec','PATHEXT','OS','LOCALAPPDATA','APPDATA',
        'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')
    $exclude = [regex]::Match($body,'(?ms)^exclude[ \t]*=[ \t]*\[(?<items>.*?)\]')
    if ($exclude.Success) {
        $exclusions = @([regex]::Matches(($exclude.Groups['items'].Value -replace '(?m)#[^\r\n]*',''),'["''](?<key>[^"'']+)["'']') | ForEach-Object { $_.Groups['key'].Value })
        foreach ($pattern in $exclusions) {
            foreach ($key in $required) {
                if ($key -ilike $pattern) { throw 'Codex exclude 策略排除了必要变量；为保留自定义策略，未自动改写。' }
            }
        }
    }
    $missing = @()
    foreach ($key in $required) {
        $covered = $false
        foreach ($token in $tokens) { if ($key -ilike $token) { $covered=$true } }
        if (-not $covered) { $missing += $key }
    }
    if ($missing.Count -eq 0) { return $Text }
    $newline = "`n"; if ($Text.Contains("`r`n")) { $newline="`r`n" }
    $bodyItems = $match.Groups['items'].Value.TrimEnd()
    $activeItems = $itemsText.TrimEnd()
    # A newline before the comma prevents a trailing comment from swallowing additions.
    $separator = ''
    if ($tokens.Count -gt 0 -and -not $activeItems.EndsWith(',')) { $separator=',' }
    $updatedItems = $bodyItems + $newline + $separator + (($missing | ForEach-Object { '"'+$_+'"' }) -join ',')
    $position = $section.Groups['body'].Index + $match.Groups['items'].Index
    return $Text.Substring(0,$position) + $updatedItems + $Text.Substring($position + $match.Groups['items'].Length)
}

function Get-BytesHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function New-RepairPlan([string]$Address,[string]$CodexHome,[bool]$Explicit = $false) {
    $environment = @()
    foreach ($key in $script:Keys) {
        $before = Get-UserProxyValue $key
        if ($key -eq 'NO_PROXY') { $after = Repair-NoProxy $before }
        else {
            if (-not $Explicit -and -not (Test-LocalProxyAddress $before)) {
                throw '检测到远程/认证用户代理，未自动覆盖。确认要改用本地代理时，请用 -ProxyUrl 显式指定。'
            }
            $after = $Address
        }
        if ($before -cne $after) { $environment += [pscustomobject]@{ Key=$key; Before=$before; After=$after } }
    }
    $files = @()
    $configPath = Join-Path $CodexHome 'config.toml'
    if ([IO.File]::Exists($configPath)) {
        $document = Get-TextDocument $configPath
        $text = Update-ShellAllowlist $document.Text
        if ($text -cne $document.Text) {
            $files += [pscustomobject]@{ Path=$configPath; Before=$document.Bytes; After=(ConvertTo-DocumentBytes $document $text) }
        }
    }
    $dotEnv = Join-Path $CodexHome '.env'
    if ([IO.File]::Exists($dotEnv)) {
        $document = Get-TextDocument $dotEnv
        $text = $document.Text
        $entries = @(Get-EnvProxyEntries $text)
        # Replace from the end, so offsets for earlier lines remain valid.
        for ($index=$entries.Count-1; $index -ge 0; $index--) {
            $entry = $entries[$index]
            if ($entry.Key -ieq 'NO_PROXY') { $value = Repair-NoProxy $entry.Value }
            else {
                if (-not $Explicit -and -not (Test-LocalProxyAddress $entry.Value)) {
                    throw 'Codex .env 含远程/认证代理，未自动覆盖。确认后可用 -ProxyUrl 显式指定本地代理。'
                }
                $value = $Address
            }
            $line = $entry.Key + '=' + $value
            $text = $text.Substring(0,$entry.Match.Index) + $line + $text.Substring($entry.Match.Index+$entry.Match.Length)
        }
        if ($text -cne $document.Text) {
            $files += [pscustomobject]@{ Path=$dotEnv; Before=$document.Bytes; After=(ConvertTo-DocumentBytes $document $text) }
        }
    }
    return [pscustomobject]@{ Environment=@($environment); Files=@($files) }
}

function Save-RepairBackup($Plan,[string]$Root) {
    $directory = Join-Path $Root ('backups\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
    [void][IO.Directory]::CreateDirectory($directory)
    # Backups may contain unrelated secrets from an existing .env; keep them private.
    $acl = Get-Acl -LiteralPath $directory
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    $manifestFiles = @()
    for ($index=0; $index -lt $Plan.Files.Count; $index++) {
        $item = $Plan.Files[$index]
        $name = 'file-' + $index + '.before'
        [IO.File]::WriteAllBytes((Join-Path $directory $name),$item.Before)
        $manifestFiles += [pscustomobject]@{ Path=$item.Path; BackupFile=$name;
            BeforeHash=(Get-BytesHash $item.Before); AfterHash=(Get-BytesHash $item.After) }
    }
    $manifest = [ordered]@{ Version=1; ToolVersion=$script:Version; State='Prepared';
        UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
        Environment=@($Plan.Environment); Files=@($manifestFiles) }
    [IO.File]::WriteAllText((Join-Path $directory 'manifest.json'),($manifest | ConvertTo-Json -Depth 8),$script:Utf8)
    return $directory
}

function Apply-RepairPlan($Plan,[string]$BackupRoot) {
    if ($Plan.Environment.Count -eq 0 -and $Plan.Files.Count -eq 0) { return $null }
    $directory = Save-RepairBackup $Plan $BackupRoot
    $attemptedEnvironment = @(); $attemptedFiles = @()
    try {
        foreach ($item in $Plan.Environment) {
            if ((Get-UserProxyValue $item.Key) -cne $item.Before) { throw '修复期间用户代理被其他程序更改，停止写入。' }
            $attemptedEnvironment += $item
            Set-UserProxyValue $item.Key $item.After
            if ((Get-UserProxyValue $item.Key) -cne $item.After) { throw '用户环境变量写入校验失败。' }
        }
        foreach ($item in $Plan.Files) {
            # Refuse concurrent changes made after the plan was calculated.
            if ((Get-BytesHash ([IO.File]::ReadAllBytes($item.Path))) -ne (Get-BytesHash $item.Before)) {
                throw '修复期间配置被其他程序更改，停止写入。'
            }
            $attemptedFiles += $item
            [IO.File]::WriteAllBytes($item.Path,$item.After)
            if ((Get-BytesHash ([IO.File]::ReadAllBytes($item.Path))) -ne (Get-BytesHash $item.After)) { throw '配置写入校验失败。' }
        }
        $manifestPath = Join-Path $directory 'manifest.json'
        $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
        $manifest.State = 'Applied'
        [IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 8),$script:Utf8)
    } catch {
        $originalError = $_
        $rollbackFailed = $false
        foreach ($item in $attemptedEnvironment) {
            try {
                $current = Get-UserProxyValue $item.Key
                if ($current -ceq $item.After) { Set-UserProxyValue $item.Key $item.Before }
            } catch { $rollbackFailed=$true }
        }
        foreach ($item in $attemptedFiles) {
            try {
                [IO.File]::WriteAllBytes($item.Path,$item.Before)
            } catch { $rollbackFailed=$true }
        }
        Write-Status ('修复中断，已尝试回滚。备份：' + $directory)
        if ($rollbackFailed) { Write-Status '有项目未能回滚，请保留备份并检查文件/注册表权限。' }
        throw $originalError
    }
    return $directory
}

function Restore-RepairBackup([string]$Directory) {
    $manifestPath = Join-Path $Directory 'manifest.json'
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    if ($manifest.Version -ne 1 -or $manifest.State -ne 'Applied' -or
        $manifest.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw '备份无效、已还原、未完整应用或不属于当前 Windows 用户。'
    }
    # Validate all records before writing anything; preserve later user changes.
    foreach ($item in $manifest.Environment) {
        if ($item.Key -notin $script:Keys) { throw '备份含不支持的环境变量。' }
        if ((Get-UserProxyValue $item.Key) -cne $item.After) {
            throw ('环境变量 ' + $item.Key + ' 在修复后又被更改，已停止还原，避免覆盖后续设置。')
        }
    }
    foreach ($item in $manifest.Files) {
        if ($item.BackupFile -notmatch '^file-\d+\.before$') { throw '备份文件名不正确。' }
        $codexHome = Get-CodexHome
        if ([IO.Path]::GetFullPath($item.Path) -notin @((Join-Path $codexHome 'config.toml'),(Join-Path $codexHome '.env'))) {
            throw '备份目标不属于当前 Codex 用户目录，停止还原。'
        }
        if (-not [IO.File]::Exists($item.Path) -or
            (Get-BytesHash ([IO.File]::ReadAllBytes($item.Path))) -ne $item.AfterHash -or
            (Get-BytesHash ([IO.File]::ReadAllBytes((Join-Path $Directory $item.BackupFile)))) -ne $item.BeforeHash) {
            throw '配置或备份在修复后有变化，已停止还原，避免覆盖后续修改。'
        }
    }
    $restoredEnv = @(); $restoredFiles = @()
    try {
        foreach ($item in $manifest.Environment) {
            Set-UserProxyValue $item.Key $item.Before
            $restoredEnv += $item
            if ((Get-UserProxyValue $item.Key) -cne $item.Before) { throw '环境变量还原校验失败。' }
        }
        foreach ($item in $manifest.Files) {
            $afterBytes = [IO.File]::ReadAllBytes($item.Path)
            $restoredFiles += [pscustomobject]@{ Path=$item.Path; Bytes=$afterBytes }
            [IO.File]::WriteAllBytes($item.Path,[IO.File]::ReadAllBytes((Join-Path $Directory $item.BackupFile)))
        }
        $manifest.State = 'Restored'
        [IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 8),$script:Utf8)
    } catch {
        foreach ($item in $restoredEnv) { Set-UserProxyValue $item.Key $item.After }
        foreach ($item in $restoredFiles) { [IO.File]::WriteAllBytes($item.Path,$item.Bytes) }
        throw
    }
    Write-Status ('已还原备份：' + $Directory)
}

function Send-EnvironmentRefresh {
    try {
        if (-not ('CodexProxyRepair.EnvironmentRefresh' -as [type])) {
            Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace CodexProxyRepair {
    public static class EnvironmentRefresh {
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg, UIntPtr wParam,
            string lParam, uint flags, uint timeout, out UIntPtr result);
    }
}
'@
        }
        Write-Status '正在通知 Windows 刷新启动环境……'
        $result = [UIntPtr]::Zero
        $sent = [CodexProxyRepair.EnvironmentRefresh]::SendMessageTimeout([IntPtr]0xffff,0x1a,[UIntPtr]::Zero,'Environment',2,500,[ref]$result)
        if ($sent -eq [IntPtr]::Zero) { Write-Status '环境通知未全部成功；建议注销并重新登录 Windows。' }
    } catch { Write-Status '环境通知不可用；请注销并重新登录 Windows，使新设置生效。' }
}

function Invoke-CodexNetworkTool {
    Initialize-WindowsEnvironment
    Write-Status ('Codex 本地代理修复工具 v' + $script:Version)
    Write-Status '修复当前用户配置；不需要管理员权限，不会自动关闭 Codex。'
    if ($Mode -eq 'Restore') {
        $directory = $BackupDirectory
        if (-not $directory) {
            $root = Join-Path $script:Root 'backups'
            $backup = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Where-Object {
                try { ([IO.File]::ReadAllText((Join-Path $_.FullName 'manifest.json')) | ConvertFrom-Json).State -eq 'Applied' } catch { $false }
            } | Select-Object -First 1)
            if ($backup.Count -eq 0) { throw '没有可还原的完整修复备份。' }
            $directory = $backup[0].FullName
        }
        Restore-RepairBackup $directory
        Send-EnvironmentRefresh
        Write-Status '请完全退出并重开 Codex；必要时注销后重新登录 Windows。'
        return
    }
    $codexHome = Get-CodexHome
    foreach ($scope in @('User','Process','Machine')) {
        foreach ($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')) {
            Write-Status ('{0} {1}: {2}' -f $scope,$key,(Get-ProxyLabel ([Environment]::GetEnvironmentVariable($key,$scope))))
        }
    }
    if ([IO.File]::Exists((Join-Path $codexHome '.env.txt'))) {
        Write-Status '提示：发现 .env.txt；它不同于 .env，本工具不修改这个文件。'
    }
    $candidates = @(Get-CandidateAddresses $ProxyUrl $codexHome)
    $selected = $null
    foreach ($candidate in $candidates) {
        if (-not (Test-ProxyPort $candidate)) { Write-Status ('未监听/连接失败：' + $candidate); continue }
        Write-Status ('验证 HTTP/Mixed 代理：' + $candidate)
        if (Test-ProxyRoute $candidate $TimeoutSec) { $selected=$candidate; break }
    }
    if (-not $selected) {
        throw '未找到通过 HTTPS 验证的本机 HTTP/Mixed 代理，未修改配置。请先打开代理软件、检查节点，或用 -ProxyUrl 指定实际端口。'
    }
    Write-Status ('选定代理：' + $selected)
    $plan = New-RepairPlan $selected $codexHome ([bool]$ProxyUrl)
    Write-Status ('计划更新：用户环境变量 {0} 项，Codex 配置文件 {1} 个。' -f $plan.Environment.Count,$plan.Files.Count)
    foreach ($item in $plan.Environment) { Write-Status ('  用户环境：' + $item.Key) }
    foreach ($item in $plan.Files) { Write-Status ('  Codex 文件：' + [IO.Path]::GetFileName($item.Path)) }
    if ($Mode -eq 'Diagnose') { Write-Status '仅诊断完成：没有修改环境变量或 Codex 配置。'; return }
    $backup = Apply-RepairPlan $plan $script:Root
    if ($backup) { Write-Status ('修复已写入并校验。备份：' + $backup); Send-EnvironmentRefresh }
    else { Write-Status '当前持久配置已匹配可用代理，无需重复修改。' }
    Write-Status '下一步：保持代理软件运行，保存工作并完全退出 Codex（包括托盘），再用原图标打开。'
    Write-Status '本工具验证了代理 CONNECT/TLS 和服务端响应；重开后请发送一条消息验证登录和流式连接。'
    Write-Status '若仍继承旧环境，请注销并重新登录 Windows。代理端口改变后可重新运行本工具。'
}

if ($MyInvocation.InvocationName -eq '.') { return }
$exitCode = 0
try { Invoke-CodexNetworkTool }
catch { Write-Status ('未完成：' + $_.Exception.Message); $exitCode=1 }
finally {
    try {
        $logRoot = Join-Path $script:Root 'logs'
        [void][IO.Directory]::CreateDirectory($logRoot)
        $logPath = Join-Path $logRoot ((Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.txt')
        [IO.File]::WriteAllLines($logPath,$script:Log,$script:Utf8)
        Write-Host ('诊断记录：' + $logPath)
    } catch { Write-Host '无法保存诊断记录；请先完整解压到桌面等可写目录。' }
}
exit $exitCode
