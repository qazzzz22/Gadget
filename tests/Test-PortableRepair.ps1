#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
. (Join-Path $workspace 'Fix-CodexNetwork.ps1')
$script:TestCount = 0
function Assert-True($Value,[string]$Message) {
    $script:TestCount++
    if (-not $Value) { throw ('ASSERT: ' + $Message) }
}
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-True $failed $Message
}

$realEnvironment = @{}
foreach ($key in $script:Keys) { $realEnvironment[$key]=[Environment]::GetEnvironmentVariable($key,'User') }
$script:FakeEnvironment = @{}
$script:FailNextWrite = $false
function Get-UserProxyValue([string]$Key) { return $script:FakeEnvironment[$Key] }
function Set-UserProxyValue([string]$Key,$Value) {
    if ($script:FailNextWrite -and $Key -eq 'HTTPS_PROXY') {
        $script:FailNextWrite=$false
        throw 'Injected write failure'
    }
    $script:FakeEnvironment[$Key]=$Value
}
$script:FixtureHome = Join-Path $PSScriptRoot ('fixture-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:FixtureHome)
function Get-CodexHome { return $script:FixtureHome }

Assert-True ((ConvertTo-LocalHttpProxy '127.0.0.1:12345') -eq 'http://127.0.0.1:12345') 'normalize local address'
foreach ($bad in @('http://example.com:80','http://user:password@127.0.0.1:7890','socks5://127.0.0.1:7890',
    'http://127.0.0.1:7890/path','http://127.0.0.1:7890/?query','http://127.0.0.1:7890/#fragment',
    'http://127.0.0.1:70000','http://127.0.0.1:7890 & echo bad')) {
    Assert-True (-not (ConvertTo-LocalHttpProxy $bad)) ('reject unsafe/unsupported address: ' + $bad)
}
Assert-True ((ConvertTo-LocalHttpProxy 'http://[::1]:7897') -eq 'http://[::1]:7897') 'IPv6 loopback'
Assert-True (Test-LocalProxyAddress 'socks5://127.0.0.1:7890') 'allow replacing stale local SOCKS env after HTTP route validation'
Assert-True (-not (Test-LocalProxyAddress 'http://secret@127.0.0.1:7890')) 'protect authenticated proxies'
Assert-True ((Get-ProxyLabel 'http://secret:password@proxy.example:8080') -notmatch 'secret|password|example') 'redact credentials and remote hosts'

$noProxy = Repair-NoProxy '*,.openai.com,chatgpt.com,*.chatgpt.com,.internal,10.0.0.0/8,localhost'
Assert-True ($noProxy -eq '.internal,10.0.0.0/8,localhost,127.0.0.1,::1') 'remove service bypasses while preserving other exclusions'
Assert-True ((Repair-NoProxy $noProxy) -eq $noProxy) 'NO_PROXY idempotent'

$cases = @(
    "[shell_environment_policy]`r`ninclude_only = [`"PATH`"]`r`n[desktop]`r`nx=1`r`n",
    "[shell_environment_policy]`ninclude_only = [`n`"PATH`", # keep PATH`n]`n",
    "[shell_environment_policy]`ninclude_only = []`n",
    "[shell_environment_policy]`ninclude_only = [`"PATH`" # trailing comment`n]`n",
    "[shell_environment_policy]`ninclude_only = [# nothing yet`n]`n"
)
foreach ($source in $cases) {
    $updated=Update-ShellAllowlist $source
    Assert-True ($updated -match 'SystemRoot' -and $updated -match 'NO_PROXY') 'fill missing Windows and proxy variables'
    Assert-True ((Update-ShellAllowlist $updated) -ceq $updated) 'allowlist idempotent'
}
Assert-True ((Update-ShellAllowlist "model='x'`n") -eq "model='x'`n") 'do not create new policy'
Assert-True ((Update-ShellAllowlist "[shell_environment_policy]`ninclude_only=['*']`n") -eq "[shell_environment_policy]`ninclude_only=['*']`n") 'respect wildcard coverage'
Assert-Throws { Update-ShellAllowlist "[shell_environment_policy]`ninherit='none'`ninclude_only=[]`n" } 'preserve restrictive inheritance policy'
Assert-Throws { Update-ShellAllowlist "[shell_environment_policy]`ninclude_only=[]`nexclude=['HTTP*']`n" } 'refuse policy conflicts'

$envText = "# heading`r`n`r`nexport http_proxy='http://127.0.0.1:7890' # old`r`nHTTPS_PROXY=http://127.0.0.1:7890`r`nTOKEN=fake-test-value`r`n"
$entries = @(Get-EnvProxyEntries $envText)
Assert-True ($entries.Count -eq 2) 'parse only proxy assignments'
Assert-True ($entries[0].Value -eq 'http://127.0.0.1:7890') 'parse quoted dotenv with comment'

$configPath = Join-Path $script:FixtureHome 'config.toml'
$envPath = Join-Path $script:FixtureHome '.env'
$beforeConfig = "model='unchanged'`r`n[shell_environment_policy]`r`ninclude_only=['PATH']`r`n[desktop]`r`nlocale='zh-CN'`r`n"
[IO.File]::WriteAllText($configPath,$beforeConfig,(New-Object Text.UTF8Encoding($true)))
[IO.File]::WriteAllText($envPath,$envText,(New-Object Text.UnicodeEncoding($false,$true)))
$originalConfig=[IO.File]::ReadAllBytes($configPath)
$originalEnv=[IO.File]::ReadAllBytes($envPath)
foreach ($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')) { $script:FakeEnvironment[$key]='http://127.0.0.1:7890' }
$script:FakeEnvironment['NO_PROXY']='*,.internal'
$plan = New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome
Assert-True ($plan.Environment.Count -eq 4 -and $plan.Files.Count -eq 2) 'plan covers stale env and Codex overrides'
Assert-True ($plan.Files[1].After[0] -eq 255 -and $plan.Files[1].After[1] -eq 254) 'preserve UTF16 BOM'
Assert-True ($plan.Files[0].After[0] -eq 239 -and $plan.Files[0].After[1] -eq 187) 'preserve UTF8 BOM'
$backupRoot = Join-Path $script:FixtureHome 'tool'
[void][IO.Directory]::CreateDirectory($backupRoot)
$backup = Apply-RepairPlan $plan $backupRoot
Assert-True ($script:FakeEnvironment['HTTP_PROXY'] -eq 'http://127.0.0.1:12345') 'apply env'
$document=Get-TextDocument $envPath
Assert-True ($document.Text.Contains('TOKEN=fake-test-value') -and $document.Text.Contains('# heading')) 'preserve unrelated dotenv settings'
Assert-True ($document.Text.Contains("`r`n`r`n")) 'preserve blank lines'
$noChange=New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome
Assert-True ($noChange.Environment.Count -eq 0 -and $noChange.Files.Count -eq 0) 'repair is fully idempotent'
Assert-True (([IO.File]::ReadAllText((Join-Path $backup 'manifest.json')) | ConvertFrom-Json).State -eq 'Applied') 'committed backup state'
Restore-RepairBackup $backup
Assert-True ((Get-BytesHash ([IO.File]::ReadAllBytes($configPath))) -eq (Get-BytesHash $originalConfig)) 'restore exact config bytes'
Assert-True ((Get-BytesHash ([IO.File]::ReadAllBytes($envPath))) -eq (Get-BytesHash $originalEnv)) 'restore exact dotenv bytes'
Assert-True ($script:FakeEnvironment['HTTP_PROXY'] -eq 'http://127.0.0.1:7890') 'restore env'
Assert-Throws { Restore-RepairBackup $backup } 'reject double restore'

$plan = New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome
$script:FailNextWrite=$true
Assert-Throws { Apply-RepairPlan $plan $backupRoot } 'rollback on injected second variable failure'
Assert-True ($script:FakeEnvironment['HTTP_PROXY'] -eq 'http://127.0.0.1:7890') 'first variable rolled back'
Assert-True ((Get-BytesHash ([IO.File]::ReadAllBytes($configPath))) -eq (Get-BytesHash $originalConfig)) 'files untouched after early failure'

$plan=New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome
[IO.File]::AppendAllText($configPath,"# later change`r`n")
Assert-Throws { Apply-RepairPlan $plan $backupRoot } 'detect concurrent file change before apply'
Assert-True (([IO.File]::ReadAllText($configPath)).Contains('# later change')) 'preserve concurrent change'
Assert-True ($script:FakeEnvironment['HTTP_PROXY'] -eq 'http://127.0.0.1:7890') 'rollback env after file race'

$plan=New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome
$backup=Apply-RepairPlan $plan $backupRoot
[IO.File]::AppendAllText($configPath,"# changed after repair`r`n")
Assert-Throws { Restore-RepairBackup $backup } 'refuse overwriting later file edits'
Assert-True ($script:FakeEnvironment['HTTP_PROXY'] -eq 'http://127.0.0.1:12345') 'preflight restore makes no partial env changes'

$script:FakeEnvironment['HTTP_PROXY']='http://company.example:3128'
Assert-Throws { New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome } 'protect remote user proxy'
$explicit = New-RepairPlan 'http://127.0.0.1:12345' $script:FixtureHome $true
Assert-True ($explicit.Environment.Count -gt 0) 'explicit local address authorizes replacing remote configuration'

foreach ($key in $script:Keys) {
    Assert-True ([Environment]::GetEnvironmentVariable($key,'User') -ceq $realEnvironment[$key]) 'real user environment untouched by tests'
}
Write-Output ('PASS: ' + $script:TestCount + ' checks; only temporary fixtures and fake environment were modified.')
Write-Output ('Fixtures: ' + $script:FixtureHome)
