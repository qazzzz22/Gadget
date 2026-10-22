#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '2.0.0',
    [string]$OutputDirectory,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'dist' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$archivePath = Join-Path $OutputDirectory ('Codex-Proxy-Repair-v' + $Version + '.zip')
if (Test-Path -LiteralPath $archivePath) {
    if (-not $Force) { throw 'Archive already exists. Use -Force to rebuild this release.' }
    Remove-Item -LiteralPath $archivePath
}
$files = @('Fix-CodexNetwork.ps1','一键修复.cmd','仅诊断.cmd','还原上次修复.cmd','README.md','LICENSE')
foreach ($name in $files) {
    if (-not [IO.File]::Exists((Join-Path $repoRoot $name))) { throw ('Missing release file: ' + $name) }
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($name in $files) {
        $entry = $archive.CreateEntry(('Codex-Proxy-Repair-v' + $Version + '/' + $name),[IO.Compression.CompressionLevel]::Optimal)
        $stream = $entry.Open()
        try {
            $path = Join-Path $repoRoot $name
            $bytes = [IO.File]::ReadAllBytes($path)
            if ($name.EndsWith('.cmd')) {
                $text = [IO.File]::ReadAllText($path) -replace '\r?\n',"`r`n"
                $bytes = [Text.Encoding]::ASCII.GetBytes($text)
            }
            $stream.Write($bytes,0,$bytes.Length)
        } finally { $stream.Dispose() }
    }
} finally { $archive.Dispose() }
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archivePath + '.sha256'),($hash + '  ' + [IO.Path]::GetFileName($archivePath) + "`r`n"),[Text.Encoding]::ASCII)
Write-Output $archivePath
Write-Output ($archivePath + '.sha256')
