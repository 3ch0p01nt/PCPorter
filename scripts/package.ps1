<#
.SYNOPSIS
  Builds C:\PCPorter-dist\PCPorter.zip for another PC: the published EXE and its DLLs, HOW-TO-RUN.txt and baseline.ps1.

.DESCRIPTION
  By default it does NOT publish: it zips the build that the last smoke run tested, and refuses unless
    - the dist folder holds exactly the published files (the same list smoke.ps1 checks; HOW-TO-RUN.txt is allowed), and
    - <OutRoot>\smoke-last.json says ok, was not a -DryRun, started after the dist EXE was written, and recorded the
      same EXE SHA-256 as the dist EXE.
  So the usual order is: scripts\regress.ps1 -Level release (publishes, runs the smoke task), then this script.

  -Publish publishes first (the old behaviour). That build has not been smoke-tested, so the script prints
  "UNTESTED build" and refuses to zip unless -AllowUntested is also given. -AllowUntested also zips a dist folder that
  fails the checks above, with the same warning.

  Prints the zip's and the EXE's SHA-256. Exit code 0 = zip written, 2 = refused or failed.
#>
#Requires -Version 7
param(
    [string] $Dist = 'C:\PCPorter-dist\PCPorter',
    [string] $Zip = 'C:\PCPorter-dist\PCPorter.zip',
    [string] $SmokeResult = 'C:\PCPorterCases\regress\smoke-last.json',
    [switch] $Publish,
    [switch] $AllowUntested
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

function Stop-Refused([string] $Why) {
    Write-Host "NOT ZIPPED: $Why" -ForegroundColor Red
    Write-Host 'Run scripts\regress.ps1 -Level release (it publishes and smoke-tests the dist folder), then run this again.' -ForegroundColor Red
    Write-Host 'To zip anyway, add -AllowUntested (the zip is then an UNTESTED build).' -ForegroundColor Red
    exit 2
}

if ($Publish) {
    dotnet publish (Join-Path $repo 'src\PCPorter.App') -p:PublishProfile=win-x64 -o $Dist -nologo -v q
    if ($LASTEXITCODE -ne 0) { Write-Host 'PUBLISH FAILED' -ForegroundColor Red; exit 2 }
    Write-Host 'UNTESTED build: it was published just now and smoke.ps1 has not run on it.' -ForegroundColor Yellow
    if (-not $AllowUntested) { Stop-Refused 'the build was published by -Publish and is untested.' }
}

$exePath = Join-Path $Dist 'PCPorter.exe'
if (-not (Test-Path -LiteralPath $exePath)) { Write-Host "No PCPorter.exe in $Dist" -ForegroundColor Red; exit 2 }
$exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash

# ---- The gate: exactly the published files, and a passing smoke run of this very EXE ----
# Keep this list in step with section 1 of scripts\regress\smoke.ps1.
$expected = 'PCPorter.exe', 'D3DCompiler_47_cor3.dll', 'PenImc_cor3.dll', 'PresentationNative_cor3.dll', 'e_sqlite3.dll', 'vcruntime140_cor3.dll', 'wpfgfx_cor3.dll'
$problems = [System.Collections.Generic.List[string]]::new()
$found = @(Get-ChildItem -LiteralPath $Dist -File | Where-Object Name -ne 'HOW-TO-RUN.txt' | ForEach-Object Name)
$missing = @($expected | Where-Object { $_ -notin $found }); $extra = @($found | Where-Object { $_ -notin $expected })
if ($missing -or $extra) { $problems.Add("the dist folder is not exactly the published files (missing: $($missing -join ', '); extra: $($extra -join ', '))") }
$dirs = @(Get-ChildItem -LiteralPath $Dist -Directory)
if ($dirs) { $problems.Add("the dist folder has subfolders: $(($dirs | ForEach-Object Name) -join ', ')") }

$smoke = $null
if (-not (Test-Path -LiteralPath $SmokeResult)) { $problems.Add("no smoke result at $SmokeResult") }
else {
    try { $smoke = Get-Content -LiteralPath $SmokeResult -Raw | ConvertFrom-Json } catch { $problems.Add("$SmokeResult is not readable JSON") }
}
if ($smoke) {
    $exeTime = (Get-Item -LiteralPath $exePath).LastWriteTime
    $started = try { [datetime] $smoke.started } catch { $null }
    if ($smoke.ok -ne $true) { $problems.Add("the last smoke run failed ($($smoke.failed) checks; see $($smoke.folder))") }
    if ($smoke.dryRun -eq $true) { $problems.Add('the last smoke run was a -DryRun') }
    if (-not $started) { $problems.Add('the smoke result has no start time') }
    elseif ($started -lt $exeTime) { $problems.Add("the last smoke run ($($started.ToString('s'))) is older than the dist EXE ($($exeTime.ToString('s')))") }
    $smokeHash = $smoke.facts.exeSha256
    if (-not $smokeHash) { $problems.Add('the smoke result records no EXE SHA-256') }
    elseif ($smokeHash -ne $exeHash) { $problems.Add("the smoke run tested a different EXE (SHA-256 $($smokeHash.Substring(0, 12))..., dist EXE $($exeHash.Substring(0, 12))...)") }
}

if ($problems.Count) {
    if (-not $AllowUntested) { Stop-Refused ($problems -join '; ') }
    Write-Host 'UNTESTED build: zipping anyway (-AllowUntested) although:' -ForegroundColor Yellow
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
} else {
    Write-Host "Smoke-tested build: smoke run $($smoke.started) passed on this EXE." -ForegroundColor Green
}

$howTo = Join-Path $repo 'packaging\HOW-TO-RUN.txt'
Copy-Item $howTo (Join-Path $Dist 'HOW-TO-RUN.txt') -Force   # keeps the folder copy in step with the repo

# The published files plus the extras. baseline.ps1 is not copied into the dist folder: the smoke run checks that the
# folder holds exactly the published files.
$files = @(Get-ChildItem -LiteralPath $Dist -File) + (Get-Item (Join-Path $repo 'scripts\regress\baseline.ps1'))
Remove-Item $Zip -ErrorAction SilentlyContinue
Compress-Archive -LiteralPath $files.FullName -DestinationPath $Zip -CompressionLevel Optimal

Get-Item $Zip | ForEach-Object { '{0}  {1:N0} bytes' -f $_.FullName, $_.Length }
'zip SHA-256 {0}' -f (Get-FileHash $Zip).Hash
'exe SHA-256 {0}' -f $exeHash
'files: ' + (($files | ForEach-Object Name | Sort-Object) -join ', ')
if ($problems.Count) { Write-Host 'UNTESTED build in this zip.' -ForegroundColor Yellow }
