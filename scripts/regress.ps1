<#
.SYNOPSIS
  PCPorter regression tests, one entry point (plan: docs/plans/2026-11-26-regression-testing.md).

.DESCRIPTION
  -Level fast     Tiers 1-3: unit, report golden and fixture tests. No admin, no live data. About 1 minute.
  -Level full     fast + the tests that read this PC's own data (Category=Live). About 6 minutes.
  -Level release  full + the packaged-EXE smoke run (tier 4, one UAC prompt) when scripts\regress\smoke.ps1 exists.

  Results go to C:\PCPorterCases\regress\<timestamp>\ (never the repo or OneDrive). Exit code 0 = all passed.

.EXAMPLE
  .\scripts\regress.ps1
  .\scripts\regress.ps1 -Level full
  .\scripts\regress.ps1 -Accept      # rewrite the golden files from this run, then review the change with git diff
#>
#Requires -Version 7
param(
    [ValidateSet('fast', 'full', 'release')] [string] $Level = 'fast',
    [string] $OutRoot = 'C:\PCPorterCases\regress',
    [switch] $Accept,
    [switch] $SkipTests   # with -Level release: re-run only tier 4 (publish, fake drive, smoke task, render check)
)
$ErrorActionPreference = 'Stop'

# A PCPORTER_ACCEPT left set in the shell would make every golden test pass by rewriting its file.
if ($env:PCPORTER_ACCEPT -and -not $Accept) {
    Write-Host 'PCPORTER_ACCEPT is set in this shell, which would silently rewrite the golden files. Use -Accept instead, or run: Remove-Item Env:PCPORTER_ACCEPT' -ForegroundColor Red
    exit 3
}
if ($Accept) { $env:PCPORTER_ACCEPT = '1' }
$repo = Split-Path $PSScriptRoot -Parent
$run = Join-Path $OutRoot (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Force $run | Out-Null

function Invoke-Smoke {
    <# Tier 4: publish, write the fake drive, run the elevated smoke task, then check the reports render in Edge. #>
    $dist = 'C:\PCPorter-dist\PCPorter'
    $fixture = Join-Path $OutRoot 'fixture-oldpc'
    $installed = 'C:\PCPorterCI\smoke.ps1'
    $repoSmoke = Join-Path $PSScriptRoot 'regress\smoke.ps1'
    if (-not (Get-ScheduledTask -TaskName 'PCPorterSmoke' -ErrorAction SilentlyContinue)) {
        Write-Host 'Tier 4 needs a one-time setup. In an administrator PowerShell 7 run: scripts\regress\install-smoke-task.ps1' -ForegroundColor Yellow
        return $false
    }
    # Without read access to C:\PCPorterCI (setups made before users could read it) the file just looks missing.
    $installedHash = try { (Get-FileHash -LiteralPath $installed -ErrorAction Stop).Hash } catch { 'unreadable' }
    if ($installedHash -eq 'unreadable') {
        Write-Host 'Cannot read the installed smoke.ps1 to compare it with the repo (set up before users got read access); running it anyway. Re-run install-smoke-task.ps1 as administrator to enable the check.' -ForegroundColor Yellow
    } elseif ($installedHash -ne (Get-FileHash $repoSmoke).Hash) {
        Write-Host 'smoke.ps1 changed since the task was set up. Re-run scripts\regress\install-smoke-task.ps1 as administrator.' -ForegroundColor Yellow
        return $false
    }

    Write-Host "Publishing to $dist"
    dotnet publish (Join-Path $repo 'src\PCPorter.App') -p:PublishProfile=win-x64 -o $dist -nologo -v q | Out-File (Join-Path $run 'publish.txt')
    if ($LASTEXITCODE -ne 0) { Write-Host 'PUBLISH FAILED (see publish.txt)' -ForegroundColor Red; return $false }

    $env:PCPORTER_FIXTURE_OUT = $fixture
    try { dotnet test (Join-Path $repo 'tests\PCPorter.Reports.Tests') --no-build --filter 'FullyQualifiedName~Export_fixture_drive_for_the_smoke_run' -nologo | Out-File (Join-Path $run 'fixture.txt') }
    finally { Remove-Item Env:PCPORTER_FIXTURE_OUT }
    if (-not (Test-Path (Join-Path $fixture 'Windows\System32\config\SOFTWARE'))) { Write-Host 'Could not write the fake drive (see fixture.txt)' -ForegroundColor Red; return $false }

    Write-Host 'Running the elevated smoke task (several minutes)...'
    $start = Get-Date
    Start-ScheduledTask -TaskName 'PCPorterSmoke'
    do {
        Start-Sleep -Seconds 5
        $state = (Get-ScheduledTask -TaskName 'PCPorterSmoke').State
        if (((Get-Date) - $start).TotalMinutes -gt 45) { Write-Host 'The smoke task took more than 45 minutes; stopping.' -ForegroundColor Red; Stop-ScheduledTask -TaskName 'PCPorterSmoke'; return $false }
    } while ($state -eq 'Running' -or ((Get-Date) - $start).TotalSeconds -lt 10)

    $last = Join-Path $OutRoot 'smoke-last.json'
    $result = if (Test-Path $last) { Get-Content $last -Raw | ConvertFrom-Json } else { $null }
    if (-not $result -or [datetime]$result.started -lt $start.AddSeconds(-5)) { Write-Host 'The smoke task left no new result.' -ForegroundColor Red; return $false }
    foreach ($c in $result.checks) {
        $color = @{ PASS = 'Gray'; SKIP = 'Yellow'; FAIL = 'Red' }[$c.status]
        Write-Host ("  {0,-4} {1}{2}" -f $c.status, $c.name, $(if ($c.detail) { " - $($c.detail)" } else { '' })) -ForegroundColor $color
    }
    Write-Host "  smoke folder: $($result.folder)"

    # Render check (not elevated): every report opens in headless Edge, shows its footer and logs no script errors.
    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    $renderOk = $true
    if ($edge) {
        $profileDir = Join-Path $run 'edge-profile'
        $n = 0
        foreach ($report in Get-ChildItem $result.folder -Recurse -Include 'HealthReport.html', 'Thumbnails.html', 'History.html') {
            $n++
            $uri = ([Uri]$report.FullName).AbsoluteUri
            # Edge is a GUI program: '&' neither waits for it nor captures its output, so use Start-Process with files.
            $common = '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions', "--user-data-dir=$profileDir$n", '--enable-logging=stderr', '--v=0'
            $domFile = Join-Path $run "render$n.dom.html"; $errFile = Join-Path $run "render$n.err.txt"
            Start-Process $edge -ArgumentList ($common + '--dump-dom', $uri) -RedirectStandardOutput $domFile -RedirectStandardError $errFile -Wait -NoNewWindow
            Start-Process $edge -ArgumentList ($common + '--window-size=1280,2400', "--screenshot=$(Join-Path $run "render$n.png")", $uri) `
                -RedirectStandardOutput (Join-Path $run "render$n.shot.txt") -RedirectStandardError (Join-Path $run "render$n.shot.err.txt") -Wait -NoNewWindow
            # Only the report's own script errors count (Edge's built-in extensions log noise such as "browser is shutting down").
            $errors = Select-String -Path $errFile -Pattern 'Uncaught|CONSOLE.*[Ee]rror' | Where-Object { $_.Line -match 'source: file:' -or $_.Line -match 'Uncaught' }
            # HealthReport ends with its read-only footer; the gallery has no footer but must render to the end of its page;
            # History's script fills the form-entries count as its last table, so a count there means the script ran through.
            $expect = switch ($report.Name) {
                'HealthReport.html' { 'Read-only scan\. Nothing was changed' }
                'History.html' { 'id="forms-count">\(\d' }
                default { '</body>' }
            }
            $ok = (Get-Content $domFile -Raw) -match $expect -and -not $errors
            if (-not $ok) { $renderOk = $false }
            Write-Host ("  {0,-4} {1} renders in Edge (screenshot render{2}.png)" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $report.Name, $n) -ForegroundColor $(if ($ok) { 'Gray' } else { 'Red' })
        }
        if ($n -eq 0) { Write-Host '  FAIL no reports found to render' -ForegroundColor Red; $renderOk = $false }
    } else { Write-Host '  SKIP render check (Edge not found)' -ForegroundColor Yellow }
    return ($result.ok -and $renderOk)
}

$filter = switch ($Level) {
    'fast' { 'Category!=Live&Category!=Admin&Category!=Manual' }
    default { 'Category!=Admin&Category!=Manual' }
}

Write-Host "PCPorter regression: $Level -> $run"
$sw = [Diagnostics.Stopwatch]::StartNew()
Push-Location $repo
try {
    dotnet build -v q -nologo | Out-File (Join-Path $run 'build.txt')
    if ($LASTEXITCODE -ne 0) { Write-Host 'BUILD FAILED (see build.txt)' -ForegroundColor Red; exit 2 }
    if ($SkipTests) { Write-Host 'Tests skipped (-SkipTests).' -ForegroundColor Yellow; $testsOk = $true }
    else {
        dotnet test --no-build --filter $filter --logger 'trx' --results-directory (Join-Path $run 'trx') -nologo 2>&1 |
            Tee-Object (Join-Path $run 'test.txt') | Select-String -Pattern '^(Passed!|Failed!)|^\s+Failed ' | ForEach-Object { Write-Host $_.Line }
        $testsOk = $LASTEXITCODE -eq 0
        # A filter that matches nothing "passes": require a real test count.
        $total = (Select-String -Path (Join-Path $run 'test.txt') -Pattern 'Total:\s+(\d+)' | ForEach-Object { [int]$_.Matches[0].Groups[1].Value } | Measure-Object -Sum).Sum
        if ($total -lt 100) { Write-Host "Only $total tests ran; expected hundreds. Check the filter." -ForegroundColor Red; $testsOk = $false }
    }
}
finally {
    Pop-Location
    if ($Accept) { Remove-Item Env:PCPORTER_ACCEPT -ErrorAction SilentlyContinue; Write-Host 'Golden files rewritten: review them with git diff before committing.' -ForegroundColor Yellow }
}

$smokeOk = $true
if ($Level -eq 'release' -and $testsOk) { $smokeOk = [bool](Invoke-Smoke | Select-Object -Last 1) }

$ok = $testsOk -and $smokeOk
"level=$Level ok=$ok seconds=$([int]$sw.Elapsed.TotalSeconds)" | Out-File (Join-Path $run 'summary.txt')
Write-Host ("{0} in {1:0} s" -f ($(if ($ok) { 'ALL PASSED' } else { 'FAILURES' }), $sw.Elapsed.TotalSeconds)) -ForegroundColor ($(if ($ok) { 'Green' } else { 'Red' }))
exit ($(if ($ok) { 0 } else { 1 }))
