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
    # Without read access to C:\PCPorterCI (setups made before users could read it) the file just looks missing. Running
    # an installed copy nobody can compare with the repo would test an unknown script, so that is a failure.
    $installedHash = try { (Get-FileHash -LiteralPath $installed -ErrorAction Stop).Hash } catch { 'unreadable' }
    if ($installedHash -eq 'unreadable') {
        Write-Host "FAIL cannot read the installed $installed to compare it with the repo (missing, or set up before users got read access). Re-run scripts\regress\install-smoke-task.ps1 in an administrator PowerShell 7." -ForegroundColor Red
        return $false
    } elseif ($installedHash -ne (Get-FileHash $repoSmoke).Hash) {
        Write-Host 'smoke.ps1 changed since the task was set up. Re-run scripts\regress\install-smoke-task.ps1 as administrator.' -ForegroundColor Yellow
        return $false
    }

    Write-Host "Publishing to $dist"
    dotnet publish (Join-Path $repo 'src\PCPorter.App') -p:PublishProfile=win-x64 -o $dist -nologo -v q | Out-File (Join-Path $run 'publish.txt')
    if ($LASTEXITCODE -ne 0) { Write-Host 'PUBLISH FAILED (see publish.txt)' -ForegroundColor Red; return $false }

    # A fresh fake drive every run: a leftover one from an older build would let a broken export pass unnoticed.
    if (Test-Path -LiteralPath $fixture) {
        try { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop }
        catch { Write-Host "Could not delete the old fake drive at ${fixture}: $($_.Exception.Message)" -ForegroundColor Red; return $false }
    }
    New-Item -ItemType Directory -Force $fixture | Out-Null
    $fixtureLog = Join-Path $run 'fixture.txt'
    $env:PCPORTER_FIXTURE_OUT = $fixture
    try {
        dotnet test (Join-Path $repo 'tests\PCPorter.Reports.Tests') --no-build --filter 'FullyQualifiedName~Export_fixture_drive_for_the_smoke_run' -nologo 2>&1 | Out-File $fixtureLog
        $fixtureCode = $LASTEXITCODE
    }
    finally { Remove-Item Env:PCPORTER_FIXTURE_OUT }
    # A filter that matches nothing also exits 0: require the export test itself to have passed.
    $exported = Select-String -Path $fixtureLog -Pattern 'Passed:\s+[1-9]' -Quiet
    if ($fixtureCode -ne 0 -or -not $exported) { Write-Host "Writing the fake drive failed (dotnet test exit $fixtureCode; see fixture.txt)" -ForegroundColor Red; return $false }
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
    function Invoke-Edge([string[]] $Arguments, [string] $Out, [string] $Err, [string] $EdgeProfile) {
        $p = Start-Process $edge -ArgumentList $Arguments -RedirectStandardOutput $Out -RedirectStandardError $Err -NoNewWindow -PassThru
        if ($p.WaitForExit(120000)) { return $true }
        Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($EdgeProfile) } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        return $false
    }
    if ($edge) {
        $profileDir = Join-Path $run 'edge-profile'
        $n = 0
        foreach ($report in Get-ChildItem $result.folder -Recurse -Include 'HealthReport.html', 'Thumbnails.html', 'History.html') {
            $n++
            $uri = ([Uri]$report.FullName).AbsoluteUri
            # Edge is a GUI program: '&' neither waits for it nor captures its output, so use Start-Process with files.
            $common = '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions', "--user-data-dir=$profileDir$n", '--enable-logging=stderr', '--v=0'
            $domFile = Join-Path $run "render$n.dom.html"; $errFile = Join-Path $run "render$n.err.txt"
            # Headless Edge sometimes never exits after writing its output: each run gets 2 minutes, then its own processes
            # (found by this run's private profile folder) are stopped. A timed-out DOM dump fails the check below.
            $timedOut = -not (Invoke-Edge ($common + '--dump-dom', $uri) $domFile $errFile "$profileDir$n")
            $timedOut = (-not (Invoke-Edge ($common + '--window-size=1280,2400', "--screenshot=$(Join-Path $run "render$n.png")", $uri) `
                (Join-Path $run "render$n.shot.txt") (Join-Path $run "render$n.shot.err.txt") "$profileDir$n")) -or $timedOut
            if ($timedOut) { Write-Host "  note: Edge did not exit within 2 minutes for render$n; it was stopped" -ForegroundColor Yellow }
            # Only the report's own script errors count (Edge's built-in extensions log noise such as "browser is shutting down").
            $errors = Select-String -Path $errFile -Pattern 'Uncaught|CONSOLE.*[Ee]rror' | Where-Object { $_.Line -match 'source: file:' -or $_.Line -match 'Uncaught' }
            # Each marker is written by the page's own script, so it is only there if the script ran through (a page whose
            # script died still has its static HTML, footer and </body>). HealthReport has no script: its read-only footer.
            # History's script fills the form-entries count as its last table. The gallery's script fills "N of M shown"
            # in #count from apply(), its last step; data-rendered="true" on <html> or <body> is accepted too, should
            # the gallery page set that marker explicitly at the end of its script.
            $expect = switch ($report.Name) {
                'HealthReport.html' { 'Read-only scan\. Nothing was changed' }
                'History.html' { 'id="forms-count">\(\d' }
                'Thumbnails.html' { 'id="count">[^<]*\d[^<]* shown<|<(html|body)[^>]*\sdata-rendered="true"' }
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
