<#
.SYNOPSIS
  Tier 5: real-PC baseline (plan: docs/plans/2026-11-26-regression-testing.md). Runs on the TARGET PC, next to PCPorter.exe.

.DESCRIPTION
  Runs a health scan, writes a SCRUBBED summary of it (counts, statuses and rule ids only: no names, paths or URLs) to
  C:\PCPorterCases\baselines\<time>.json, then compares it with the accepted baseline (or, before one is accepted, with
  the previous summary) and lists what changed:
    - more High startup findings for a rule, or a security check that became "Risk"
    - any security check whose status changed
    - an item count that changed by more than 10%
    - a part of the scan that was Ok and now is not
    - the scan taking more than twice as long
    - a different exit code
  Review the flags. If the changes are expected (new PCPorter version, apps installed on purpose), run with -Accept to
  make the newest summary the baseline. Summaries never leave this PC.

  Works in Windows PowerShell 5.1 (built into Windows) and PowerShell 7. The scan needs an administrator window.
  The full scan results (HealthReport.html, case.db) are kept under C:\PCPorterCases\baselines\cases.

  Exit codes: 0 nothing changed, 1 changes flagged (or first baseline), 2 failed, 4 not run as administrator.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\baseline.ps1            # scan, summarize, compare
  powershell -ExecutionPolicy Bypass -File .\baseline.ps1 -Accept    # the newest summary becomes the baseline
  powershell -ExecutionPolicy Bypass -File .\baseline.ps1 -Case <case folder>   # summarize an existing scan (no admin)
#>
param(
    [string] $Exe = (Join-Path $PSScriptRoot 'PCPorter.exe'),
    [string] $Root = 'C:\PCPorterCases\baselines',
    [string] $Case,      # summarize this existing case folder instead of scanning (run time and part statuses are then unknown)
    [switch] $Accept
)
$ErrorActionPreference = 'Stop'
$acceptedFile = Join-Path $Root 'accepted.json'

function Get-Summaries { @(Get-ChildItem -LiteralPath $Root -Filter '2*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name) }

function Get-Count($Items, [scriptblock] $Key) {
    $map = [ordered]@{}
    # An empty key would make the file unreadable for Windows PowerShell 5.1's ConvertFrom-Json.
    foreach ($i in $Items) { $k = [string](& $Key $i); if (-not $k) { $k = '(none)' }; if ($map.Contains($k)) { $map[$k]++ } else { $map[$k] = 1 } }
    $sorted = [ordered]@{}
    foreach ($k in ($map.Keys | Sort-Object)) { $sorted[$k] = $map[$k] }
    $sorted
}

function Read-Kind([string] $CaseDir, [string] $Kind) {
    $f = Join-Path $CaseDir "scan\$Kind.json"
    if (Test-Path -LiteralPath $f) { Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
}

function New-Summary([string] $CaseDir, $ScanOut, $Seconds, $ExitCode) {
    $persist = Read-Kind $CaseDir 'persistence'
    $posture = Read-Kind $CaseDir 'posture'
    $apps = Read-Kind $CaseDir 'apps'
    $av = Read-Kind $CaseDir 'av'
    $prof = Read-Kind $CaseDir 'profile'
    $docs = [ordered]@{ persistence = $persist; posture = $posture; apps = $apps; av = $av; profile = $prof }
    $any = @($docs.Values) | Where-Object { $_ } | Select-Object -First 1

    $s = [ordered]@{
        schema      = 1
        created     = (Get-Date).ToString('o')
        toolVersion = if ($any) { $any.toolVersion } else { $null }
        osBuild     = if ($any) { $any.source.osBuild } else { $null }
        mode        = if ($any) { $any.source.mode } else { $null }
        seconds     = $Seconds
        exitCode    = $ExitCode
        status      = if ($ScanOut) { $ScanOut.summary.status } else { $null }
        findings    = if ($ScanOut) { [ordered]@{ worthALook = $ScanOut.summary.findings.worthALook; unusual = $ScanOut.summary.findings.unusual } } else { $null }
        parts       = [ordered]@{}
        counts      = [ordered]@{}
        startup     = [ordered]@{}
        posture     = [ordered]@{}
        apps        = [ordered]@{}
        antivirus   = [ordered]@{}
        reportRows  = $null
    }
    if ($ScanOut) { foreach ($c in $ScanOut.summary.collectors) { $s.parts[$c.name] = $c.status } }
    foreach ($k in $docs.Keys) { if ($docs[$k]) { $s.counts[$k] = @($docs[$k].items).Count } }
    if ($persist) {
        $items = @($persist.items)
        $s.startup['bySeverity'] = Get-Count $items { param($i) if ($i.isHidden) { 'Hidden' } else { $i.severity } }
        # rule|severity, so "more High findings for a rule" can be told apart from more Low ones.
        $s.startup['byRule'] = Get-Count ($items | Where-Object { -not $_.isHidden -and $_.ruleId }) { param($i) "$($i.ruleId)|$($i.severity)" }
        $s.startup['disabled'] = @($items | Where-Object { $_.disabled }).Count
        $s.startup['bySignature'] = Get-Count $items { param($i) $i.signatureStatus }
    }
    if ($posture) {
        # Per-extension rows carry the extension id: counted by status, not listed.
        foreach ($p in @($posture.items) | Where-Object { $_.id -notlike 'browser-extension:*' }) { $s.posture[$p.id] = $p.status }
        $ext = @($posture.items) | Where-Object { $_.id -like 'browser-extension:*' }
        foreach ($g in (Get-Count $ext { param($i) $i.status }).GetEnumerator()) { $s.posture["browser-extension:* $($g.Key)"] = "$($g.Value)" }
    }
    if ($apps) {
        $items = @($apps.items)
        $s.apps['byMatch'] = Get-Count $items { param($i) $i.matchMethod }
        $s.apps['byKind'] = Get-Count $items { param($i) $i.kind }
        $s.apps['reinstallCandidates'] = @($items | Where-Object { $_.reinstallCandidate }).Count
    }
    if ($av) { $s.antivirus = Get-Count @($av.items) { param($i) "$($i.status)|$($i.state)" } }
    $report = Join-Path $CaseDir 'HealthReport.html'
    if (Test-Path -LiteralPath $report) { $s.reportRows = ([regex]::Matches((Get-Content -LiteralPath $report -Raw -Encoding UTF8), '<tr[\s>]')).Count }
    $s
}

function Test-Scrubbed([string] $Json) {
    # Guard: a summary must never carry this PC's or user's name, or a path.
    $bad = @($env:COMPUTERNAME, $env:USERNAME) | Where-Object { $_ -and $_.Length -ge 3 -and $Json -match [regex]::Escape($_) }
    if ($bad) { return "contains a computer or user name" }
    if ($Json -match '[A-Za-z]:\\\\|\\\\\\\\|https?://') { return 'contains a path or URL' }
    $null
}

function Get-Prop($Obj, [string] $Name) { if ($Obj -and $Obj.PSObject.Properties[$Name]) { $Obj.PSObject.Properties[$Name].Value } else { $null } }
function Get-Names($Obj) { if ($Obj) { @($Obj.PSObject.Properties | ForEach-Object Name) } else { @() } }

function Compare-Summary($Old, $New) {
    $flags = New-Object System.Collections.Generic.List[string]
    # New High startup findings, per rule.
    $oldRules = Get-Prop $Old.startup 'byRule'; $newRules = Get-Prop $New.startup 'byRule'
    foreach ($k in (Get-Names $newRules | Where-Object { $_ -like '*|High' })) {
        $was = [int](Get-Prop $oldRules $k); $now = [int](Get-Prop $newRules $k)
        if ($now -gt $was) { $flags.Add("NEW HIGH  startup rule $($k.Split('|')[0]): $was -> $now") }
    }
    # Security checks.
    foreach ($k in ((Get-Names $Old.posture) + (Get-Names $New.posture) | Sort-Object -Unique)) {
        $a = Get-Prop $Old.posture $k; $b = Get-Prop $New.posture $k
        if ($a -ne $b) {
            $tag = if ($b -eq 'Risk' -or ($k -like 'browser-extension:* Risk')) { 'NEW RISK ' } else { 'POSTURE  ' }
            $flags.Add("$tag $k`: $(if ($null -eq $a) { '(none)' } else { $a }) -> $(if ($null -eq $b) { '(none)' } else { $b })")
        }
    }
    # Item counts: more than 10% (and at least 2 items, so 1 -> 2 on a small list is not noise).
    foreach ($k in (Get-Names $New.counts)) {
        $a = Get-Prop $Old.counts $k; $b = Get-Prop $New.counts $k
        if ($null -eq $a) { continue }
        $diff = [math]::Abs([int]$b - [int]$a)
        if ($diff -ge 2 -and $diff -gt 0.10 * [math]::Max([int]$a, 1)) { $flags.Add("COUNT     $k items: $a -> $b") }
    }
    # Parts of the scan that were Ok.
    foreach ($k in (Get-Names $Old.parts)) {
        $a = Get-Prop $Old.parts $k; $b = Get-Prop $New.parts $k
        if ($a -eq 'Ok' -and $null -ne $b -and $b -ne 'Ok') { $flags.Add("PART      $k`: Ok -> $b") }
    }
    if ($Old.seconds -and $New.seconds -and $New.seconds -gt 2 * $Old.seconds) { $flags.Add("SLOW      scan took $($New.seconds) s, was $($Old.seconds) s") }
    if ($null -ne $Old.exitCode -and $null -ne $New.exitCode -and $Old.exitCode -ne $New.exitCode) { $flags.Add("EXIT      exit code $($Old.exitCode) -> $($New.exitCode)") }
    if ($Old.toolVersion -ne $New.toolVersion) { $flags.Add("INFO      PCPorter version $($Old.toolVersion) -> $($New.toolVersion) (expect changes)") }
    if ($Old.osBuild -ne $New.osBuild) { $flags.Add("INFO      Windows build $($Old.osBuild) -> $($New.osBuild)") }
    , $flags
}

New-Item -ItemType Directory -Force $Root | Out-Null

if ($Accept) {
    $newest = Get-Summaries | Select-Object -Last 1
    if (-not $newest) { Write-Host "No summaries in $Root yet. Run this script without -Accept first." -ForegroundColor Red; exit 2 }
    Copy-Item -LiteralPath $newest.FullName $acceptedFile -Force
    Write-Host "Baseline is now $($newest.Name)." -ForegroundColor Green
    exit 0
}

if ($Case) {
    if (-not (Test-Path -LiteralPath $Case)) { Write-Host "The case folder $Case does not exist." -ForegroundColor Red; exit 2 }
    if (-not (Test-Path -LiteralPath (Join-Path $Case 'scan'))) { Write-Host "$Case is not a PCPorter case folder (no scan folder)." -ForegroundColor Red; exit 2 }
    $summary = New-Summary $Case $null $null $null
} else {
    $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Run this from an administrator PowerShell window (right-click > Run as administrator).' -ForegroundColor Red; exit 4
    }
    if (-not (Test-Path -LiteralPath $Exe)) { Write-Host "PCPorter.exe not found at $Exe. Keep this script next to it, or pass -Exe." -ForegroundColor Red; exit 2 }
    $cases = Join-Path $Root 'cases'
    Write-Host 'Scanning (a few minutes)...'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # PCPorter writes UTF-8. Windows PowerShell 5.1 decodes a program's output with the console code page (437/1252),
    # which garbles non-ASCII names in the JSON; decode as UTF-8 for this call only.
    $oldEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        $text = (& $Exe scan --out $cases --json --quiet | Out-String)
        $code = $LASTEXITCODE
    } finally { [Console]::OutputEncoding = $oldEncoding }
    $seconds = [int]$sw.Elapsed.TotalSeconds
    $scanOut = try { $text | ConvertFrom-Json } catch { $null }
    # The case folder is "caseFolder" in newer builds and "casePath" in older ones.
    $caseDir = if ($scanOut) { @($scanOut.summary.caseFolder, $scanOut.summary.casePath) | Where-Object { $_ } | Select-Object -First 1 } else { $null }
    if (-not $caseDir) { Write-Host "The scan gave no summary (exit code $code). Output:`n$text" -ForegroundColor Red; exit 2 }
    if (-not (Test-Path -LiteralPath (Join-Path $caseDir 'scan'))) {
        Write-Host "The scan reported the case folder $caseDir, but it (or its scan folder) does not exist (exit code $code). Nothing to summarize." -ForegroundColor Red; exit 2
    }
    $summary = New-Summary $caseDir $scanOut $seconds $code
}

$json = $summary | ConvertTo-Json -Depth 6
$problem = Test-Scrubbed $json
if ($problem) { Write-Host "Not saved: the summary $problem. This is a bug in baseline.ps1." -ForegroundColor Red; exit 2 }
$name = (Get-Date).ToString('yyyyMMdd-HHmmss') + '.json'
$path = Join-Path $Root $name
[IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host "Summary: $path"

$against = if (Test-Path -LiteralPath $acceptedFile) { Get-Item -LiteralPath $acceptedFile } else { Get-Summaries | Where-Object Name -ne $name | Select-Object -Last 1 }
if (-not $against) {
    Write-Host 'First summary on this PC: nothing to compare with yet. If the report looks right, run with -Accept to make it the baseline.' -ForegroundColor Yellow
    exit 1
}
$old = Get-Content -LiteralPath $against.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
$new = $json | ConvertFrom-Json
$flags = Compare-Summary $old $new
$label = if ($against.Name -eq 'accepted.json') { 'the accepted baseline' } else { "$($against.Name) (no baseline accepted yet)" }
$lines = @("Compared with ${label}:") + $(if ($flags.Count) { $flags } else { @('No changes.') })
$lines | Out-File (Join-Path $Root ($name -replace '\.json$', '.compare.txt')) -Encoding utf8
foreach ($l in $lines) {
    $color = if ($l -match '^NEW ') { 'Red' } elseif ($l -match '^(INFO|Compared)') { 'Gray' } elseif ($l -eq 'No changes.') { 'Green' } else { 'Yellow' }
    Write-Host $l -ForegroundColor $color
}
$real = @($flags | Where-Object { $_ -notmatch '^INFO' })
if ($real.Count) { Write-Host 'Review these. If they are expected, run with -Accept.' -ForegroundColor Yellow; exit 1 }
exit 0
