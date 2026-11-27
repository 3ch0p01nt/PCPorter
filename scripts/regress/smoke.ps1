<#
.SYNOPSIS
  Tier 4: packaged-EXE smoke test (plan: docs/plans/2026-11-26-regression-testing.md). Runs ELEVATED.

.DESCRIPTION
  Normally started by the "PCPorterSmoke" scheduled task that install-smoke-task.ps1 registers (no UAC prompt per run),
  from its admin-only copy in C:\PCPorterCI. It can also be run by hand from an administrator PowerShell 7.

  It never runs the EXE from the user-writable dist folder: the 7 files are first copied to C:\PCPorterCI\run
  (administrators only) and their SHA-256 is recorded. Results: <OutRoot>\smoke-<time>\result.json, and a copy at
  <OutRoot>\smoke-last.json for regress.ps1. Exit code 0 = every check passed.
#>
#Requires -Version 7
param(
    [string] $Dist = 'C:\PCPorter-dist\PCPorter',
    [string] $Fixture = 'C:\PCPorterCases\regress\fixture-oldpc',
    [string] $OutRoot = 'C:\PCPorterCases\regress',
    [string] $RunDir = 'C:\PCPorterCI\run',
    [switch] $DryRun   # testing this script without elevation: live scans then fail with exit 4, everything else runs
)
$ErrorActionPreference = 'Stop'
$Canary = 'Hunter2Canary'
$started = Get-Date
$out = Join-Path $OutRoot ('smoke-' + $started.ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force $out | Out-Null
$checks = [System.Collections.Generic.List[object]]::new()
$facts = [ordered]@{}

function Add-Check([string] $Name, [bool] $Ok, [string] $Detail = '', [double] $Seconds = 0, [switch] $Skip) {
    $status = if ($Skip) { 'SKIP' } elseif ($Ok) { 'PASS' } else { 'FAIL' }
    $checks.Add([ordered]@{ name = $Name; status = $status; detail = $Detail; seconds = [math]::Round($Seconds, 1) })
    "{0,-4}  {1}{2}" -f $status, $Name, $(if ($Detail) { " - $Detail" } else { '' }) | Tee-Object -FilePath (Join-Path $out 'log.txt') -Append
}

function Invoke-Pcp {
    <# Runs the EXE. -ToFile: stdout goes to a real file (FILE_TYPE_DISK); otherwise through a PowerShell pipe. #>
    param([string[]] $Arguments, [switch] $ToFile, [string] $Name)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $stdout = Join-Path $out "$Name.out.txt"; $stderr = Join-Path $out "$Name.err.txt"
    try {
        if ($ToFile) {
            $p = Start-Process -FilePath $exe -ArgumentList $Arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru -NoNewWindow
            $code = $p.ExitCode
        } else {
            & $exe @Arguments 2> $stderr | Out-File $stdout -Encoding utf8
            $code = $LASTEXITCODE
        }
    } catch {
        # A program that cannot start (no elevation, blocked by antivirus) fails its check instead of ending the run.
        $_.Exception.Message | Out-File $stderr
        $code = -1
    }
    [pscustomobject]@{ Code = $code; Out = (Get-Content $stdout -Raw -ErrorAction SilentlyContinue) ?? ''; Seconds = $sw.Elapsed.TotalSeconds }
}

function Read-Json([string] $Text) { try { $Text | ConvertFrom-Json } catch { $null } }

function Get-Fingerprint([string] $Root) {
    $map = [ordered]@{}
    Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length)
        $map[$rel] = if ($_.PSIsContainer) { "dir $($_.LastWriteTimeUtc.ToString('o'))" }
                     else { "$($_.Length) $($_.LastWriteTimeUtc.ToString('o')) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)" }
    }
    $map
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $DryRun -and -not ([Security.Principal.WindowsPrincipal] $me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Check 'Running elevated' $false 'smoke.ps1 must run as administrator (through the PCPorterSmoke task)'
} else {
    # ---- 1. The published folder ----
    $expected = 'PCPorter.exe', 'D3DCompiler_47_cor3.dll', 'PenImc_cor3.dll', 'PresentationNative_cor3.dll', 'e_sqlite3.dll', 'vcruntime140_cor3.dll', 'wpfgfx_cor3.dll'
    $found = @(Get-ChildItem -LiteralPath $Dist -File | Where-Object Name -ne 'HOW-TO-RUN.txt' | ForEach-Object Name)
    $missing = $expected | Where-Object { $_ -notin $found }; $extra = $found | Where-Object { $_ -notin $expected }
    Add-Check 'Published folder has exactly the 7 program files' (-not $missing -and -not $extra) $(if ($missing -or $extra) { "missing: $($missing -join ', '); extra: $($extra -join ', ')" } else { '' })

    # Copy to an administrators-only folder before running anything elevated, and record what ran.
    if (Test-Path $RunDir) { Remove-Item -LiteralPath $RunDir -Recurse -Force }
    New-Item -ItemType Directory $RunDir | Out-Null
    foreach ($f in $expected) { if (Test-Path (Join-Path $Dist $f)) { Copy-Item -LiteralPath (Join-Path $Dist $f) -Destination $RunDir } }
    $exe = Join-Path $RunDir 'PCPorter.exe'
    $facts.exeSha256 = (Get-FileHash $exe -Algorithm SHA256).Hash
    $facts.exeBytes = (Get-Item $exe).Length

    # The manifest sits in the resources, about 10 MB in (after the ReadyToRun code): search the file in overlapping chunks.
    $manifestFound = $false
    $buf = [byte[]]::new(16MB)
    $fs = [IO.File]::OpenRead($exe)
    try {
        for ($pos = 0L; $pos -lt $fs.Length -and -not $manifestFound; $pos += $buf.Length - 64) {
            $fs.Position = $pos
            $n = $fs.Read($buf, 0, $buf.Length)
            $manifestFound = [Text.Encoding]::Latin1.GetString($buf, 0, $n).Contains('requestedExecutionLevel level="requireAdministrator"')
        }
    } finally { $fs.Dispose() }
    Add-Check 'EXE manifest asks for administrator' $manifestFound
    Add-Check 'EXE is not signed (expected for a personal build)' $true (Get-AuthenticodeSignature $exe).Status

    # ---- 2. Defender scan of the program files ----
    $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $mp) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        & $mp -Scan -ScanType 3 -File $RunDir -DisableRemediation | Out-File (Join-Path $out 'defender.txt')
        $mpCode = $LASTEXITCODE
        Add-Check 'Defender finds nothing in the program files' ($mpCode -eq 0) "MpCmdRun exit $mpCode (2 = threat found)" $sw.Elapsed.TotalSeconds
    } else { Add-Check 'Defender scan' $true 'MpCmdRun.exe not found (another antivirus?)' -Skip }

    # ---- 3. Commands and exit codes ----
    $r = Invoke-Pcp -Name 'selftest' -Arguments 'selftest'
    $pass = ([regex]::Matches($r.Out, '(?m)^PASS ')).Count; $fail = ([regex]::Matches($r.Out, '(?m)^FAIL ')).Count
    Add-Check 'selftest: exit 0, 4 PASS, no FAIL' ($r.Code -eq 0 -and $pass -ge 4 -and $fail -eq 0) "exit $($r.Code), PASS $pass, FAIL $fail" $r.Seconds

    $pipe = Invoke-Pcp -Name 'scan-live-pipe' -Arguments 'scan', '--out', "$out\live-pipe", '--json', '--quiet'
    $pj = Read-Json $pipe.Out
    Add-Check 'Live scan through a pipe: exit 0, valid JSON, 5 checks' ($pipe.Code -eq 0 -and $pj.summary -and @($pj.summary.collectors).Count -eq 5) "exit $($pipe.Code)" $pipe.Seconds

    $file = Invoke-Pcp -Name 'scan-live-file' -ToFile -Arguments 'scan', '--out', "$out\live-file", '--json', '--quiet'
    $fj = Read-Json $file.Out
    $sameShape = $pj -and $fj -and ((@($pj.summary.collectors).name -join '|') -eq (@($fj.summary.collectors).name -join '|'))
    Add-Check 'Live scan to a file: exit 0, same JSON shape as the pipe' ($file.Code -eq 0 -and $sameShape) "exit $($file.Code)" $file.Seconds

    $cases = @()
    foreach ($j in @($pj, $fj)) {
        if (-not $j) { continue }
        $case = $j.summary.casePath; $cases += $case
        $ok = (Test-Path (Join-Path $case 'case.db')) -and (Test-Path (Join-Path $case 'HealthReport.html')) -and
              @(Get-ChildItem (Join-Path $case 'scan') -Filter *.json).Count -ge 5 -and -not (Test-Path (Join-Path $case 'work'))
        Add-Check "Case folder complete, work folder gone ($(Split-Path $case -Leaf))" $ok
    }

    # ---- 4. Dead-PC mode on the tier-3 fake drive ----
    if (Test-Path (Join-Path $Fixture 'Windows\System32\config\SOFTWARE')) {
        $before = Get-Fingerprint $Fixture
        $off = Invoke-Pcp -Name 'scan-offline' -Arguments 'scan', '--offline', $Fixture, '--out', "$out\offline", '--json', '--quiet'
        $oj = Read-Json $off.Out
        $facts.offlineFindings = $oj.summary.findings
        Add-Check 'Offline scan of the fake drive: findings reported' ($off.Code -in 0, 1 -and $oj.summary.findings.worthALook -gt 0 -and $oj.summary.findings.unusual -gt 0) "exit $($off.Code); $($oj.summary.findings | ConvertTo-Json -Compress)" $off.Seconds
        if ($oj) { $cases += $oj.summary.casePath }
        $after = Get-Fingerprint $Fixture
        $changed = @($before.Keys + $after.Keys | Sort-Object -Unique | Where-Object { $before[$_] -ne $after[$_] })
        Add-Check 'The fake old drive is byte-for-byte unchanged' ($changed.Count -eq 0) ((@($changed) | Select-Object -First 5) -join ', ')
        $fo = Invoke-Pcp -Name 'scan-offline-failon' -Arguments 'scan', '--offline', $Fixture, '--out', "$out\offline-failon", '--json', '--quiet', '--fail-on', 'high'
        Add-Check '--fail-on high exits 5 on findings' ($fo.Code -eq 5) "exit $($fo.Code)" $fo.Seconds
        if ((Read-Json $fo.Out).summary.casePath) { $cases += (Read-Json $fo.Out).summary.casePath }
    } else { Add-Check 'Offline scan of the fake drive' $false "no fixture at $Fixture (regress.ps1 -Level release writes it)" }

    $bad = Invoke-Pcp -Name 'bad-args' -Arguments 'scan', '--no-such-option'
    Add-Check 'Bad arguments exit 3' ($bad.Code -eq 3) "exit $($bad.Code)"
    $od = $env:OneDriveCommercial ?? $env:OneDrive
    if ($od -and (Test-Path $od)) {
        $target = Join-Path $od 'PCPorter-smoke-must-not-exist'
        $odr = Invoke-Pcp -Name 'onedrive' -Arguments 'scan', '--out', $target, '--json', '--quiet'
        Add-Check 'A OneDrive folder is refused (exit 3) and nothing is written there' ($odr.Code -eq 3 -and -not (Test-Path $target)) "exit $($odr.Code): $((Read-Json $odr.Out).error)"
    } else { Add-Check 'OneDrive refusal' $true 'no OneDrive folder on this PC' -Skip }

    $th = Invoke-Pcp -Name 'thumbs' -Arguments 'thumbs', '--out', "$out\thumbs", '--json'
    $tj = Read-Json $th.Out
    $facts.thumbsSummary = $tj
    Add-Check 'thumbs: exit 0 or 1 with a JSON summary' ($th.Code -in 0, 1 -and $tj) "exit $($th.Code)" $th.Seconds
    $thumbCase = Get-ChildItem "$out\thumbs" -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'case.db') } | Select-Object -First 1
    if ($thumbCase) { $cases += $thumbCase.FullName }

    # ---- 5. Outputs: private folders, no secrets ----
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $me.User.Value)
    foreach ($case in ($cases | Where-Object { $_ } | Sort-Object -Unique)) {
        $acl = Get-Acl -LiteralPath $case
        $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
        $others = $sids | Where-Object { $_ -notin $allowed }
        Add-Check "Case folder is private ($(Split-Path $case -Leaf))" ($acl.AreAccessRulesProtected -and -not $others) "others: $($others -join ', ')"
    }
    $skipExt = '.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp'
    $leaks = foreach ($f in @(Get-ChildItem $out -Recurse -File) + @(Get-ChildItem (Join-Path $env:ProgramData 'PCPorter\logs') -File -ErrorAction SilentlyContinue)) {
        if ($f.Extension -in $skipExt -or $f.Length -gt 64MB -or $f.FullName -like '*\log.txt') { continue }
        $bytes = [IO.File]::ReadAllBytes($f.FullName)
        $s1 = [Text.Encoding]::Latin1.GetString($bytes); $s2 = [Text.Encoding]::Unicode.GetString($bytes)
        if ($s1.Contains($Canary) -or $s2.Contains($Canary)) { $f.FullName }
    }
    Add-Check 'The planted password appears in no output or log' (-not $leaks) ($leaks -join ', ')
}

# ---- 6. Timing against the previous run ----
$last = Join-Path $OutRoot 'smoke-last.json'
if (Test-Path $last) {
    $prev = Get-Content $last -Raw | ConvertFrom-Json
    foreach ($c in $checks) {
        $p = @($prev.checks) | Where-Object name -eq $c.name | Select-Object -First 1
        if ($p -and $p.seconds -gt 5 -and $c.seconds -gt 2 * $p.seconds) { $c.detail += " [SLOWER: $($c.seconds) s, was $($p.seconds) s]" }
    }
}

$failed = @($checks | Where-Object status -eq 'FAIL').Count
$result = [ordered]@{ started = $started.ToString('o'); seconds = [int]((Get-Date) - $started).TotalSeconds; folder = $out; ok = ($failed -eq 0); failed = $failed; facts = $facts; checks = $checks }
$json = $result | ConvertTo-Json -Depth 6
$json | Out-File (Join-Path $out 'result.json') -Encoding utf8
$json | Out-File $last -Encoding utf8
exit ($(if ($failed -eq 0) { 0 } else { 1 }))
