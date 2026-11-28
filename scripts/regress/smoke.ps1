<#
.SYNOPSIS
  Tier 4: packaged-EXE smoke test (plan: docs/plans/2026-11-26-regression-testing.md). Runs ELEVATED.

.DESCRIPTION
  Normally started by the "PCPorterSmoke" scheduled task that install-smoke-task.ps1 registers (no UAC prompt per run),
  from its admin-only copy in C:\PCPorterCI. It can also be run by hand from an administrator PowerShell 7.

  It never runs the EXE from the user-writable dist folder: the 7 files are first copied to C:\PCPorterCI\run
  (administrators only) and the EXE's SHA-256 is recorded as facts.exeSha256 (package.ps1 zips only an EXE whose hash
  matches a passing, non-DryRun smoke-last.json). Results: <OutRoot>\smoke-<time>\result.json, and a copy at
  <OutRoot>\smoke-last.json for regress.ps1. Exit code 0 = every check passed.
#>
#Requires -Version 7
param(
    [string] $Dist = 'C:\PCPorter-dist\PCPorter',
    [string] $Fixture = 'C:\PCPorterCases\regress\fixture-oldpc',
    [string] $OutRoot = 'C:\PCPorterCases\regress',
    [string] $RunDir = 'C:\PCPorterCI\run',
    # Testing this script without elevation: the EXE asks for administrator (requireAdministrator), so a non-elevated
    # start of it fails to launch at all; every check that runs it then fails with code -1. Everything else runs.
    [switch] $DryRun
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

# ---- Save drives: real NTFS/exFAT/FAT32 volumes on small virtual disks (most USB backup drives are exFAT) ----
$VhdDir = Join-Path $OutRoot 'save-drives'
function Remove-TestDrives {
    foreach ($v in @(Get-ChildItem -LiteralPath $VhdDir -Filter *.vhdx -ErrorAction SilentlyContinue)) {
        try { Dismount-DiskImage -ImagePath $v.FullName -ErrorAction SilentlyContinue | Out-Null } catch { }
        Remove-Item -LiteralPath $v.FullName -Force -ErrorAction SilentlyContinue
    }
}
function New-TestDrive([string] $Name, [string] $FileSystem, [int] $SizeMB) {
    <# A formatted volume with a drive letter, or $null. Formatted BEFORE it gets a letter, so Explorer never offers to format it. #>
    New-Item -ItemType Directory -Force $VhdDir | Out-Null
    $vhd = Join-Path $VhdDir "$Name.vhdx"
    "create vdisk file=`"$vhd`" maximum=$SizeMB type=expandable" | diskpart.exe | Out-Null
    if (-not (Test-Path $vhd)) { return $null }
    $disk = Mount-DiskImage -ImagePath $vhd -NoDriveLetter -PassThru | Get-Disk
    Initialize-Disk -Number $disk.Number -PartitionStyle MBR
    $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize
    $label = ('PCPT ' + $Name).Substring(0, [Math]::Min(11, 5 + $Name.Length))
    Format-Volume -Partition $part -FileSystem $FileSystem -NewFileSystemLabel $label -Confirm:$false | Out-Null
    $part | Add-PartitionAccessPath -AssignDriveLetter
    $letter = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber).DriveLetter
    if (-not $letter -or $letter -eq [char]0) { return $null }
    [pscustomobject]@{ Name = $Name; FileSystem = $FileSystem; Root = "${letter}:\"; Vhd = $vhd; DiskNumber = $disk.Number }
}

function Get-Fingerprint([string] $Root) {
    $map = [ordered]@{}
    Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length)
        # Times are read from each item itself, not from the listing: a folder listing reports a subfolder's time late
        # (NTFS updates it only once that subfolder is opened), so two listings of a fresh folder can differ.
        $map[$rel] = if ($_.PSIsContainer) { "dir $([IO.Directory]::GetLastWriteTimeUtc($_.FullName).ToString('o'))" }
                     else { "$([IO.FileInfo]::new($_.FullName).Length) $([IO.File]::GetLastWriteTimeUtc($_.FullName).ToString('o')) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)" }
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

    # Save drives for section 4b (and the gallery run): removed again at the end.
    Remove-TestDrives
    $drives = [ordered]@{}
    foreach ($d in @(@('NTFS', 'NTFS', 256), @('exFAT', 'exFAT', 256), @('FAT32', 'FAT32', 256), @('Full', 'NTFS', 16), @('ReadOnly', 'exFAT', 64))) {
        try { $drives[$d[0]] = New-TestDrive $d[0] $d[1] $d[2] } catch { $drives[$d[0]] = $null; "$($d[0]): $($_.Exception.Message)" | Out-File (Join-Path $out 'save-drives.err.txt') -Append }
    }
    Add-Check 'Test save drives created (NTFS, exFAT, FAT32, full, read-only)' (@($drives.Values | Where-Object { $_ }).Count -eq 5) (($drives.Keys | ForEach-Object { "$_=$(if ($drives[$_]) { $drives[$_].Root } else { 'none' })" }) -join ' ')

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
        $case = $j.summary.caseFolder; $cases += $case
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
        Add-Check 'Offline scan of the fake drive: findings reported, exit 1 (offline is always partial)' ($off.Code -eq 1 -and $oj.summary.findings.worthALook -gt 0 -and $oj.summary.findings.unusual -gt 0) "exit $($off.Code); $($oj.summary.findings | ConvertTo-Json -Compress)" $off.Seconds
        if ($oj) { $cases += $oj.summary.caseFolder }
        $after = Get-Fingerprint $Fixture
        $changed = @($before.Keys + $after.Keys | Sort-Object -Unique | Where-Object { $before[$_] -ne $after[$_] })
        Add-Check 'The fake old drive is byte-for-byte unchanged' ($changed.Count -eq 0) ((@($changed) | Select-Object -First 5) -join ', ')
        # Web history of the fake drive: bob's planted Chrome (with 8 deleted visits), Firefox and IE history.
        $ho = Invoke-Pcp -Name 'history-offline' -Arguments 'history', '--offline', $Fixture, '--out', "$out\history-offline", '--json'
        $hoj = Read-Json $ho.Out
        $facts.historyOfflineSummary = $hoj.summary
        $hoReport = $hoj.summary.report
        $planted = $hoReport -and (Test-Path -LiteralPath $hoReport) -and (Get-Content -LiteralPath $hoReport -Raw).Contains('news.example')
        Add-Check 'Offline history of the fake drive: planted and deleted visits found' ($ho.Code -in 0, 1 -and $planted -and $hoj.summary.profiles -eq 3 -and
            $hoj.summary.visits -ge 30 -and $hoj.summary.recovered -ge 8) "exit $($ho.Code); profiles $($hoj.summary.profiles), visits $($hoj.summary.visits), recovered $($hoj.summary.recovered)" $ho.Seconds
        if ($hoj.summary.caseFolder) { $cases += $hoj.summary.caseFolder }
        $afterHistory = Get-Fingerprint $Fixture
        $changed = @($before.Keys + $afterHistory.Keys | Sort-Object -Unique | Where-Object { $before[$_] -ne $afterHistory[$_] })
        Add-Check 'The fake old drive is unchanged after the history report' ($changed.Count -eq 0) ((@($changed) | Select-Object -First 5) -join ', ')

        # Saving onto the drive being checked is refused (exit 3) and writes nothing. A subst letter makes the fake
        # drive a drive of its own, as a connected old disk would be; the app must see through the letter.
        $letter = [char[]](90..68) | Where-Object { -not (Test-Path "$($_):\") } | Select-Object -First 1
        if ($letter) {
            $drive = "${letter}:"
            & subst.exe $drive $Fixture | Out-Null
            try {
                foreach ($cmd in 'scan', 'history') {
                    $target = "$drive\PCPorter-smoke-must-not-exist-$cmd"
                    $sdArgs = @($cmd, '--offline', "$drive\", '--out', $target, '--json') + $(if ($cmd -eq 'scan') { '--quiet' } else { @() })
                    $sd = Invoke-Pcp -Name "$cmd-onto-scanned-drive" -Arguments $sdArgs
                    $why = (Read-Json $sd.Out).error
                    $written = (Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath (Join-Path $Fixture "PCPorter-smoke-must-not-exist-$cmd"))
                    # Exit 3 is also "bad arguments": the reason must be the drive check, not a typo in this script.
                    Add-Check "${cmd}: saving onto the drive being checked is refused (exit 3), nothing written" ($sd.Code -eq 3 -and $why -match 'drive being checked' -and -not $written) "exit $($sd.Code): $why"
                }
            } finally { & subst.exe $drive /D | Out-Null }
            $afterRefusals = Get-Fingerprint $Fixture
            $changed = @($before.Keys + $afterRefusals.Keys | Sort-Object -Unique | Where-Object { $before[$_] -ne $afterRefusals[$_] })
            Add-Check 'The fake old drive is unchanged after the refused saves' ($changed.Count -eq 0) ((@($changed) | Select-Object -First 5) -join ', ')
        } else { Add-Check 'Saving onto the drive being checked is refused' $false 'no free drive letter for subst' }
        $fo = Invoke-Pcp -Name 'scan-offline-failon' -Arguments 'scan', '--offline', $Fixture, '--out', "$out\offline-failon", '--json', '--quiet', '--fail-on', 'high'
        Add-Check '--fail-on high exits 5 on findings' ($fo.Code -eq 5) "exit $($fo.Code)" $fo.Seconds
        if ((Read-Json $fo.Out).summary.caseFolder) { $cases += (Read-Json $fo.Out).summary.caseFolder }
    } else { Add-Check 'Offline scan of the fake drive' $false "no fixture at $Fixture (regress.ps1 -Level release writes it)" }

    $bad = Invoke-Pcp -Name 'bad-args' -Arguments 'scan', '--no-such-option'
    Add-Check 'Bad arguments exit 3' ($bad.Code -eq 3) "exit $($bad.Code)"
    $od = $env:OneDriveCommercial ?? $env:OneDrive
    if ($od -and (Test-Path $od)) {
        $target = Join-Path $od 'PCPorter-smoke-must-not-exist'
        $odr = Invoke-Pcp -Name 'onedrive' -Arguments 'scan', '--out', $target, '--json', '--quiet'
        Add-Check 'A OneDrive folder is refused (exit 3) and nothing is written there' ($odr.Code -eq 3 -and -not (Test-Path $target)) "exit $($odr.Code): $((Read-Json $odr.Out).error)"
    } else { Add-Check 'OneDrive refusal' $true 'no OneDrive folder on this PC' -Skip }

    # The gallery (the slowest run, about 6 minutes) saves to the ROOT of the exFAT test drive, like a new USB backup drive.
    $thumbsOut = if ($drives['exFAT']) { $drives['exFAT'].Root } else { "$out\thumbs" }
    $th = Invoke-Pcp -Name 'thumbs' -Arguments 'thumbs', '--out', $thumbsOut, '--json'
    $tj = Read-Json $th.Out
    $facts.thumbsSummary = $tj
    $thumbCase = Get-ChildItem $thumbsOut -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'case.db') } | Select-Object -First 1
    Add-Check "thumbs to $thumbsOut ($(if ($drives['exFAT']) { 'exFAT drive root' } else { 'NTFS' })): exit 0 or 1, gallery written" ($th.Code -in 0, 1 -and $tj.summary -and $null -ne $tj.exitCode -and
        $thumbCase -and (Test-Path (Join-Path $thumbCase.FullName 'Thumbnails\Thumbnails.html'))) "exit $($th.Code)$(if (-not $tj) { ': ' + $th.Out.Trim() })" $th.Seconds
    if ($thumbCase -and -not $drives['exFAT']) { $cases += $thumbCase.FullName }
    # A cancelled gallery must leave no case folder, but cancelling needs a Ctrl+C delivered to the EXE's console,
    # which this script cannot send to an elevated child reliably. Covered by the manual checklist (section 4).
    Add-Check 'thumbs: a cancelled run leaves no case folder' $true 'not automated: see docs/testing/manual-checklist.md' -Skip

    # Web history of this PC (elevated: restore points and IE through a temporary shadow copy). The canary scan below covers it.
    $hl = Invoke-Pcp -Name 'history-live' -Arguments 'history', '--out', "$out\history", '--json'
    $hlj = Read-Json $hl.Out
    $facts.historySummary = $hlj.summary
    $hlReport = $hlj.summary.report
    Add-Check 'history: exit 0 or 1, History.html written, work folder gone' ($hl.Code -in 0, 1 -and $hlReport -and (Test-Path -LiteralPath $hlReport) -and
        (Split-Path $hlReport -Leaf) -eq 'History.html' -and -not (Test-Path (Join-Path $hlj.summary.caseFolder 'work'))) "exit $($hl.Code)" $hl.Seconds
    if ($hlj.summary.caseFolder) { $cases += $hlj.summary.caseFolder }

    # ---- 4b. Saving to real backup-drive formats (NTFS, exFAT, FAT32), full and read-only drives ----
    # Uses the fake old drive as the source (offline runs take seconds). Each format: the drive ROOT and a new folder
    # with spaces and accented letters; health check and web history. No-ACL formats must say anyone can read the case.
    if (Test-Path (Join-Path $Fixture 'Windows\System32\config\SOFTWARE')) {
        foreach ($fsName in 'NTFS', 'exFAT', 'FAT32') {
            $d = $drives[$fsName]
            if (-not $d) { Add-Check "$fsName save drive" $false 'test drive could not be created'; continue }
            $noAcl = $fsName -ne 'NTFS'
            foreach ($target in @($d.Root, (Join-Path $d.Root 'PCPorter results\Résumé ü 1'))) {
                $where = if ($target -eq $d.Root) { 'drive root' } else { 'new folder with spaces and accents' }
                $sv = Invoke-Pcp -Name "save-$fsName-scan-$($where -replace '\W', '')" -Arguments 'scan', '--offline', $Fixture, '--out', $target, '--json', '--quiet'
                $sj = Read-Json $sv.Out
                $report = $sj.summary.report
                $warned = @($sj.folderWarnings | Where-Object { $_ -match 'Anyone with the drive' }).Count -gt 0
                Add-Check "Health check saves to $fsName $where (exit 1, report written$(if ($noAcl) { ', no-permissions warning' }))" ($sv.Code -eq 1 -and $report -and
                    (Test-Path -LiteralPath $report) -and $report.StartsWith($d.Root) -and ($warned -eq $noAcl)) "exit $($sv.Code)$(if ($sj.error) { ': ' + $sj.error } elseif (-not $sj) { ': ' + $sv.Out.Trim() })" $sv.Seconds
                if ($sj.summary.caseFolder -and -not $noAcl) { $cases += $sj.summary.caseFolder }
            }
            $hv = Invoke-Pcp -Name "save-$fsName-history" -Arguments 'history', '--offline', $Fixture, '--out', $d.Root, '--json'
            $hj = Read-Json $hv.Out
            Add-Check "Web history saves to $fsName drive root (exit 0 or 1, History.html written)" ($hv.Code -in 0, 1 -and $hj.summary.report -and
                (Test-Path -LiteralPath $hj.summary.report) -and $hj.summary.report.StartsWith($d.Root)) "exit $($hv.Code)$(if ($hj.error) { ': ' + $hj.error } elseif (-not $hj) { ': ' + $hv.Out.Trim() })" $hv.Seconds
            if ($hj.summary.caseFolder -and -not $noAcl) { $cases += $hj.summary.caseFolder }
        }

        # A drive with almost no free space: a plain message (never a stack trace) and exit 2. What was saved is kept and named.
        if ($drives['Full']) {
            $root = $drives['Full'].Root
            $free = (Get-Volume -DriveLetter $root[0]).SizeRemaining
            if ($free -gt 300KB) { fsutil.exe file createnew (Join-Path $root 'filler.bin') ($free - 200KB) | Out-Null }
            $fv = Invoke-Pcp -Name 'save-full' -Arguments 'scan', '--offline', $Fixture, '--out', $root, '--json', '--quiet'
            $fj2 = Read-Json $fv.Out
            $left = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'System Volume Information', '$RECYCLE.BIN' })
            $plain = $fj2.error -and $fj2.error -match 'space' -and $fj2.error -notmatch '   at |Exception'
            Add-Check 'A full drive: exit 2 with a plain "not enough space" message' ($fv.Code -eq 2 -and $plain) "exit $($fv.Code): $($fj2.error ?? $fv.Out.Trim()); left: $(($left | ForEach-Object Name) -join ', ')" $fv.Seconds
        } else { Add-Check 'A full drive' $false 'test drive could not be created' }

        # A read-only drive (write-protect switch on an SD card or stick): refused with a plain message.
        if ($drives['ReadOnly']) {
            # Read-only and then off/online again, so the mounted volume reports itself read-only (as with a locked SD card).
            $n = $drives['ReadOnly'].DiskNumber
            Set-Disk -Number $n -IsReadOnly $true; Set-Disk -Number $n -IsOffline $true; Set-Disk -Number $n -IsOffline $false
            Start-Sleep -Seconds 2
            $rv = Invoke-Pcp -Name 'save-readonly' -Arguments 'scan', '--offline', $Fixture, '--out', $drives['ReadOnly'].Root, '--json', '--quiet'
            $rj = Read-Json $rv.Out
            Add-Check 'A read-only drive: refused up front with a plain message (exit 3)' ($rv.Code -eq 3 -and $rj.error -match 'write-protected' -and $rj.error -notmatch '   at |Exception') "exit $($rv.Code): $($rj.error ?? $rv.Out.Trim())" $rv.Seconds
        } else { Add-Check 'A read-only drive' $false 'test drive could not be created' }
    } else { Add-Check 'Saving to NTFS/exFAT/FAT32 drives' $false "no fixture at $Fixture (regress.ps1 -Level release writes it)" }

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

Remove-TestDrives

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
$result = [ordered]@{ started = $started.ToString('o'); seconds = [int]((Get-Date) - $started).TotalSeconds; folder = $out; ok = ($failed -eq 0); failed = $failed; dryRun = [bool]$DryRun; facts = $facts; checks = $checks }
$json = $result | ConvertTo-Json -Depth 6
$json | Out-File (Join-Path $out 'result.json') -Encoding utf8
$json | Out-File $last -Encoding utf8
exit ($(if ($failed -eq 0) { 0 } else { 1 }))
