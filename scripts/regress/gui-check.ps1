<#
.SYNOPSIS
  Tier 6: the manual GUI checklist (docs/testing/manual-checklist.md), automated with UI Automation.

.DESCRIPTION
  Drives the packaged PCPorter.exe only through UI Automation patterns (Invoke, Value, Toggle, SelectionItem,
  ExpandCollapse, Window). WPF-UI menu items have no Invoke pattern: they get UIA focus and a Space key posted to
  PCPorter's own window; message-box buttons get BM_CLICK posted to their own window; closing posts WM_CLOSE to
  PCPorter's window. No system-wide mouse or keyboard input is ever sent.

  PCPorter always runs as administrator, and only an elevated process can drive an elevated window. Started without
  elevation, the script relaunches itself ONCE with Start-Process -Verb RunAs (one UAC prompt, which the person
  approves), waits for it, then renders the reports in headless Edge (not elevated), deletes the results folder that
  holds the person's own history and pictures, and prints the results.

  Phase 1 (elevated): back up %AppData%\PCPorter\settings.json (the pages then start with defaults), subst P: onto the
  fake old-PC drive, run the checklist, then in finally: close the app, remove the subst, restore settings.json.
  Phase 2 (any): headless Edge --dump-dom of each report, checks of the report content, delete C:\PCPorterCases\manual.

  Output: C:\PCPorterCases\gui-check\<time>\result.json and log.txt with PASS / FAIL / SKIP and evidence per item.
  They hold counts and UI labels only: user, computer and OneDrive names, case folder names and URLs are masked, and
  no visit, title, picture name or form value is ever written.

.PARAMETER Dll
  Developer dry run: drive a debug build (dotnet <Dll>) instead of the EXE. Use with -NoElevate.
.PARAMETER NoElevate
  Do not relaunch elevated. Items that need an elevated app are SKIPped.

.EXAMPLE
  pwsh -File scripts\regress\gui-check.ps1
.EXAMPLE
  pwsh -File scripts\regress\gui-check.ps1 -NoElevate -Dll src\PCPorter.App\bin\Debug\net10.0-windows10.0.19041.0\PCPorter.dll
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string] $Exe = 'C:\PCPorter-dist\PCPorter\PCPorter.exe',
    [string] $Dll,
    [switch] $NoElevate,
    [string] $RunDir,
    [switch] $Child   # internal: this is the elevated relaunch; phase 2 is left to the caller
)
$ErrorActionPreference = 'Stop'

$CasesRoot = 'C:\PCPorterCases'
$Manual = Join-Path $CasesRoot 'manual'
$Fixture = Join-Path $CasesRoot 'regress\fixture-oldpc'
$Letter = 'P:'
$SettingsFile = Join-Path $env:APPDATA 'PCPorter\settings.json'
$SettingsBackup = "$SettingsFile.gui-check-backup"
$Repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Dll) { $Dll = (Resolve-Path $Dll).Path }

# A run whose administrator prompt went unanswered is called off by writing cancelled.txt into its folder: should the
# prompt be approved later, the elevated copy then exits at once instead of running unattended.
if ($Child -and $RunDir -and (Test-Path -LiteralPath (Join-Path $RunDir 'cancelled.txt'))) { exit 4 }
if (-not $RunDir) { $RunDir = Join-Path $CasesRoot ('gui-check\' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force $RunDir | Out-Null
$ResultFile = Join-Path $RunDir 'result.json'
$LogFile = Join-Path $RunDir 'log.txt'
$QueueFile = Join-Path $RunDir 'render-queue.json'   # report paths for phase 2; deleted when phase 2 is done
$ManualMarker = Join-Path $RunDir 'manual-created.txt'   # phase 2 deletes $Manual only if this run created it

# ---------------------------------------------------------------------------------------------------------------------
# Results and log (everything passes through Hide first)
# ---------------------------------------------------------------------------------------------------------------------
function Hide([string] $s) {
    if (-not $s) { return $s }
    $pairs = @()
    if ($env:OneDrive) { $pairs += , @($env:OneDrive, '<OneDrive>') }
    $pairs += , @($env:USERPROFILE, '<profile>')
    foreach ($p in $pairs) { $s = [regex]::Replace($s, [regex]::Escape($p[0]), $p[1], 'IgnoreCase') }
    $s = [regex]::Replace($s, '[\p{L}\p{Nd}_-]+_\d{8}T\d{6}Z_[0-9a-f]{6}', '<case>')
    $s = [regex]::Replace($s, 'https?://\S+', '<url>')
    foreach ($w in @($env:USERNAME, $env:COMPUTERNAME) | Where-Object { $_ }) {
        $s = [regex]::Replace($s, '(?<![\p{L}\p{Nd}])' + [regex]::Escape($w) + '(?![\p{L}\p{Nd}])', '<name>', 'IgnoreCase')
    }
    return $s
}

function Log([string] $m) {
    $line = '{0:HH:mm:ss} {1}' -f (Get-Date), (Hide $m)
    Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8
    Write-Host $line
}

function Read-Results {
    if (Test-Path -LiteralPath $ResultFile) {
        $j = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($r in @($j.items)) { $list.Add([ordered]@{ id = $r.id; item = $r.item; status = $r.status; evidence = $r.evidence }) }
        return , $list
    }
    return , [System.Collections.Generic.List[object]]::new()
}
$script:Results = Read-Results

function Save-Results {
    $counts = [ordered]@{ PASS = 0; FAIL = 0; SKIP = 0 }
    foreach ($r in $script:Results) { $counts[$r.status]++ }
    [ordered]@{
        started   = $script:Started
        updated   = (Get-Date).ToString('s')
        app       = if ($Dll) { 'debug build (dotnet)' } else { 'packaged EXE' }
        version   = $script:AppVersion
        elevated  = $script:AppElevated
        counts    = $counts
        items     = $script:Results
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultFile -Encoding utf8
}

function Add-Result([string] $id, [string] $item, [string] $status, [string] $evidence) {
    $evidence = Hide $evidence
    $existing = $script:Results | Where-Object { $_.id -eq $id } | Select-Object -First 1
    if ($existing) { $existing.status = $status; $existing.evidence = $evidence; $existing.item = $item }
    else { $script:Results.Add([ordered]@{ id = $id; item = $item; status = $status; evidence = $evidence }) }
    Log ("{0,-4} {1} {2} - {3}" -f $status, $id, $item, $evidence)
    Save-Results
}
function Check([string] $id, [string] $item, $ok, [string] $evidence) { Add-Result $id $item $(if ($ok) { 'PASS' } else { 'FAIL' }) $evidence }
function Skip([string] $id, [string] $item, [string] $reason) { Add-Result $id $item 'SKIP' $reason }

function Show-Results {
    if (-not (Test-Path -LiteralPath $ResultFile)) { Write-Host "No results were written ($ResultFile)." -ForegroundColor Red; return }
    $j = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
    Write-Host ''
    Write-Host "PCPorter GUI check: $($j.counts.PASS) passed, $($j.counts.FAIL) failed, $($j.counts.SKIP) skipped"
    foreach ($r in $j.items) {
        $color = @{ PASS = 'Gray'; SKIP = 'Yellow'; FAIL = 'Red' }[$r.status]
        Write-Host ("  {0,-4} {1,-7} {2} - {3}" -f $r.status, $r.id, $r.item, $r.evidence) -ForegroundColor $color
    }
    Write-Host "Results: $ResultFile"
}

# ---------------------------------------------------------------------------------------------------------------------
# Phase 2: report content in headless Edge (works without elevation), then delete the results folder
# ---------------------------------------------------------------------------------------------------------------------
function Get-Dom([string] $path, [string] $tag) {
    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edge) { return $null }
    $work = Join-Path $Manual '_render'   # inside the folder that is deleted at the end: the DOM holds private data
    New-Item -ItemType Directory -Force $work | Out-Null
    $dom = Join-Path $work "$tag.dom.html"; $err = Join-Path $work "$tag.err.txt"
    # Edge is a GUI program: '&' neither waits nor captures output, so Start-Process with files (as in regress.ps1).
    $common = '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions', "--user-data-dir=$work\profile-$tag", '--enable-logging=stderr', '--v=0'
    # Headless Edge sometimes writes the DOM and then never exits: wait at most 2 minutes, then end only the Edge
    # processes that use this run's own profile folder.
    $p = Start-Process $edge -ArgumentList ($common + '--dump-dom', ([Uri]$path).AbsoluteUri) -RedirectStandardOutput $dom -RedirectStandardError $err -NoNewWindow -PassThru
    if (-not $p.WaitForExit(120000)) {
        Log "headless Edge did not exit for $tag; ending it"
        Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains("--user-data-dir=$work\profile-$tag") } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        $p.WaitForExit(10000) | Out-Null
    }
    Start-Sleep -Milliseconds 500
    $errors = @(Select-String -Path $err -Pattern 'Uncaught|CONSOLE.*[Ee]rror' -ErrorAction SilentlyContinue | Where-Object { $_.Line -match 'source: file:' -or $_.Line -match 'Uncaught' }).Count
    return [pscustomobject]@{ Html = (Get-Content -LiteralPath $dom -Raw); ScriptErrors = $errors }
}

function Get-VisibleText([string] $html) {
    $t = [regex]::Replace($html, '(?s)<(script|style)\b.*?</\1>', ' ')
    $t = [regex]::Replace($t, '<[^>]+>', ' ')
    return [Net.WebUtility]::HtmlDecode($t)
}

function Test-Luhn([string] $digits) {
    $sum = 0; $alt = $false
    for ($i = $digits.Length - 1; $i -ge 0; $i--) {
        $d = [int]::Parse($digits[$i]); if ($alt) { $d *= 2; if ($d -gt 9) { $d -= 9 } }
        $sum += $d; $alt = -not $alt
    }
    return ($sum % 10) -eq 0
}

function Get-TableRows([string] $html, [string] $tableId) {
    $m = [regex]::Match($html, '(?s)<table[^>]*id="' + $tableId + '"[^>]*>(.*?)</table>')
    if (-not $m.Success) { return , @() }
    $body = [regex]::Match($m.Groups[1].Value, '(?s)<tbody>(.*?)</tbody>').Groups[1].Value
    $rows = foreach ($r in [regex]::Matches($body, '(?s)<tr[^>]*>(.*?)</tr>')) {
        , @([regex]::Matches($r.Groups[1].Value, '(?s)<td[^>]*>(.*?)</td>') | ForEach-Object { [Net.WebUtility]::HtmlDecode(($_.Groups[1].Value -replace '<[^>]+>', '')) })
    }
    return , @($rows)
}

function Test-HealthDom($q, $d) {
    $h = $d.Html
    $footer = $h -match 'Read-only scan\. Nothing was changed'
    $chips = @([regex]::Matches($h, '<span class="chip [a-z]+">([^<]*)</span>') | ForEach-Object { [Net.WebUtility]::HtmlDecode($_.Groups[1].Value) })
    $look = [regex]::Match($h, '<b>(\d+)</b> worth a look'); $unusual = [regex]::Match($h, '<b>(\d+)</b> unusual')
    $lookChips = @($chips | Where-Object { $_ -in 'Worth a look', 'Fix this' }).Count
    $unusualChips = @($chips | Where-Object { $_ -eq 'Unusual' }).Count
    $bannerOk = $look.Success -and $unusual.Success -and [int]$look.Groups[1].Value -eq $lookChips -and [int]$unusual.Groups[1].Value -eq $unusualChips
    $ev = "footer 'Read-only scan. Nothing was changed'=$footer; banner $($look.Groups[1].Value) worth a look / $($unusual.Groups[1].Value) unusual vs labels $lookChips / $unusualChips; script errors $($d.ScriptErrors)"
    $ok = $footer -and $bannerOk
    foreach ($mk in @($q.markers)) {
        if (-not $mk) { continue }
        $found = $h.Contains($mk.text)
        $ev += "; $($mk.label)=$found"
        $ok = $ok -and $found
    }
    Check $q.id $q.item $ok $ev
}

function Test-HistoryDom($q, $d) {
    $h = $d.Html
    $ran = $h -match 'id="forms-count">\(\d'
    $tiles = [ordered]@{}
    foreach ($m in [regex]::Matches($h, '<div class="tile"><div class="n">([^<]*)</div><div class="l">([^<]*)</div></div>')) { $tiles[$m.Groups[2].Value] = $m.Groups[1].Value }
    $coverage = Get-TableRows $h 'coverage'
    $browsers = @($coverage | ForEach-Object { if ($_.Count -ge 2) { $_[1] } } | Sort-Object -Unique)
    $charts = @('perday', 'heat', 'top' | Where-Object { $h -match ('<svg[^>]*id="' + $_ + '"[^>]*>\s*<') })
    $visits = $h -match '(?s)<div id="visits"[^>]*>\s*<'
    $notes = [regex]::Match($h, '(?s)<div class="banner" id="notes"[^>]*>(.*?)</div>\s*<section').Groups[1].Value
    $visible = Get-VisibleText $h
    $secretWords = @('password_value', 'encrypted_value', 'card_number', 'name_on_card', 'Login Data', 'logins.json', 'key4.db', 'Hunter2Canary') | Where-Object { $h.Contains($_) }
    $cards = @([regex]::Matches($visible, '(?<!\d)(?:\d[ -]?){13,19}(?!\d)') | ForEach-Object { $_.Value -replace '[ -]', '' } | Where-Object { $_.Length -ge 13 -and $_.Length -le 19 -and (Test-Luhn $_) })
    $ev = "script ran=$ran; tiles $($tiles.Count) (Visits $($tiles['Visits'])); coverage rows $($coverage.Count) [$($browsers -join ', ')]; charts drawn [$($charts -join ', ')]; visit table filled=$visits; secret markers $($secretWords.Count); card-like numbers $($cards.Count); script errors $($d.ScriptErrors)"
    $ok = $ran -and $tiles.Count -gt 0 -and $coverage.Count -gt 0 -and $charts.Count -eq 3 -and $visits -and $secretWords.Count -eq 0 -and $cards.Count -eq 0 -and $d.ScriptErrors -eq 0
    if ($q.notesId) {
        # The notes explain what was NOT read; Internet Explorer history that was read shows up in the coverage table.
        $rp = $notes -match 'restore point'; $ie = $notes -match 'Internet Explorer'
        $ieRead = [bool]($browsers | Where-Object { $_ -like 'Internet Explorer*' })
        Check $q.notesId 'Processing notes say whether restore points and Internet Explorer history were read' ($rp -and ($ie -or $ieRead)) "notes mention restore points=$rp, Internet Explorer=$ie; Internet Explorer listed in the coverage table (read)=$ieRead"
    }
    if ($q.oldPc) {
        $want = 'Google Chrome', 'Firefox', 'Internet Explorer'
        $have = @($want | Where-Object { $w = $_; $browsers | Where-Object { $_ -like "$w*" } })
        $rec = $tiles['Recovered visits']
        $ev += "; old-PC browsers found [$($have -join ', ')]; Recovered visits tile=$rec"
        $ok = $ok -and $have.Count -eq 3 -and $rec -eq '8'
    }
    Check $q.id $q.item $ok $ev
}

function Test-GalleryDom($q, $d) {
    $h = $d.Html
    $count = [regex]::Match($h, 'id="count">([\d,.]+) of ([\d,.]+) shown<')
    $shown = if ($count.Success) { [int]($count.Groups[1].Value -replace '[,.]', '') } else { 0 }
    $selects = @('kind', 'status', 'pic', 'size', 'user', 'group', 'sort' | Where-Object { $h -match ('<select id="' + $_ + '"') })
    $groupOpts = @('folder', 'status', 'month', 'kind' | Where-Object { $h -match ('<option value="' + $_ + '"') })
    $imgs = [regex]::Matches($h, '<img [^>]*src="(?!data:)[^"]+"').Count
    $tiles = [regex]::Matches($h, '<button class="tile"').Count
    $ok = $count.Success -and $shown -gt 0 -and $selects.Count -eq 7 -and $groupOpts.Count -eq 4 -and $imgs -gt 0 -and $d.ScriptErrors -eq 0
    Check $q.id $q.item $ok "count '$($count.Groups[1].Value) of $($count.Groups[2].Value) shown'; filters [$($selects -join ', ')]; grouping options [$($groupOpts -join ', ')]; picture elements $imgs; summary tiles $tiles; script errors $($d.ScriptErrors)"
}

function Invoke-Phase2 {
    Log 'Phase 2: report content in headless Edge'
    $queue = if (Test-Path -LiteralPath $QueueFile) { @(Get-Content -LiteralPath $QueueFile -Raw | ConvertFrom-Json) } else { @() }
    $n = 0
    foreach ($q in $queue) {
        $n++
        if (-not $q.path -or -not (Test-Path -LiteralPath $q.path)) { Check $q.id $q.item $false 'report file not found'; continue }
        try {
            $d = Get-Dom $q.path "r$n"
            if (-not $d) { Skip $q.id $q.item 'Edge not found'; continue }
            switch ($q.kind) { 'health' { Test-HealthDom $q $d } 'history' { Test-HistoryDom $q $d } 'gallery' { Test-GalleryDom $q $d } }
        }
        catch { Check $q.id $q.item $false "render failed: $($_.Exception.Message)" }
    }
    if (-not $queue) { Log 'no reports were queued for rendering' }
    Skip '4.R2' 'Gallery: filters/grouping change the grid, arrow keys, Enter opens detail with zoom' 'needs interaction in a live browser; only the DOM after load is checked (--dump-dom)'
    Skip '4.R3' 'Gallery: Export CSV' 'opens a download dialog'
    Skip '4.R4' 'Gallery: print preview shows the contact sheet' 'print preview needs a printer dialog'
    Skip '5.R2' 'Web history: visit table scrolls, sorts and filters; Export CSV' 'needs interaction in a live browser (CSV opens a download dialog); table presence is checked from the DOM'

    # The results folder holds the person's own history and pictures: delete it (only when this run created it).
    if (-not (Test-Path -LiteralPath $ManualMarker)) { Log "$Manual was not created by this run: left alone"; return }
    Remove-Item -LiteralPath $ManualMarker -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Manual) {
        try { Remove-Item -LiteralPath $Manual -Recurse -Force -ErrorAction Stop } catch { Log "deleting $Manual failed: $($_.Exception.Message)" }
    }
    Check '7.3' "Clean-up: $Manual deleted" (-not (Test-Path -LiteralPath $Manual)) "exists after delete=$(Test-Path -LiteralPath $Manual)"
    Remove-Item -LiteralPath $QueueFile -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------------------------------------------------
# Outer (not elevated): relaunch once elevated, then phase 2
# ---------------------------------------------------------------------------------------------------------------------
if (-not $IsAdmin -and -not $NoElevate) {
    Write-Host "PCPorter GUI check -> $RunDir"
    Write-Host 'Windows will ask ONCE for administrator rights: PCPorter always runs as administrator, and only an elevated script can drive it.' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Child', '-RunDir', "`"$RunDir`"", '-Exe', "`"$Exe`"")
    try { Start-Process pwsh -Verb RunAs -ArgumentList $argList -Wait -ErrorAction Stop }
    catch {
        Write-Host "The administrator prompt was declined or failed: $($_.Exception.Message)" -ForegroundColor Red
        Set-Content -LiteralPath (Join-Path $RunDir 'declined.txt') -Value 'The administrator prompt was declined; nothing was run.'
        exit 3
    }
    $script:Started = (Get-Date).ToString('s')
    $script:Results = Read-Results
    $j = if (Test-Path -LiteralPath $ResultFile) { Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json } else { $null }
    if ($j) { $script:Started = $j.started; $script:AppVersion = $j.version; $script:AppElevated = $j.elevated }
    Invoke-Phase2
    Show-Results
    exit $(if (@($script:Results | Where-Object { $_.status -eq 'FAIL' }).Count -eq 0) { 0 } else { 1 })
}

# ---------------------------------------------------------------------------------------------------------------------
# UI Automation helpers
# ---------------------------------------------------------------------------------------------------------------------
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$CT = [System.Windows.Automation.ControlType]
$PInvoke = [System.Windows.Automation.InvokePattern]::Pattern
$PSelect = [System.Windows.Automation.SelectionItemPattern]::Pattern
$PToggle = [System.Windows.Automation.TogglePattern]::Pattern
$PValue = [System.Windows.Automation.ValuePattern]::Pattern
$PExpand = [System.Windows.Automation.ExpandCollapsePattern]::Pattern
$PWindow = [System.Windows.Automation.WindowPattern]::Pattern

Add-Type -Namespace GuiCheck -Name Win32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
'@

# Records LiveRegionChanged events (what Narrator is told to read) on a worker thread: PowerShell script blocks can't
# run on UIA's callback threads.
$script:LiveOk = $true
try {
    Add-Type -ReferencedAssemblies ([System.Windows.Automation.AutomationElement].Assembly.Location), ([System.Windows.Automation.TreeScope].Assembly.Location), 'System.Collections', 'System.Runtime', 'System.Threading' -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Windows.Automation;
namespace GuiCheck {
    public static class Live {
        static readonly List<string> Events = new List<string>();
        static AutomationElement _root;
        static AutomationEventHandler _handler;
        public static void Start(AutomationElement root) {
            Stop();
            _root = root;
            _handler = (s, e) => {
                string id = "", name = "";
                try { var el = s as AutomationElement; id = el.Current.AutomationId; name = el.Current.Name; } catch { }
                lock (Events) Events.Add(id + "\u001f" + name);
            };
            Automation.AddAutomationEventHandler(AutomationElementIdentifiers.LiveRegionChangedEvent, root, TreeScope.Subtree, _handler);
        }
        public static void Stop() {
            if (_handler == null) return;
            try { Automation.RemoveAutomationEventHandler(AutomationElementIdentifiers.LiveRegionChangedEvent, _root, _handler); } catch { }
            _handler = null;
        }
        public static string[] Drain() {
            lock (Events) { var a = Events.ToArray(); Events.Clear(); return a; }
        }
    }
}
'@
}
catch { $script:LiveOk = $false; Log "live-region recorder unavailable: $($_.Exception.Message)" }

function Cond($prop, $value) { [System.Windows.Automation.PropertyCondition]::new($prop, $value) }
function AndCond($a, $b) { [System.Windows.Automation.AndCondition]::new([System.Windows.Automation.Condition[]]@($a, $b)) }

function Wait-Until([scriptblock] $cond, [double] $seconds = 10) {
    $end = (Get-Date).AddSeconds($seconds)
    do {
        try { $r = & $cond; if ($r) { return $r } } catch { }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $end)
    return $null
}

function Pat($el, $pattern) { $p = $null; if ($el -and $el.TryGetCurrentPattern($pattern, [ref]$p)) { return $p }; return $null }

function Get-AppProcesses {
    if ($Dll) {
        $leaf = [IO.Path]::GetFileName($Dll)
        @(Get-CimInstance Win32_Process -Filter "Name='dotnet.exe'" | Where-Object { $_.CommandLine -like "*$leaf*" } | ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    }
    else { @(Get-Process -Name PCPorter -ErrorAction SilentlyContinue) }
}

function Start-PCPorterProcess {
    if ($Dll) { Start-Process dotnet -ArgumentList "`"$Dll`"" -PassThru } else { Start-Process $Exe -PassThru }
}

# The main window: a top-level PCPorter window that holds the page area (a start-up window without it is skipped).
function Find-AppWindow([int] $procId) {
    @($AE::RootElement.FindAll($TS::Children, (Cond $AE::ProcessIdProperty $procId))) |
        Where-Object { $_.Current.ControlType -eq $CT::Window -and $_.Current.Name -like 'PCPorter*' -and
            $_.FindFirst($TS::Descendants, (Cond $AE::AutomationIdProperty 'PART_NavigationViewContentPresenter')) } | Select-Object -First 1
}

function Start-App {
    $p = Start-PCPorterProcess
    $win = Wait-Until { Find-AppWindow $p.Id } 60
    if (-not $win) { throw "PCPorter's window did not appear (process $($p.Id))" }
    $script:App = [pscustomobject]@{ Proc = $p; Win = $win; Hwnd = [IntPtr]$win.Current.NativeWindowHandle }
    Start-Sleep -Seconds 2
    if ($script:LiveOk) { try { [GuiCheck.Live]::Start($win) } catch { $script:LiveOk = $false; Log "live-region recorder failed: $($_.Exception.Message)" } }
    Log "app started (process $($p.Id))"
}

function Stop-App([int] $seconds = 30) {
    if (-not $script:App) { return $true }
    if ($script:LiveOk) { [GuiCheck.Live]::Stop() }
    $p = $script:App.Proc
    if (-not $p.HasExited) {
        Post-Close
        if (-not $p.WaitForExit($seconds * 1000)) { Log 'the app did not close; ending its process'; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $p.WaitForExit(10000) | Out-Null; $script:App = $null; return $false }
    }
    $script:App = $null
    return $true
}

function Post-Close { [GuiCheck.Win32]::PostMessage($script:App.Hwnd, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null }   # WM_CLOSE

function Get-ContentRoot { $script:App.Win.FindFirst($TS::Descendants, (Cond $AE::AutomationIdProperty 'PART_NavigationViewContentPresenter')) }
function El([string] $id, [double] $wait = 5) { Wait-Until { (Get-ContentRoot).FindFirst($TS::Descendants, (Cond $AE::AutomationIdProperty $id)) } $wait }
function ElName([string] $name, [double] $wait = 5, $type = $null) {
    Wait-Until {
        $c = Cond $AE::NameProperty $name
        if ($type) { $c = AndCond $c (Cond $AE::ControlTypeProperty $type) }
        (Get-ContentRoot).FindFirst($TS::Descendants, $c)
    } $wait
}
function Texts { @((Get-WalkedTexts) | ForEach-Object { $_.Current.Name } | Where-Object { $_ }) }
function Text-Of([string] $id) { $e = El $id 1; if ($e) { $e.Current.Name } else { $null } }
function Enabled([string] $id) { $e = El $id 1; [bool]($e -and $e.Current.IsEnabled) }
function Present([string] $id, [double] $wait = 1) { $e = El $id $wait; [bool]($e -and -not $e.Current.IsOffscreen) }

function Invoke-El($el) {
    if (-not $el) { throw 'no element to invoke' }
    $p = Pat $el $PInvoke
    if ($p) {
        # A busy UI thread (a job just starting or ending) can fail the cross-process call once: try again after a moment.
        try { $p.Invoke() } catch { Start-Sleep -Milliseconds 700; if (-not $el.Current.IsEnabled) { Log "'$($el.Current.Name)' was no longer enabled"; return }; $p.Invoke() }
        Start-Sleep -Milliseconds 300; return
    }
    $p = Pat $el $PSelect; if ($p) { $p.Select(); Start-Sleep -Milliseconds 300; return }
    throw "cannot invoke '$($el.Current.Name)'"
}
function Invoke-Id([string] $id) { Invoke-El (El $id) }
function Select-Radio([string] $id) { (Pat (El $id) $PSelect).Select(); Start-Sleep -Milliseconds 400 }
function Get-Toggle([string] $id) { $p = Pat (El $id) $PToggle; if ($p) { "$($p.Current.ToggleState)" } else { '?' } }
function Set-Toggle([string] $id, [bool] $on) {
    $p = Pat (El $id) $PToggle
    for ($i = 0; $i -lt 3 -and (($p.Current.ToggleState -eq 'On') -ne $on); $i++) { $p.Toggle(); Start-Sleep -Milliseconds 250 }
    return ($p.Current.ToggleState -eq 'On') -eq $on
}
function Get-Value([string] $id) { (Pat (El $id) $PValue).Current.Value }
function Set-Value([string] $id, [string] $v) { (Pat (El $id) $PValue).SetValue($v); Start-Sleep -Milliseconds 250 }

# The result InfoBar's title and message, or $null while it is closed. WPF-UI's InfoBar has no peer of its own: its
# template's TextBlocks (AutomationId TitleText, then the message) show up as siblings in the page. The Health page's
# "Flagged does not mean harmful" banner comes before the result, so the result is the last TitleText. FindAll and the
# control view miss these TextBlocks (so Narrator users may not reach them either), so the raw view is walked instead.
function Get-WalkedTexts {
    $w = [System.Windows.Automation.TreeWalker]::RawViewWalker   # only the raw view holds the InfoBar's TextBlocks
    $list = [System.Collections.Generic.List[object]]::new()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push((Get-ContentRoot))
    while ($stack.Count) {
        $e = $stack.Pop()
        $kids = [System.Collections.Generic.List[object]]::new()
        for ($c = $w.GetFirstChild($e); $c; $c = $w.GetNextSibling($c)) { $kids.Add($c) }
        for ($i = $kids.Count - 1; $i -ge 0; $i--) { $stack.Push($kids[$i]) }
        if ($e.Current.ControlType -eq $CT::Text) { $list.Add($e) }
    }
    return , $list
}
function Get-Result {
    $texts = Get-WalkedTexts
    $idx = -1
    for ($i = 0; $i -lt $texts.Count; $i++) { if ($texts[$i].Current.AutomationId -eq 'TitleText' -and $texts[$i].Current.Name -ne 'Flagged does not mean harmful') { $idx = $i } }
    if ($idx -lt 0) { return $null }
    $msg = if ($idx + 1 -lt $texts.Count) { $texts[$idx + 1].Current.Name } else { '' }
    [pscustomobject]@{ Title = $texts[$idx].Current.Name; Message = $msg }
}
function Wait-Result([string] $titleLike = '*', [double] $seconds = 10) { Wait-Until { $r = Get-Result; if ($r -and $r.Title -like $titleLike) { $r } } $seconds }

# Menu items (WPF-UI NavigationViewItem) have no Invoke pattern: UIA focus, then Space posted to PCPorter's own window.
$PageMarker = @{ 'Home' = 'n:What would you like to do?'; 'Web history' = 'i:AdminHint'; 'Images viewed' = 'i:WebCaches'; 'Health and security' = 'i:Elapsed'; 'About' = 'i:VersionText' }
function On-Page([string] $page, [double] $wait = 3) {
    $m = $PageMarker[$page]
    if ($m.StartsWith('n:')) { [bool](ElName $m.Substring(2) $wait) } else { [bool](El $m.Substring(2) $wait) }
}
function Go([string] $page) {
    for ($try = 0; $try -lt 3; $try++) {
        $item = $script:App.Win.FindFirst($TS::Descendants, (AndCond (Cond $AE::NameProperty $page) (Cond $AE::ControlTypeProperty $CT::DataItem)))
        if (-not $item) { throw "menu item '$page' not found" }
        $item.SetFocus(); Start-Sleep -Milliseconds 300
        [GuiCheck.Win32]::PostMessage($script:App.Hwnd, 0x100, [IntPtr]0x20, [IntPtr]0x00390001) | Out-Null              # WM_KEYDOWN Space
        Start-Sleep -Milliseconds 80
        [GuiCheck.Win32]::PostMessage($script:App.Hwnd, 0x101, [IntPtr]0x20, [IntPtr]([int64]0xC0390001)) | Out-Null     # WM_KEYUP
        if (On-Page $page 4) { Start-Sleep -Milliseconds 500; return $true }
    }
    throw "could not open the '$page' page"
}

function Find-Dialog([string] $title, [double] $wait = 10) {
    Wait-Until {
        $c = AndCond (Cond $AE::NameProperty $title) (Cond $AE::ProcessIdProperty $script:App.Proc.Id)
        $d = $script:App.Win.FindFirst($TS::Children, $c)
        if (-not $d) { $d = $AE::RootElement.FindFirst($TS::Children, $c) }
        $d
    } $wait
}
# Message box controls may show as Pane rather than Button/Text, so match on names and control ids only.
function Dialog-Text($d) { (@($d.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition) | ForEach-Object { $_.Current.Name }) -join ' ') }
# A message box button by its Win32 control id (IDOK 1, IDCANCEL 2, IDYES 6, IDNO 7) or name; BM_CLICK posted to it.
function Click-DialogButton($d, [string] $autoId, [string] $name) {
    $b = @($d.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition)) |
        Where-Object { $_.Current.NativeWindowHandle -ne 0 -and ($_.Current.AutomationId -eq $autoId -or ($name -and $_.Current.Name -eq $name)) } | Select-Object -First 1
    if (-not $b) { throw "dialog button $autoId/$name not found" }
    [GuiCheck.Win32]::PostMessage([IntPtr]$b.Current.NativeWindowHandle, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null   # BM_CLICK
    Start-Sleep -Milliseconds 600
}

function Select-Drive([string] $letterLike) {
    $combo = El 'Drives'
    $ec = Pat $combo $PExpand
    if ($ec) { $ec.Expand(); Start-Sleep -Milliseconds 600 }
    $items = @($combo.FindAll($TS::Descendants, (Cond $AE::ControlTypeProperty $CT::ListItem)))
    $names = @($items | ForEach-Object { $_.Current.Name })
    $pick = $items | Where-Object { $_.Current.Name -like $letterLike } | Select-Object -First 1
    if ($pick) { (Pat $pick $PSelect).Select(); Start-Sleep -Milliseconds 300 }
    if ($ec) { try { $ec.Collapse() } catch { } ; Start-Sleep -Milliseconds 300 }
    [pscustomobject]@{ Names = $names; Picked = [bool]$pick; Value = (Get-ComboText $combo) }
}
function Get-ComboText($combo) {
    $v = Pat $combo $PValue
    if ($v) { return "$($v.Current.Value)" }
    $s = Pat $combo ([System.Windows.Automation.SelectionPattern]::Pattern)
    if ($s) { return (@($s.Current.GetSelection() | ForEach-Object { $_.Current.Name }) -join ';') }
    return ''
}

function Drain-Live {
    if (-not $script:LiveOk) { return @() }
    Start-Sleep -Milliseconds 1500   # events arrive on UIA's threads a moment after the change
    @([GuiCheck.Live]::Drain() | ForEach-Object { $p = $_ -split [char]0x1f, 2; [pscustomobject]@{ Id = $p[0]; Text = $p[1] } })
}

$Browsers = 'Google Chrome', 'Microsoft Edge', 'Firefox', 'Brave', 'Opera', 'Vivaldi', 'Internet Explorer', 'Chromium'
function Browsers-In([string[]] $texts) { @($Browsers | Where-Object { $b = $_; $texts | Where-Object { $_ -and $_.Contains($b) } }) }

# Watches a run from Start to its end, sampling the page. $During runs once, $DuringAfter seconds after the start.
function Watch-Run {
    # -Stopping: Cancel was already pressed (it greys itself), so do not wait for the run to start; just wait for its end.
    # -MemKey: the page's key in settings.json; a run that ends before Cancel is ever seen enabled still counts as started
    # and finished when the page remembered a run that finished just now.
    param([string[]] $GreyIds, [string] $StatusId, [string] $CardsId, [int] $TimeoutMin = 25, [scriptblock] $During, [double] $DuringAfter = 4, [switch] $Stopping, [string] $MemKey)
    $o = [ordered]@{ started = $false; stillEnabled = @(); cancelEnabled = $false; statuses = [System.Collections.Generic.List[string]]::new()
        cardCounts = [System.Collections.Generic.List[int]]::new(); cardStates = [System.Collections.Generic.List[string]]::new()
        elapsed = [System.Collections.Generic.List[string]]::new(); finished = $false; seconds = 0; duringDone = $false; quick = $false }
    $since = (Get-Date).AddSeconds(-3)
    $justFinished = { if (-not $MemKey) { return $false }; $m = Get-Memory $MemKey; $m -and $m.LastRun -and [datetime]$m.LastRun.FinishedAt -ge $since -and (Enabled 'StartButton') }
    $o.started = $Stopping -or [bool](Wait-Until { (Enabled 'CancelButton') -or (& $justFinished) } 15)
    if (-not $o.started) { return $o }
    if (-not $Stopping -and -not (Enabled 'CancelButton') -and (& $justFinished)) { $o.finished = $o.quick = $true; return $o }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $o.stillEnabled = @($GreyIds | Where-Object { Enabled $_ })
    $o.cancelEnabled = Enabled 'CancelButton'
    $doneSince = $null
    while ($sw.Elapsed.TotalMinutes -lt $TimeoutMin) {
        if ($script:App.Proc.HasExited) { $o.appExited = $true; break }
        $cancel = El 'CancelButton' 1
        if ($cancel) {
            $s = Text-Of $StatusId
            if ($s -and ($o.statuses.Count -eq 0 -or $o.statuses[-1] -ne $s)) { $o.statuses.Add($s) }
            if ($CardsId) {
                $cards = El $CardsId 1
                if ($cards) {
                    $states = @($cards.FindAll($TS::Descendants, (Cond $AE::ControlTypeProperty $CT::Text)) | ForEach-Object { $_.Current.Name } |
                        Where-Object { $_ -match '^(Waiting|Checking\.\.\.|Done - |Partly done - |Not available|Stopped|Took too long|Couldn)' })
                    if ($o.cardCounts.Count -eq 0 -or $o.cardCounts[-1] -ne $states.Count) { $o.cardCounts.Add($states.Count) }
                    foreach ($st in $states) { if (-not $o.cardStates.Contains($st)) { $o.cardStates.Add($st) } }
                }
                $e = Text-Of 'Elapsed'; if ($e -and -not $o.elapsed.Contains($e)) { $o.elapsed.Add($e) }
            }
            $finishedNow = $cancel -and -not $cancel.Current.IsEnabled -and (Enabled 'StartButton')
            if ($finishedNow) { if (-not $doneSince) { $doneSince = Get-Date } elseif (((Get-Date) - $doneSince).TotalSeconds -ge 1) { $o.finished = $true; break } }
            else { $doneSince = $null }
        }
        if ($During -and -not $o.duringDone -and $sw.Elapsed.TotalSeconds -ge $DuringAfter -and -not $o.finished) { $o.duringDone = $true; & $During $o }
        Start-Sleep -Milliseconds 400
    }
    $o.seconds = [int]$sw.Elapsed.TotalSeconds
    return $o
}

# Close during a job, answer No: the box must appear, the run must go on.
$CloseNo = {
    param($o)
    if (-not (Enabled 'CancelButton')) { $o.closeSkipped = $true; return }   # the run already ended: closing now would just close
    Post-Close
    $d = Find-Dialog 'Stop and close?' 10
    $o.closeAsked = [bool]$d
    if ($d) {
        $o.closeText = (Dialog-Text $d) -match 'still working'
        Click-DialogButton $d '7' 'No'
        $o.closeGone = -not (Find-Dialog 'Stop and close?' 2)
    }
    Start-Sleep -Milliseconds 500
    $o.runningAfterNo = Enabled 'CancelButton'
    $o.appAliveAfterNo = -not $script:App.Proc.HasExited
}
function Report-CloseNo([string] $id, [string] $what, $o) {
    if ($o.closeSkipped) { Skip $id "Close during $what, answer No: the run goes on and finishes" "the run ended after $($o.seconds) s, before the window could be closed during it"; return }
    Check $id "Close during $what, answer No: the run goes on and finishes" ($o.closeAsked -and $o.closeText -and $o.closeGone -and $o.runningAfterNo -and $o.appAliveAfterNo -and $o.finished) `
        "asked 'Stop and close?'=$($o.closeAsked) (says still working=$($o.closeText)); box gone after No=$($o.closeGone); still running=$($o.runningAfterNo); finished=$($o.finished) after $($o.seconds) s"
}

# Case folders, links and permissions -----------------------------------------------------------------------------
function Get-CaseFolders { $r = Join-Path $Manual 'PCPorter'; if (Test-Path -LiteralPath $r) { @(Get-ChildItem -LiteralPath $r -Directory | ForEach-Object FullName) } else { @() } }
function Get-WorkFolders { @(Get-CaseFolders | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'work') }) }

function Test-CaseFolderPath([string] $p) {
    if (-not $p -or $p -notmatch '^[A-Za-z]:\\' -or $p.Contains('/')) { return $false }
    if ([IO.Path]::GetFullPath($p) -cne $p) { return $false }
    $t = $p.TrimEnd('\'); $parent = Split-Path $t -Parent
    return ((Split-Path $t -Leaf) -cmatch '^[\p{L}\p{Nd}_-]+_\d{8}T\d{6}Z_[0-9a-f]{6}$') -and $parent -and ((Split-Path $parent -Leaf) -eq 'PCPorter')
}
function Test-ReportPath([string] $p) {
    if (-not $p -or [IO.Path]::GetExtension($p) -ne '.html' -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return $false }
    for ($d = Split-Path $p -Parent; $d; $d = Split-Path $d -Parent) { if (Test-CaseFolderPath $d) { return $true } }
    return $false
}

function Get-Memory([string] $page) {
    if (-not (Test-Path -LiteralPath $SettingsFile)) { return $null }
    $j = Get-Content -LiteralPath $SettingsFile -Raw | ConvertFrom-Json
    if ($j.Pages -and $j.Pages.PSObject.Properties[$page]) { return $j.Pages.$page }
    return $null
}

function Test-CaseAcl([string] $path) {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = Get-Acl -LiteralPath $path
    $labels = @(); $extra = 0
    foreach ($rule in $acl.Access) {
        $sid = try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$($rule.IdentityReference)" }
        $label = switch ($sid) { 'S-1-5-18' { 'SYSTEM' } 'S-1-5-32-544' { 'Administrators' } { $_ -eq $me } { 'current user' } default { $extra++; "other ($sid)" } }
        if ($labels -notcontains $label) { $labels += $label }
    }
    [pscustomobject]@{ Ok = ($extra -eq 0 -and $labels.Count -gt 0); Labels = ($labels -join ', '); Protected = $acl.AreAccessRulesProtected }
}

function Describe-Case([string] $case) {
    $names = @(Get-ChildItem -LiteralPath $case -Force | ForEach-Object { if ($_.PSIsContainer) { "$($_.Name)\" } else { $_.Name } })
    return $names
}

function Get-ExplorerWindows { @($AE::RootElement.FindAll($TS::Children, (Cond $AE::ClassNameProperty 'CabinetWClass'))) }

# "Open the case folder": invoke it while watching explorer.exe starts, expect a File Explorer window for exactly that
# folder, then close only that window (identified by the case folder's unique name and not open before).
function Test-OpenFolder([string] $id, [string] $item, [string] $expected) {
    $btn = El 'OpenFolder' 2
    if (-not $btn -or -not $btn.Current.IsEnabled) { Check $id $item $false 'button not shown or not enabled'; return }
    if (-not (Test-CaseFolderPath $expected) -or -not (Test-Path -LiteralPath $expected)) { Check $id $item $false 'the remembered path does not pass the case folder check'; return }
    $leaf = Split-Path $expected -Leaf
    $before = @(Get-ExplorerWindows | ForEach-Object { $_.Current.NativeWindowHandle })
    Get-Event -SourceIdentifier 'gc-*' -ErrorAction SilentlyContinue | Remove-Event
    Register-CimIndicationEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 0.2 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'" -SourceIdentifier 'gc-create' | Out-Null
    if ($IsAdmin) { Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'explorer.exe'" -SourceIdentifier 'gc-trace' | Out-Null }
    try {
        Start-Sleep -Milliseconds 800
        Invoke-El $btn
        $win = Wait-Until { Get-ExplorerWindows | Where-Object { $_.Current.NativeWindowHandle -notin $before -and ($_.Current.Name -eq $leaf -or $_.Current.Name -like "$leaf - *") } | Select-Object -First 1 } 15
        Start-Sleep -Milliseconds 1500
        $created = @(Get-Event -SourceIdentifier 'gc-create' -ErrorAction SilentlyContinue | ForEach-Object { $_.SourceEventArgs.NewEvent.TargetInstance })
        $traced = @(Get-Event -SourceIdentifier 'gc-trace' -ErrorAction SilentlyContinue | ForEach-Object { $_.SourceEventArgs.NewEvent })
    }
    finally {
        Unregister-Event -SourceIdentifier 'gc-create' -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier 'gc-trace' -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier 'gc-*' -ErrorAction SilentlyContinue | Remove-Event
    }
    $appPid = $script:App.Proc.Id
    $byApp = @($traced | Where-Object { $_.ParentProcessID -eq $appPid }).Count + @($created | Where-Object { $_.ParentProcessId -eq $appPid }).Count
    # Only the explorer.exe PCPorter itself started (the shell may start more, e.g. "explorer.exe /factory,... -Embedding").
    $cmd = $created | Where-Object { $_.CommandLine -and $_.ParentProcessId -eq $appPid } | Select-Object -First 1
    $exe = Join-Path $env:windir 'explorer.exe'
    $cmdOk = if ($cmd) { $cmd.CommandLine.Contains($expected) -and $cmd.ExecutablePath -eq $exe } else { $null }
    $closed = $false
    if ($win) { try { (Pat $win $PWindow).Close(); $closed = $true } catch { } }
    $ok = $win -and $byApp -gt 0 -and ($cmdOk -ne $false)
    Check $id $item $ok "explorer.exe started by PCPorter=$($byApp -gt 0); command line seen=$([bool]$cmd) (matches %windir%\explorer.exe + the case folder=$cmdOk); new Explorer window for that case folder=$([bool]$win); closed it again=$closed"
}

function Get-ShadowIds {
    if (-not $IsAdmin) { return $null }
    $out = & "$env:windir\System32\vssadmin.exe" list shadows 2>&1 | Out-String
    @([regex]::Matches($out, 'Shadow Copy ID: (\{[0-9a-fA-F-]+\})') | ForEach-Object { $_.Groups[1].Value })
}

# Health page refusal helper: set the folder, press Start, read the box.
function Try-Refused([string] $folder) {
    Set-Value 'OutFolder' $folder
    Invoke-Id 'StartButton'
    $r = Wait-Result '*' 8
    $started = Enabled 'CancelButton'
    if ($started) { Invoke-Id 'CancelButton'; Wait-Until { Enabled 'StartButton' } 180 | Out-Null }   # not refused: stop it again
    [pscustomobject]@{ Title = $r.Title; Message = $r.Message; Started = $started }
}

# ---------------------------------------------------------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------------------------------------------------------
$script:Started = (Get-Date).ToString('s')
$script:AppVersion = if ($Dll) { (Get-Item $Dll).VersionInfo.ProductVersion } else { (Get-Item $Exe).VersionInfo.ProductVersion }
$script:AppElevated = $IsAdmin
$script:Queue = [System.Collections.Generic.List[object]]::new()
function Queue-Render($entry) { $script:Queue.Add($entry); $script:Queue | ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath $QueueFile -Encoding utf8 }

$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$state = @{ subst = $false; settingsMoved = $false; settingsExisted = $false; shadowsBefore = $null }
Log "Phase 1: $(if ($Dll) { 'debug build' } else { $Exe }) version $($script:AppVersion); script elevated=$IsAdmin; results $RunDir"

try {
    # ----- setup ------------------------------------------------------------------------------------------------------
    if (@(Get-AppProcesses).Count -gt 0) { throw 'PCPorter is already running. Close it first (this script never ends a PCPorter it did not start).' }
    # Any PCPorter in this session (also a debug build from another folder) holds the single-instance mutex: a new start
    # would only bring that one forward.
    $m = $null
    $held = try { [System.Threading.Mutex]::TryOpenExisting('Local\PCPorter-7d1f6a2e', [ref]$m) } catch [System.UnauthorizedAccessException] { $true }
    if ($m) { $m.Dispose() }
    if ($held) { throw 'Another PCPorter (possibly a debug build) is running in this session. Close it first.' }
    if (Test-Path -LiteralPath $Manual) { throw "$Manual already exists. Move or delete it first (it is deleted at the end of this run)." }
    New-Item -ItemType Directory -Force $Manual | Out-Null
    Set-Content -LiteralPath $ManualMarker -Value $Manual

    if (Test-Path -LiteralPath $SettingsBackup) { throw "$SettingsBackup exists from an earlier run: put it back as settings.json (or delete it) first." }
    if (Test-Path -LiteralPath $SettingsFile) {
        $state.settingsExisted = $true
        Move-Item -LiteralPath $SettingsFile -Destination $SettingsBackup -Force
        $state.settingsMoved = $true
    }
    $state.settingsHandled = $true
    Log "settings.json backed up=$($state.settingsMoved) (existed=$($state.settingsExisted)); the pages start with their defaults"

    if (-not (Test-Path -LiteralPath (Join-Path $Fixture 'Windows\System32\config\SOFTWARE'))) {
        Log 'the fake old-PC drive is missing: exporting it (as scripts/regress.ps1 does)'
        New-Item -ItemType Directory -Force $Fixture | Out-Null
        $env:PCPORTER_FIXTURE_OUT = $Fixture
        try { dotnet test (Join-Path $Repo 'tests\PCPorter.Reports.Tests') --filter 'FullyQualifiedName~Export_fixture_drive_for_the_smoke_run' -nologo 2>&1 | Out-File (Join-Path $RunDir 'fixture.txt') }
        finally { Remove-Item Env:PCPORTER_FIXTURE_OUT -ErrorAction SilentlyContinue }
        if (-not (Test-Path -LiteralPath (Join-Path $Fixture 'Windows\System32\config\SOFTWARE'))) { throw 'could not write the fake old-PC drive (see fixture.txt)' }
    }
    if (Test-Path "$Letter\") { throw "$Letter is already in use; free it first" }
    & subst.exe $Letter $Fixture
    if (-not (Test-Path "$Letter\Windows\System32\config\SOFTWARE")) { throw "subst $Letter failed" }
    $state.subst = $true
    Log "subst $Letter -> fake old-PC drive"
    $state.shadowsBefore = Get-ShadowIds
    if ($null -ne $state.shadowsBefore) { Log "shadow copies before: $($state.shadowsBefore.Count)" }

    # ===== Session A ==================================================================================================
    Start-App
    $title = $script:App.Win.Current.Name
    $script:AppElevated = $title -ceq 'PCPorter  -  running as administrator'
    if (-not $Dll) { Check '1.1' "Title says 'PCPorter  -  running as administrator'" $script:AppElevated "title '$title'" }
    else { Check '1.1' 'Title matches how the app runs' ($title -ceq $(if ($IsAdmin) { 'PCPorter  -  running as administrator' } else { 'PCPorter' })) "title '$title' (debug build, script elevated=$IsAdmin)" }

    # 1. Home -------------------------------------------------------------------------------------------------------
    Go 'Home' | Out-Null
    $tileNames = 'Move to my new PC (coming soon)', "Explore my PC's history", 'Check health and security'
    $tiles = @($tileNames | Where-Object { ElName $_ 2 $CT::Button })
    $texts = Texts
    Check '1.2' 'Home shows three tiles; the Move tile says Coming soon' ($tiles.Count -eq 3 -and $texts -contains 'Coming soon') "tiles found $($tiles.Count) of 3 [$($tiles -join '; ')]; 'Coming soon' text=$($texts -contains 'Coming soon')"

    Invoke-El (ElName 'Move to my new PC (coming soon)' 2 $CT::Button)
    $d = Find-Dialog 'Move to my new PC' 10
    if ($d) {
        $dt = Dialog-Text $d
        Click-DialogButton $d '2' 'OK'
        $gone = -not (Find-Dialog 'Move to my new PC' 2)
        Check '1.3' "Move to my new PC: a box says it is still being built and points to the health check" ($dt -match 'still being built' -and $dt -match 'Check health and security' -and $gone) "box text mentions 'still being built'=$($dt -match 'still being built'), 'Check health and security'=$($dt -match 'Check health and security'); closed with OK=$gone"
    }
    else { Check '1.3' 'Move to my new PC: a box says it is still being built' $false 'no box appeared' }

    # Second start: the first window comes forward, the second exits.
    $wp = Pat $script:App.Win $PWindow
    $wp.SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Minimized); Start-Sleep -Seconds 1
    $minimized = "$($wp.Current.WindowVisualState)"
    $p2 = Start-PCPorterProcess
    $exited = $p2.WaitForExit(30000)
    $code = if ($exited) { $p2.ExitCode } else { 'still running' }
    if (-not $exited) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }
    $restored = Wait-Until { "$($wp.Current.WindowVisualState)" -eq 'Normal' } 10
    $fg = [GuiCheck.Win32]::GetForegroundWindow() -eq $script:App.Hwnd
    $still = -not $script:App.Proc.HasExited
    Check '1.4' 'Second start: the first window comes forward, the second exits' ($exited -and $code -eq 0 -and $restored -and $still) "before: $minimized; second exited=$exited (code $code); first window restored=$([bool]$restored), in front=$fg, still open=$still (the app shows no box: by design SingleInstance.cs only brings the first window forward)"
    if (-not $restored) { $wp.SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Normal) }

    Skip '1.5' 'Light/dark theme follows Windows' 'needs changing Windows settings (Personalization > Colors)'

    Go 'About' | Out-Null
    $ver = Text-Of 'VersionText'
    $logBtn = ElName 'Open log folder' 2 $CT::Button
    $verOk = $ver -and $script:AppVersion -and $ver.Contains($script:AppVersion)
    Check '1.6' "About: the version shows; 'Open log folder' exists" ($verOk -and $logBtn -and $logBtn.Current.IsEnabled) "version text '$ver' (file version $($script:AppVersion)); Open log folder button enabled=$([bool]($logBtn -and $logBtn.Current.IsEnabled)) (not pressed: it would open Explorer)"

    # 2. Health and security (this PC) ------------------------------------------------------------------------------
    Go 'Health and security' | Out-Null
    $removable = try { [IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -eq 'Removable' } | Select-Object -First 1 } catch { $null }
    $expectDefault = if ($removable) { $removable.RootDirectory.FullName } else { 'C:\PCPorterCases' }
    $def = Wait-Until { $v = Get-Value 'OutFolder'; if ($v -eq $expectDefault) { $v } } 8
    Check '2.1' 'Default save folder: a removable drive, else C:\PCPorterCases' ([bool]$def) "box '$(Get-Value 'OutFolder')', expected '$expectDefault'"

    if ($env:OneDrive -and (Test-Path -LiteralPath $env:OneDrive)) {
        $od = Join-Path $env:OneDrive "PCPorter-gui-check-$stamp"
        if ($script:AppElevated) { Select-Radio 'ThisPc' } else { Select-Radio 'OtherDrive'; Select-Drive "$Letter\*" | Out-Null }   # not elevated: This PC stops at "Administrator rights needed"
        $r = Try-Refused $od
        Check '2.2' 'OneDrive save folder: "Pick another folder" with the cloud-sync reason; nothing created' ($r.Title -eq 'Pick another folder' -and $r.Message -match 'cloud|OneDrive' -and -not $r.Started -and -not (Test-Path -LiteralPath $od)) "box '$($r.Title)': '$($r.Message)'; run started=$($r.Started); folder created=$(Test-Path -LiteralPath $od)"
        Select-Radio 'ThisPc'
    }
    else { Skip '2.2' 'OneDrive save folder refused' 'no OneDrive folder on this PC' }

    if ($script:AppElevated) {
        Select-Radio 'ThisPc'
        Set-Value 'OutFolder' $Manual
        $before = Get-CaseFolders
        Drain-Live | Out-Null
        Invoke-Id 'StartButton'
        $o = Watch-Run -GreyIds 'ThisPc', 'OtherDrive', 'OutFolder', 'StartButton' -StatusId 'Step' -CardsId 'Cards' -TimeoutMin 25 -During $CloseNo -DuringAfter 4 -MemKey scan
        $live = Drain-Live
        $grow = @($o.cardCounts | Select-Object -Unique).Count
        Check '2.3' 'Cards appear one by one with counts; the elapsed timer runs' ($grow -ge 2 -and ($o.cardStates | Where-Object { $_ -match '^Done - \d+ found' }) -and $o.elapsed.Count -ge 2) "card counts seen [$(($o.cardCounts | Select-Object -Unique) -join ', ')]; states seen [$(($o.cardStates | ForEach-Object { $_ -replace '\d+', 'N' } | Select-Object -Unique) -join '; ')]; elapsed values $($o.elapsed.Count) (last '$($o.elapsed[-1])')"
        Check '2.4' 'While it runs: scan choice, folder box, Start greyed; Cancel enabled' ($o.started -and $o.stillEnabled.Count -eq 0 -and $o.cancelEnabled) "still enabled while running: [$($o.stillEnabled -join ', ')]; Cancel enabled=$($o.cancelEnabled)"
        Report-CloseNo '5c.1' 'a health check' $o
        $res = Get-Result
        $after = @(Get-CaseFolders | Where-Object { $_ -notin $before })
        $mem = Get-Memory 'scan'
        $rep = $mem.LastRun.ReportPath; $case = $mem.LastRun.CaseFolder
        $btnOk = (Present 'OpenReport') -and (Enabled 'OpenReport') -and (Present 'OpenFolder') -and (Enabled 'OpenFolder')
        Check '2.5' 'When it ends: a result message, "Open the report" and "Open the case folder"' ($o.finished -and $res.Title -eq 'Done' -and $btnOk -and (Test-ReportPath $rep)) "finished in $($o.seconds) s; box '$($res.Title)': '$($res.Message)'; both buttons shown and enabled=$btnOk; report path passes the app's check=$(Test-ReportPath $rep) (not opened: it would open the browser)"
        if ($after.Count -eq 1 -and $case -eq $after[0]) {
            $names = Describe-Case $case
            $acl = Test-CaseAcl $case
            $hasScan = @($names | Where-Object { $_ -like '*\' }).Count -ge 1
            Check '2.6' 'Case folder holds HealthReport.html, case.db and a scan folder; permissions only SYSTEM, Administrators and you' (($names -contains 'HealthReport.html') -and ($names -contains 'case.db') -and $hasScan -and $acl.Ok) "contents [$($names -join ', ')]; permissions [$($acl.Labels)] (inheritance off=$($acl.Protected))"
            Queue-Render @{ id = '2.7'; item = 'Health report: banner counts match the labels; footer says read-only'; kind = 'health'; path = $rep }
            Test-OpenFolder '2.8' '"Open the case folder" opens that case folder in File Explorer' $case
        }
        else { Check '2.6' 'Case folder contents and permissions' $false "new case folders $($after.Count); remembered case folder matches=$($case -in $after)" }
        $steps = @($live | Where-Object { $_.Id -eq 'Step' } | ForEach-Object Text)
        $stepLines = @($steps | Where-Object { $_ -match '^Step \d+ of \d+: ' })
        $sampledSteps = @($o.statuses | Where-Object { $_ -match '^Step \d+ of \d+: ' } | Select-Object -Unique)
        $finishEvent = [bool]($steps | Where-Object { $_ -like 'Scan finished*' })
        $finishText = [bool]($o.statuses | Where-Object { $_ -like 'Scan finished*' })
        Check '6.2' 'Health: the live region (Step, LiveRegionChanged) announces each step and the end' ($script:LiveOk -and $stepLines.Count -ge 2 -and $finishText) "LiveRegionChanged events from Step: $($steps.Count) ($(@($stepLines | Select-Object -Unique).Count) distinct 'Step N of M', last '$($steps[-1])'); finish line raised as an event=$finishEvent; Step text read while running: $($sampledSteps.Count) distinct steps, finish line shown=$finishText"

        # Cancel during the second or third card.
        $before = Get-CaseFolders
        Drain-Live | Out-Null
        Invoke-Id 'StartButton'
        $at = Wait-Until { $s = Text-Of 'Step'; if ($s -match '^Step [23] of') { $s } } 180
        $stopping = $null
        if ($at) { Invoke-Id 'CancelButton'; $stopping = Wait-Until { $s = Text-Of 'Step'; if ($s -like 'Stopping*') { $s } } 3 }
        $o = Watch-Run -GreyIds @() -StatusId 'Step' -CardsId 'Cards' -TimeoutMin 10 -Stopping -MemKey scan
        $live = Drain-Live
        $res = Get-Result
        $enabledAgain = (Enabled 'ThisPc') -and (Enabled 'OutFolder') -and (Enabled 'StartButton') -and -not (Enabled 'CancelButton')
        $mem = Get-Memory 'scan'
        Check '2.9' 'Cancel during the 2nd/3rd card: "Stopped"; the controls are enabled again' ($at -and $res.Title -eq 'Stopped' -and $enabledAgain -and (Test-ReportPath $mem.LastRun.ReportPath)) "cancelled at '$at'; box '$($res.Title)': '$($res.Message)'; controls enabled again=$enabledAgain; report kept=$(Test-ReportPath $mem.LastRun.ReportPath) (severity colour not readable through UIA)"
        if (Test-ReportPath $mem.LastRun.ReportPath) {
            Queue-Render @{ id = '2.10'; item = 'Stopped health report shows what was checked so far'; kind = 'health'; path = $mem.LastRun.ReportPath; markers = @(@{ label = "says 'stopped early'"; text = 'stopped early' }) }
        }
        $steps = @($live | Where-Object { $_.Id -eq 'Step' } | ForEach-Object Text)
        Check '6.3' 'Health: Cancel is announced "Stopping after the current step..." then "Scan stopped."' ($steps -contains 'Stopping after the current step...' -and $steps -contains 'Scan stopped.') "live events [$((@($steps | Where-Object { $_ -notmatch '^Step ' }) ) -join ' | ')]"
    }
    else {
        foreach ($i in '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9', '2.10', '6.2', '6.3', '5c.1') { Skip $i 'Health and security on this PC' 'the app is not elevated (it refuses This PC)' }
    }

    # 3. Health and security (another PC's drive) ----------------------------------------------------------------------
    Select-Radio 'OtherDrive'
    Invoke-El (ElName 'Refresh' 2 $CT::Button)
    Start-Sleep -Seconds 3
    $sel = Select-Drive "$Letter\*"
    Check '3.1' "Another PC's drive + Refresh: $Letter\ is listed" ($sel.Picked) "drive list [$($sel.Names -join '; ')]; selected '$($sel.Value)'"
    $r = Try-Refused "$Letter\out"
    Check '3.2' "Save folder $Letter\out is refused; nothing created on $Letter" ($r.Title -eq 'Pick another folder' -and -not $r.Started -and -not (Test-Path "$Letter\out")) "box '$($r.Title)': '$($r.Message)'; $Letter\out exists=$(Test-Path "$Letter\out")"
    $r = Try-Refused (Join-Path $Fixture 'out')
    Check '3.3' 'Save folder on the same drive by its real path is refused; no out folder in the fixture' ($r.Title -eq 'Pick another folder' -and -not $r.Started -and -not (Test-Path (Join-Path $Fixture 'out'))) "box '$($r.Title)': '$($r.Message)'; out folder exists=$(Test-Path (Join-Path $Fixture 'out'))"
    Set-Value 'OutFolder' $Manual
    Invoke-Id 'StartButton'
    $o = Watch-Run -GreyIds 'ThisPc', 'OtherDrive', 'OutFolder', 'StartButton' -StatusId 'Step' -CardsId 'Cards' -TimeoutMin 15 -MemKey scan
    $res = Get-Result
    $mem = Get-Memory 'scan'
    $okRun = $o.finished -and $res.Title -eq 'Done' -and (Test-ReportPath $mem.LastRun.ReportPath)
    if ($okRun) {
        Queue-Render @{ id = '3.4'; item = "Old PC's drive: report names OLDPC and Windows 10 and shows the planted findings"; kind = 'health'; path = $mem.LastRun.ReportPath
            markers = @(@{ label = 'OLDPC'; text = 'OLDPC' }, @{ label = 'Windows 10'; text = 'Windows 10' }, @{ label = 'Winlogon Taskman'; text = 'Taskman' },
                @{ label = 'user Run entry in AppData'; text = 'x7f3kq9zpw.exe' }, @{ label = 'forced Chrome extension'; text = 'aaaabbbbccccddddeeeeffffgggghhhh' }, @{ label = 'forced Firefox extension'; text = 'evil.example' }) }
    }
    else { Check '3.4' "Old PC's drive: the check runs to the end" $false "finished=$($o.finished); box '$($res.Title)': '$($res.Message)'" }
    Skip '3.5' 'BitLocker-locked drive: listed as (locked or not ready), Start says Pick a drive' 'no BitLocker-locked drive is connected'

    # 4. Images viewed --------------------------------------------------------------------------------------------------
    Go 'Images viewed' | Out-Null
    if ($env:OneDrive -and (Test-Path -LiteralPath $env:OneDrive)) {
        $od = Join-Path $env:OneDrive "PCPorter-gui-check-$stamp"
        $r = Try-Refused $od
        Check '4.1' 'Images viewed: OneDrive save folder refused; nothing created' ($r.Title -eq 'Pick another folder' -and -not $r.Started -and -not (Test-Path -LiteralPath $od)) "box '$($r.Title)': '$($r.Message)'; folder created=$(Test-Path -LiteralPath $od)"
    }
    else { Skip '4.1' 'Images viewed: OneDrive folder refused' 'no OneDrive folder on this PC' }
    if ((Enabled 'AllUsers')) { Set-Toggle 'AllUsers' $false | Out-Null }   # other people's pictures are not part of this test
    Set-Toggle 'WebCaches' $true | Out-Null
    Set-Toggle 'FullIndex' $false | Out-Null
    Set-Value 'OutFolder' $Manual
    Invoke-Id 'StartButton'
    $o = Watch-Run -GreyIds 'OutFolder', 'WebCaches', 'FullIndex', 'AllUsers', 'StartButton' -StatusId 'Status' -TimeoutMin 30 -During $CloseNo -DuringAfter 3 -MemKey thumbs
    Check '4.2' 'Gallery: while it runs the folder, checkboxes and Start are greyed; Cancel enabled' ($o.started -and $o.stillEnabled.Count -eq 0 -and $o.cancelEnabled) "still enabled while running: [$($o.stillEnabled -join ', ')]; Cancel enabled=$($o.cancelEnabled)"
    Report-CloseNo '5c.2' 'a gallery' $o
    $res = Get-Result
    $mem = Get-Memory 'thumbs'
    $galleryOk = $o.finished -and $res.Title -eq 'Gallery ready' -and (Test-ReportPath $mem.LastRun.ReportPath) -and (Present 'OpenReport')
    Check '4.4' 'Gallery finishes with a result and "Open the report"' $galleryOk "finished in $($o.seconds) s; box '$($res.Title)': '$($res.Message)'; Open the report shown=$(Present 'OpenReport'); report path passes the app's check=$(Test-ReportPath $mem.LastRun.ReportPath)"
    if ($galleryOk) { Queue-Render @{ id = '4.R1'; item = 'Gallery report: pictures, filters and grouping are on the page'; kind = 'gallery'; path = $mem.LastRun.ReportPath } }

    $before = Get-CaseFolders
    Invoke-Id 'StartButton'
    $running = Wait-Until { Enabled 'CancelButton' } 15
    Start-Sleep -Seconds 3
    $stillRunning = Enabled 'CancelButton'
    if ($stillRunning) { Invoke-Id 'CancelButton' }
    $o = Watch-Run -GreyIds @() -StatusId 'Status' -TimeoutMin 10 -Stopping -MemKey thumbs
    $res = Get-Result
    $new = @(Get-CaseFolders | Where-Object { $_ -notin $before })
    $work = Get-WorkFolders
    Check '4.3' 'Gallery Cancel: no new case folder (not even half-written) and no work folder' ($stillRunning -and $o.finished -and $new.Count -eq 0 -and $work.Count -eq 0) "cancelled while running=$stillRunning; new case folders $($new.Count); work folders $($work.Count)"
    Check '4.3b' 'Gallery Cancel: the message says "Stopped"' ($res.Title -eq 'Stopped') "box '$($res.Title)': '$($res.Message)'"

    Set-Toggle 'WebCaches' $false | Out-Null
    Invoke-Id 'StartButton'
    $o = Watch-Run -GreyIds @() -StatusId 'Status' -TimeoutMin 30 -MemKey thumbs
    $res = Get-Result
    $web = [regex]::Match("$($res.Message)", '([\d,.]+) web images')
    Check '4.5' 'Gallery without "Include web browser caches": no web pictures' ($o.finished -and $res.Title -eq 'Gallery ready' -and $web.Success -and $web.Groups[1].Value -eq '0') "box '$($res.Title)': '$($res.Message)'"

    # 5. Web history --------------------------------------------------------------------------------------------------
    Go 'Home' | Out-Null
    Invoke-El (ElName "Explore my PC's history" 2 $CT::Button)
    $viaTile = On-Page 'Web history' 5
    $link = ElName 'Go to Images viewed' 3 $CT::Hyperlink
    if ($link) { Invoke-El $link }
    $viaLink = On-Page 'Images viewed' 5
    Go 'Web history' | Out-Null
    Check '5.1' "Home > Explore my PC's history opens Web history (also in the menu); 'Go to Images viewed' opens the gallery" ($viaTile -and $viaLink) "tile opened Web history=$viaTile; link found=$([bool]$link), opened Images viewed=$viaLink; menu opened Web history=True"

    Select-Radio 'ThisPc'
    if ($env:OneDrive -and (Test-Path -LiteralPath $env:OneDrive)) {
        $od = Join-Path $env:OneDrive "PCPorter-gui-check-$stamp"
        $r = Try-Refused $od
        Check '5.2' 'Web history: OneDrive save folder refused; nothing created' ($r.Title -eq 'Pick another folder' -and -not $r.Started -and -not (Test-Path -LiteralPath $od)) "box '$($r.Title)': '$($r.Message)'; folder created=$(Test-Path -LiteralPath $od)"
    }
    else { Skip '5.2' 'Web history: OneDrive folder refused' 'no OneDrive folder on this PC' }

    if ($script:AppElevated) {
        $a = Set-Toggle 'AllUsers' $true; $b = Set-Toggle 'RestorePoints' $true
        Check '5.3' 'Both "other accounts" and "restore points" can be ticked' ($a -and $b -and (Get-Toggle 'AllUsers') -eq 'On' -and (Get-Toggle 'RestorePoints') -eq 'On') "other accounts: enabled=$(Enabled 'AllUsers'), ticked=$(Get-Toggle 'AllUsers'); restore points: enabled=$(Enabled 'RestorePoints'), ticked=$(Get-Toggle 'RestorePoints')"
        Set-Toggle 'AllUsers' $false | Out-Null   # other accounts' history is not part of this test
    }
    else { Skip '5.3' 'Both checkboxes can be ticked' "the app is not elevated (both are greyed: '$(Text-Of 'AdminHint')')" }

    Set-Value 'OutFolder' $Manual
    $folderBefore = Get-Value 'OutFolder'
    $optsBefore = "$(Get-Toggle 'AllUsers')/$(Get-Toggle 'RestorePoints')"
    $before = Get-CaseFolders
    Drain-Live | Out-Null
    Invoke-Id 'StartButton'
    $nav = {
        param($o)
        Go 'Home' | Out-Null
        Start-Sleep -Milliseconds 500
        Go 'Web history' | Out-Null
        $o.navRunning = Enabled 'CancelButton'
        $o.navStatus = [bool](Text-Of 'Status')
        $o.navFolderSame = (Get-Value 'OutFolder') -eq $folderBefore
        $o.navOptsSame = "$(Get-Toggle 'AllUsers')/$(Get-Toggle 'RestorePoints')" -eq $optsBefore
        & $CloseNo $o
    }
    $o = Watch-Run -GreyIds 'ThisPc', 'OtherDrive', 'AllUsers', 'RestorePoints', 'OutFolder', 'StartButton' -StatusId 'Status' -TimeoutMin 30 -During $nav -DuringAfter 0.5 -MemKey history
    $live = Drain-Live
    $statusLive = @($live | Where-Object { $_.Id -eq 'Status' } | ForEach-Object Text)
    $named = Browsers-In (@($o.statuses) + $statusLive)
    Check '5.4' 'Web history run: inputs and Start greyed, the status line names each browser, Cancel enabled' ($o.started -and $o.stillEnabled.Count -eq 0 -and $o.cancelEnabled -and $named.Count -ge 1) "still enabled while running: [$($o.stillEnabled -join ', ')]; Cancel enabled=$($o.cancelEnabled); browsers named in the status line [$($named -join ', ')] ($($o.statuses.Count + $statusLive.Count) status updates)"
    $res = Get-Result
    Check '5b.1' 'Menu Home and back while it runs: still running, folder and options unchanged, finishes there with "Open the report"' ($o.navRunning -and $o.navStatus -and $o.navFolderSame -and $o.navOptsSame -and $o.finished -and (Present 'OpenReport')) "after coming back: running=$($o.navRunning), status line shown=$($o.navStatus), folder unchanged=$($o.navFolderSame), options unchanged=$($o.navOptsSame); finished=$($o.finished); Open the report shown=$(Present 'OpenReport')"
    Report-CloseNo '5c.3' 'a Web history report' $o
    $mem = Get-Memory 'history'
    $rep = $mem.LastRun.ReportPath; $case = $mem.LastRun.CaseFolder
    $btnOk = (Present 'OpenReport') -and (Enabled 'OpenReport') -and (Present 'OpenFolder') -and (Enabled 'OpenFolder')
    $new = @(Get-CaseFolders | Where-Object { $_ -notin $before })
    $countsOk = "$($res.Message)" -match '\d'
    if ($o.finished -and $res.Title -like 'Report ready*' -and $new.Count -eq 1 -and $case -eq $new[0]) {
        $names = Describe-Case $case
        $acl = Test-CaseAcl $case
        Check '5.5' 'When it ends: a sentence with the counts, both buttons; History.html and case.db, no work folder; permissions only SYSTEM, Administrators and you' ($countsOk -and $btnOk -and ($names -contains 'History.html') -and ($names -contains 'case.db') -and ($names -notcontains 'work\') -and $acl.Ok -and (Test-ReportPath $rep)) "box '$($res.Title)': '$($res.Message)'; buttons shown and enabled=$btnOk; contents [$($names -join ', ')]; permissions [$($acl.Labels)]"
        Queue-Render @{ id = '5.R1'; item = 'Web history report: tiles, coverage, charts and visit table present; no passwords, cookies or card numbers'; kind = 'history'; path = $rep; notesId = '5.6' }
        Test-OpenFolder '5.7' 'Web history "Open the case folder" opens that case folder' $case
    }
    else { Check '5.5' 'Web history finishes with a result, buttons and one case folder' $false "finished=$($o.finished); box '$($res.Title)': '$($res.Message)'; new case folders $($new.Count)" }
    Check '6.5' 'Web history: the live region (Status) announces each browser and "Report ready." with the counts' ($script:LiveOk -and $statusLive.Count -ge 2 -and ($statusLive | Where-Object { $_ -like 'Report ready.*' -and $_ -match '\d' })) "LiveRegionChanged events from Status: $($statusLive.Count); browsers [$((Browsers-In $statusLive) -join ', ')]; ends with 'Report ready.' + counts=$([bool]($statusLive | Where-Object { $_ -like 'Report ready.*' })); last event starts '$(if ($statusLive) { ($statusLive[-1] -replace '^(.{0,14}).*$', '$1') })'; status line now starts '$((Text-Of 'Status') -replace '^(.{0,14}).*$', '$1')'"

    # Again, come back through the Home tile, and Cancel.
    Drain-Live | Out-Null
    Invoke-Id 'StartButton'
    $running = Wait-Until { Enabled 'CancelButton' } 15
    Start-Sleep -Milliseconds 500
    Go 'Home' | Out-Null
    Invoke-El (ElName "Explore my PC's history" 2 $CT::Button)
    $samePage = (On-Page 'Web history' 5) -and (Enabled 'CancelButton') -and ((Get-Value 'OutFolder') -eq $folderBefore)
    $stopping = $null
    if (Enabled 'CancelButton') { Invoke-Id 'CancelButton'; $stopping = Wait-Until { $s = Text-Of 'Status'; if ($s -like 'Stopping*') { $s } } 3 }
    $o = Watch-Run -GreyIds @() -StatusId 'Status' -TimeoutMin 10 -Stopping -MemKey history
    $live = Drain-Live
    $res = Get-Result
    $enabledAgain = (Enabled 'ThisPc') -and (Enabled 'OutFolder') -and (Enabled 'StartButton') -and -not (Enabled 'CancelButton')
    Check '5b.2' 'The Home tile during a run opens the same page (run still going, folder kept)' $samePage "Web history shown with the run still going and the same folder=$samePage"
    Check '5.8' 'Web history Cancel: "Stopped", controls enabled again' ($res.Title -eq 'Stopped' -and (Text-Of 'Status') -eq 'Stopped.' -and $enabledAgain) "status after Cancel '$stopping' then '$(Text-Of 'Status')'; box '$($res.Title)': '$($res.Message)'; controls enabled again=$enabledAgain"

    # Another PC's drive.
    Select-Radio 'OtherDrive'
    Invoke-El (ElName 'Refresh the list of drives' 2 $CT::Button)
    Start-Sleep -Seconds 3
    $sel = Select-Drive "$Letter\*"
    $forced = (Get-Toggle 'AllUsers') -eq 'On' -and -not (Enabled 'AllUsers') -and (Get-Toggle 'RestorePoints') -eq 'Off' -and -not (Enabled 'RestorePoints')
    Check '5.9' "Another PC's drive: all accounts ticked and greyed, restore points unticked and greyed" ($sel.Picked -and $forced) "drive selected=$($sel.Picked); other accounts ticked=$(Get-Toggle 'AllUsers') enabled=$(Enabled 'AllUsers'); restore points ticked=$(Get-Toggle 'RestorePoints') enabled=$(Enabled 'RestorePoints')"
    $r = Try-Refused "$Letter\out"
    Check '5.10' "Web history: saving to $Letter\out is refused" ($r.Title -eq 'Pick another folder' -and -not $r.Started -and -not (Test-Path "$Letter\out")) "box '$($r.Title)': '$($r.Message)'; $Letter\out exists=$(Test-Path "$Letter\out")"
    Set-Value 'OutFolder' $Manual
    Invoke-Id 'StartButton'
    $o = Watch-Run -GreyIds @() -StatusId 'Status' -TimeoutMin 15 -MemKey history
    $res = Get-Result
    $mem = Get-Memory 'history'
    if ($o.finished -and $res.Title -like 'Report ready*' -and (Test-ReportPath $mem.LastRun.ReportPath)) {
        Queue-Render @{ id = '5.11'; item = "Old PC's drive: report shows bob's Chrome (8 recovered), Firefox and Internet Explorer"; kind = 'history'; path = $mem.LastRun.ReportPath; oldPc = $true }
        $script:OldPcHistory = $script:Queue[-1]
    }
    else { Check '5.11' "Web history on the old PC's drive runs to the end" $false "finished=$($o.finished); box '$($res.Title)': '$($res.Message)'" }

    # 6. Narrator proxy: every focusable control on Health and Web history has a name.
    foreach ($pg in @(@{ id = '6.4'; page = 'Web history'; status = 'Status' }, @{ id = '6.1'; page = 'Health and security'; status = 'Step' })) {
        Go $pg.page | Out-Null
        $all = @((Get-ContentRoot).FindAll($TS::Descendants, (Cond $AE::IsKeyboardFocusableProperty $true)))
        # Controls a person works with must have a name; focusable containers without one (the page's ScrollViewer, the
        # cards list) are listed as a note: Narrator reads them as "pane" / "list".
        $interactive = 'Button', 'Edit', 'ComboBox', 'RadioButton', 'CheckBox', 'Hyperlink', 'ListItem', 'MenuItem', 'DataItem'
        $unnamed = @($all | Where-Object { -not $_.Current.Name.Trim() } | ForEach-Object { [pscustomobject]@{ Type = ($_.Current.ControlType.ProgrammaticName -replace 'ControlType\.', ''); Id = $_.Current.AutomationId; Cls = $_.Current.ClassName } })
        $bad = @($unnamed | Where-Object { $_.Type -in $interactive } | ForEach-Object { "$($_.Type)#$($_.Id)" })
        $containers = @($unnamed | Where-Object { $_.Type -notin $interactive } | ForEach-Object { "$($_.Type) $($_.Cls)$(if ($_.Id) { '#' + $_.Id })" })
        $drives = (El 'Drives' 1).Current.Name
        Check $pg.id "$($pg.page): every focusable control has a name (Narrator proxy)" ($bad.Count -eq 0 -and $drives -eq "Drive with the other PC's Windows") "focusable elements $($all.Count); controls without a name $($bad.Count) [$($bad -join ', ')]; drive list name '$drives'; note: focusable containers without a name [$($containers -join ', ')]"
    }
    Skip '6.6' 'Narrator speech itself' 'speech output cannot be checked automatically; the names and LiveRegionChanged events Narrator reads are checked instead'

    $closedA = Stop-App
    Log "session A closed cleanly=$closedA"

    # ===== Session B: the pages remember ==============================================================================
    Start-App
    Go 'Web history' | Out-Null
    $line = Wait-Until { Texts | Where-Object { $_ -like 'Last report: *' } | Select-Object -First 1 } 8
    $drivePicked = Wait-Until { (Pat (El 'OtherDrive') $PSelect).Current.IsSelected -and (Get-ComboText (El 'Drives')) -like "$Letter\*" } 8
    $hFolder = Get-Value 'OutFolder'
    $hMem = Get-Memory 'history'
    $hOk = $line -and $drivePicked -and $hFolder -eq $Manual -and (Present 'OpenReport') -and (Present 'OpenFolder') -and (Test-ReportPath $hMem.LastRun.ReportPath)
    Check '5b.3' 'Restart, Web history: folder, source and drive remembered; "Last report: <date> - <counts>" with both buttons' $hOk "line '$line'; other drive $Letter re-selected=$([bool]$drivePicked); folder kept=$($hFolder -eq $Manual); buttons shown=$((Present 'OpenReport') -and (Present 'OpenFolder')); remembered report passes the app's check=$(Test-ReportPath $hMem.LastRun.ReportPath)"
    if ($hOk) { Test-OpenFolder '5b.6' 'Restart, Web history: "Open the case folder" on the Last report line opens it' $hMem.LastRun.CaseFolder }

    Go 'Images viewed' | Out-Null
    $line = Wait-Until { Texts | Where-Object { $_ -like 'Last gallery: *' } | Select-Object -First 1 } 5
    $tMem = Get-Memory 'thumbs'
    $tOk = $line -and (Get-Value 'OutFolder') -eq $Manual -and (Get-Toggle 'WebCaches') -eq 'Off' -and (Present 'OpenReport') -and (Test-ReportPath $tMem.LastRun.ReportPath)
    Check '5b.4' 'Restart, Images viewed: folder and options remembered; "Last gallery" line with Open the report' $tOk "line '$line'; folder kept=$((Get-Value 'OutFolder') -eq $Manual); web caches still unticked=$((Get-Toggle 'WebCaches') -eq 'Off'); Open the report shown=$(Present 'OpenReport') (the gallery page has no case folder button); report path passes the app's check=$(Test-ReportPath $tMem.LastRun.ReportPath)"

    Go 'Health and security' | Out-Null
    $line = Wait-Until { Texts | Where-Object { $_ -like 'Last check: *' } | Select-Object -First 1 } 5
    $drivePicked = Wait-Until { (Pat (El 'OtherDrive') $PSelect).Current.IsSelected -and (Get-ComboText (El 'Drives')) -like "$Letter\*" } 8
    $sMem = Get-Memory 'scan'
    $sOk = $line -and $drivePicked -and (Get-Value 'OutFolder') -eq $Manual -and (Present 'OpenReport') -and (Present 'OpenFolder') -and (Test-ReportPath $sMem.LastRun.ReportPath)
    Check '5b.5' 'Restart, Health: folder, source and drive remembered; "Last check" line with both buttons' $sOk "line '$line'; drive re-selected=$([bool]$drivePicked); folder kept=$((Get-Value 'OutFolder') -eq $Manual); buttons shown=$((Present 'OpenReport') -and (Present 'OpenFolder')); report path passes the app's check=$(Test-ReportPath $sMem.LastRun.ReportPath)"
    if ($sOk) { Test-OpenFolder '5b.7' 'Restart, Health: "Open the case folder" on the Last check line opens it' $sMem.LastRun.CaseFolder }
    Skip '5b.8' 'Restart: "Open the report" on the Last ... lines opens the browser' 'not pressed so the browser is not opened; the remembered paths pass the same check CaseLinks.IsReport makes (5b.3-5b.5)'
    Stop-App | Out-Null

    # Move the last Web history report away: the line must go.
    $moved = $null
    if ($hMem -and (Test-Path -LiteralPath $hMem.LastRun.ReportPath)) {
        $moved = Join-Path (Split-Path $hMem.LastRun.ReportPath -Parent) 'History-moved.html'
        Move-Item -LiteralPath $hMem.LastRun.ReportPath -Destination $moved
        if ($script:OldPcHistory -and $script:OldPcHistory.path -eq $hMem.LastRun.ReportPath) {
            $script:OldPcHistory.path = $moved   # the queued entry: render the moved file in phase 2
            $script:Queue | ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath $QueueFile -Encoding utf8
        }
    }

    # ===== Session C: forgotten report, then closing during a job with Yes ============================================
    Start-App
    Go 'Web history' | Out-Null
    Start-Sleep -Seconds 2
    $line = Texts | Where-Object { $_ -like 'Last report: *' }
    Check '5b.9' 'Report moved away, restart: the "Last report" line and its buttons are gone' ($moved -and -not $line -and -not (Present 'OpenReport')) "report moved=$([bool]$moved); line shown=$([bool]$line); Open the report shown=$(Present 'OpenReport')"

    $yes = @(
        @{ id = '5c.4'; what = 'a health check'; page = 'Health and security'; prep = { if ($script:AppElevated) { Select-Radio 'ThisPc' } else { Select-Radio 'OtherDrive'; Select-Drive "$Letter\*" | Out-Null }; Set-Value 'OutFolder' $Manual }; wait = { Start-Sleep -Seconds 4 } }
        @{ id = '5c.5'; what = 'a Web history report'; page = 'Web history'; prep = { Select-Radio 'ThisPc'; if (Enabled 'AllUsers') { Set-Toggle 'AllUsers' $false | Out-Null; Set-Toggle 'RestorePoints' $true | Out-Null }; Set-Value 'OutFolder' $Manual }
            wait = { Wait-Until { (Text-Of 'Status') -like '*shadow copy*' -or -not (Enabled 'CancelButton') } 60 | Out-Null } }
        @{ id = '5c.6'; what = 'a gallery'; page = 'Images viewed'; prep = { Set-Value 'OutFolder' $Manual }; wait = { Start-Sleep -Seconds 4 } }
    )
    $first = $true
    foreach ($y in $yes) {
        if (-not $first) { Start-App }
        $first = $false
        Go $y.page | Out-Null
        & $y.prep
        $before = Get-CaseFolders
        Invoke-Id 'StartButton'
        $started = Wait-Until { Enabled 'CancelButton' } 15
        & $y.wait
        $runningAtClose = Enabled 'CancelButton'
        $statusAtClose = if ($y.page -eq 'Web history') { [bool]((Text-Of 'Status') -like '*shadow copy*') } else { $null }
        Post-Close
        $d = Find-Dialog 'Stop and close?' 10
        if ($d) { Click-DialogButton $d '6' 'Yes' }
        $p = $script:App.Proc
        $exited = $p.WaitForExit(90000)
        if (-not $exited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        $script:App = $null
        Start-Sleep -Seconds 2
        $new = @(Get-CaseFolders | Where-Object { $_ -notin $before })
        $half = @($new | Where-Object { -not (Get-ChildItem -LiteralPath $_ -Filter '*.html' -ErrorAction SilentlyContinue) })
        $work = Get-WorkFolders
        $left = @(Get-AppProcesses).Count
        $extra = if ($null -ne $statusAtClose) { "; closed during the shadow copy step=$statusAtClose" } else { '' }
        $ev = "running when closed=$runningAtClose$extra; asked=$([bool]$d); closed within 90 s=$exited; new case folders $($new.Count) (without a report: $($half.Count)); work folders $($work.Count); PCPorter processes left $left"
        if (-not $runningAtClose) { Skip $y.id "Close during $($y.what), answer Yes" "the run ended before the window could be closed during it ($ev)" }
        else { Check $y.id "Close during $($y.what), answer Yes: closes, nothing half-written, no work folder, no PCPorter process" ($started -and $d -and $exited -and $half.Count -eq 0 -and $work.Count -eq 0 -and $left -eq 0) $ev }
    }
    $after = Get-ShadowIds
    if ($null -ne $state.shadowsBefore) {
        $newShadows = @($after | Where-Object { $_ -notin $state.shadowsBefore })
        Check '5c.7' 'vssadmin list shadows: no shadow copy left by PCPorter' ($newShadows.Count -eq 0) "shadow copies before $($state.shadowsBefore.Count), after $(@($after).Count), new $($newShadows.Count)"
    }
    else { Skip '5c.7' 'No shadow copy left' 'vssadmin needs an elevated script' }
}
catch {
    Add-Result 'run' 'The script ran to the end' 'FAIL' "stopped with: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
}
finally {
    if ($script:App) { Stop-App | Out-Null }
    foreach ($p in @(Get-AppProcesses)) { Log "ending a PCPorter process left over by this run ($($p.Id))"; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    if ($state.subst) { & subst.exe $Letter /D; Check '7.1' "Clean-up: subst $Letter removed" (-not (Test-Path "$Letter\")) "$Letter exists=$(Test-Path "$Letter\")" }
    if ($state.settingsMoved) {
        Move-Item -LiteralPath $SettingsBackup -Destination $SettingsFile -Force
        Check '7.2' 'Clean-up: settings.json restored' (Test-Path -LiteralPath $SettingsFile) 'the backed-up file was put back'
    }
    elseif ($state.settingsHandled -and -not $state.settingsExisted) {
        Remove-Item -LiteralPath $SettingsFile -ErrorAction SilentlyContinue   # there was none before: remove the one this run made
        Check '7.2' 'Clean-up: settings.json back to how it was (there was none)' (-not (Test-Path -LiteralPath $SettingsFile)) 'the file written by this run was removed'
    }
    Log 'Phase 1 done'
}

if (-not $Child) { Invoke-Phase2; Show-Results }
