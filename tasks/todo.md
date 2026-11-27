# PCPorter - Task Tracker

Design: [docs/plans/2026-11-26-pcporter-design.md](../docs/plans/2026-11-26-pcporter-design.md)

## Phase 1 - Foundation
- [x] Design approved and saved
- [x] Install .NET 10 SDK (10.0.404)
- [x] git init + .gitignore (branch `phase1-foundation`)
- [x] Detailed Phase 1 implementation plan (docs/plans)
- [x] Solution skeleton: App, Core, Security, 2 test projects (Collectors/Forensics/Reports added in their phases)
- [x] WPF-UI shell: home screen (3 tiles), navigation, Mica, system theme, About
- [x] Logging (Serilog), crash handler, settings JSON (atomic save), single instance
- [x] CLI (System.CommandLine 3.0) with exit codes
- [x] case.db schema (SQLite + FTS5 + tags)
- [x] Vault (Argon2id + chunked AES-GCM) - 11 tests incl. tamper/truncation
- [x] VSS snapshot wrapper (code + unit test)
- [ ] VSS elevated integration test (needs admin prompt approval)
- [ ] Manual smoke: launch GUI, check tiles/About/log folder/second-instance message
- [x] Single-file publish (224 MB) - Defender scan clean

## Thumbnail report (pulled forward from Phase 3) - plan: docs/plans/2026-11-26-thumbnail-report.md
- [x] Thumbcache parser (Vista-Win11), verified: 827 real images all decode
- [x] Collector + case.db rows + images in case folder
- [x] Thumbnails.html gallery (offline, filters, detail view, notes banner)
- [x] `pcporter thumbs --out <folder>` CLI
- [x] Original paths from the Win11 search index (255 of 587 matched; 7 s)
- [x] Folder thumbnails no longer marked "deleted" (was 137 deleted, real: 16)
- [x] VSS via built-in WMI Win32_ShadowCopy (AlphaVSS 2.x ships an ARM64-only Common DLL)
- [x] Windows 10 search index (Windows.edb, ESE) path lookup (synthetic ESE tests; live Win10 uses a temporary shadow copy)
- [x] "Explore my PC's history" tile + "Images viewed" page
- [x] Report opened directly from disk (file://) in headless Edge: images load
- [~] Recovered entries: parser fixed to look behind the free-space record; this PC's free space is all zeros (0 expected)

## Thumbnail report v2 (docs/plans/2026-11-27-thumbnail-report-v2.md) - status
- [x] P0 1-10: private unique case folders, current-user default, Exists/Deleted/Unreachable/Unknown, parser fixes
      (versions, free-space record, strict scan checks), empty entries kept, dedupe, CLI errors, VSS cleanup,
      OneDrive-by-name guard, report JS bugs
- [~] P0 4 header CRC: table matches thumbcache.dll but the input range could not be reproduced on real entries -> dropped
- [x] P1 11 index copy incl. WAL (--full-index), fallback path columns, specific errors
- [x] P1 12 shell cache-id matching (verified: shell ids == cache ids; 140-153 matched in budget)
- [x] P1 13 thumbnails from existing restore points (admin) + window tightening
- [x] P1 14 Windows 10 Windows.edb resolver (agent; compressed Xpress columns not decoded - noted)
- [x] P1 15 date windows (cache file times, original modified time, restore points, opened-file corroboration)
- [x] P1 16 thumbcache_idx stale-entry notes (layout verified: 1,032 of 1,040 ids listed)
- [x] P2 17-21 sources: Chromium blockfile/simple cache (2,026 Edge images here), Firefox cache2 (synthetic only),
      screenshots (101), recent files + Jump Lists (88), Recall/Photos notes
- [x] P2 22-26 streaming parser, content-hash image store, folder-grouped checks, index PRAGMAs, streamed JSON
- [x] P2 27-36 gallery: virtualized grid, grouping (folder/website/status/month/source), keyboard nav, URL state,
      tags, CSV, zoom/pan, sizes side by side, copy path, similar-picture groups, month strip, contact-sheet print
- [ ] Not done: browser page-title join (History), ZIP export (browsers block reading local files), parallel image writes

## Phase 2 - Read-only scanners
- [x] App inventory (Uninstall keys, Appx, winget export, games, choco/scoop, portable)
- [x] AV detection (SecurityCenter2 + fallbacks)
- [x] PC health / readiness collector (readiness score waits for a new-PC scan to compare)
- [x] Persistence audit (Authenticode-checked, severity rules)
- [x] Security settings check (21 checks, live + offline)
- [x] Dead-PC rescue mode (offline Windows volume source, BitLocker/locked drives listed)
- [x] Scan runner/job/case DB hardening from the 10-agent review (timeouts, cancel, transactions, redaction)
- [x] Security review fixes: redactor coverage, admin-only %ProgramData% folders, clean helper env, WQL input checks, no self-extract
- [x] HealthReport.html (verdict, top 3, security, moving, hardware, appendix; offline, redacted, print/dark)
- [x] Health page + CLI fixes (Stopped state, Narrator, Ctrl+C exit 6, --fail-on exit 5, --quiet)
- [x] Admin verification run of the published EXE on this PC: all 5 checks Ok, no secrets in output; fixed 37 false "worth a look" leftover tasks
- [x] winget matching in elevated and offline runs: reads winget's own catalog (index.db) as data, nothing started; this PC 0 -> 45 of 92 non-Store apps
- [x] Packaged for the other machine: C:\PCPorter-dist\PCPorter.zip (folder + HOW-TO-RUN.txt). Dev PC is a work VM: not a tuning target
- [x] Bug pass on the packaged EXE (admin run): redirected CLI output, report wording consistency, duplicate app versions, Python shortcuts as portable apps, .sdb entries; confirmed by a second run
- [ ] Old vs new comparison section (needs scans of both PCs)

## Regression testing (docs/plans/2026-11-26-regression-testing.md)
- [x] Tag live-data tests Category=Live; scripts/regress.ps1 -Level fast|full|release (fast: ~2 min, was ~5)
- [x] Tier 2: golden comparer, 6 synthetic PCs, report wording invariants (+ one Assessment decides every label and count)
- [x] Tier 3: fixture old-PC drive with planted cases, offline end-to-end, read-only proof, denylist spy
  (lives in tests/PCPorter.Reports.Tests/Regression/OldPcScanTests.cs + TestKit/OldPcDrive.cs, not a new project).
  Found and fixed: offline scans called unsigned programs "not checked" (now unsigned once the old PC's catalogs
  were read); side-by-side app versions shared one item key, so case.db silently dropped one.
  Not covered: upgrade-code matching (UpgradeCode is never read from the registry; see backlog), thumbcache.
- [x] Research batch 1 (startup scan): exact Microsoft signer names + WHQL drivers named; signed-adware watchlist;
  Microsoft programs launching user-folder files or URLs no longer hidden; ProgramData treated like AppData;
  -nop / -w hidden alone = Medium; damaged offline catalogs fall back to "not checked"; extensions from outside a
  store = Medium. New locations: Command Processor AutoRun, Winlogon Taskman/AppSetup, Windows\Load/Run,
  UserInitMprLogonScript, moved Startup folders, exefile/ms-settings/mscfile open-command hijacks, Chrome/Edge
  ExtensionSettings + external extensions, Firefox extension policy. All planted in the tier-3 drive.
  Left for later: offline WMI repository, Explorer shell extensions, Store-app startup tasks, print processors,
  time providers, revocation checks (would need the network).
- [x] Research batch 2 (winget matching): winget's own normalization ported (all 1,137 of winget's test cases match);
  MSI upgrade codes read from packed GUIDs (260 of 272 MSI apps on the dev PC); per-user tracking catalogs
  (InstalledByWinget, winget + msstore ids); architecture-tagged names and version ranges break ties; Store apps by
  package family name; catalog schema 1.x and 2.x both read. Not done: the experimental delta index (watch
  winget-cli doc/specs/Delta Index.md).
- [x] Research batch 3 (test suite): read-only proof compares folder times (catches create-then-delete); spy checks every
  mapped path; report rules: tag allowlist + event handlers, no "no action" to-dos, missing sections flagged, 8 more
  self-check cases; de-DE/fr-FR rule runs; fixed clock for tier 3 (ScanJobOptions.Now); fixture fails loudly without
  a catalog; regress.ps1 needs PowerShell 7, refuses a leftover PCPORTER_ACCEPT (use -Accept), fails if too few
  tests ran. Not done: Stryker.NET (needs a tool download; run once when wanted), FsCheck property tests.
- [x] Backlog from tier 3: read MSI upgrade codes (SOFTWARE\Classes\Installer\UpgradeCodes, packed GUIDs) so winget's
  upgradecodes2 table is used.
- [x] Tier 4 built: scripts/regress/smoke.ps1 (elevated checks), scripts/regress/install-smoke-task.ps1 (one-time,
  admin: C:\PCPorterCI + on-demand "PCPorterSmoke" task, -Uninstall removes both), regress.ps1 -Level release
  (publish, fake drive, task, Edge render check). Dry run (not elevated) passes the package, manifest, Defender,
  read-only and leak checks. Found and fixed: library .pdb files were being published; --fail-on never gave exit 5
  offline (offline is always "partial").
- [x] Tier 4 first real run (2026-11-27): task installed; release level ALL PASSED (26 checks, 547 s). The real run
  found: monitors "access denied" from a task made scans partial; forced-extension posture check missed
  ExtensionSettings/Firefox and double-counted; render check needed Start-Process for Edge. All fixed.
  To-do: re-run install-smoke-task.ps1 as admin once so regress.ps1 can verify the installed smoke.ps1 (read access).
- [x] Tier 5 built: scripts/regress/baseline.ps1 (Windows PowerShell 5.1 and 7). Scans, writes a counts-only summary to
  C:\PCPorterCases\baselines (refuses to save one holding the PC/user name, a path or a URL), compares with the
  accepted baseline: new High per rule, posture changes, counts over 10%, parts no longer Ok, 2x slower, exit code.
  -Accept, -Case <folder>. Dry run here on saved smoke cases: live vs live "No changes", fixture vs live flags the
  planted cases. Ships in the zip via the new scripts/package.ps1 (+ packaging/HOW-TO-RUN.txt, now in the repo).
  Fixed on the way: an empty count key made the file unreadable in PowerShell 5.1.
  To do on the target PC: run it once, -Accept, then after each new build.
- [x] Tier 6 written: docs/testing/manual-checklist.md (Home, Health live/offline/cancel/refusals, gallery, Narrator,
  second instance; fixture drive via subst). Not yet walked through.

## Phase 3 - Reports
- [ ] Shared HTML report template (ECharts, uPlot, Tabulator, fflate)
- [x] History.html (plan: docs/plans/2026-11-27-web-history.md, Milestones 1-5). Built: Chromium (Chrome, Edge,
  Brave, Opera, Vivaldi), Firefox and IE / legacy Edge (WebCacheV01.dat) visits, searches, downloads (still on disk?),
  bookmarks, open and closed tabs, form entries (password/card fields dropped, Web Data guarded to the autofill table);
  deleted visits carved from free space and the WAL; older visits from existing restore points (admin); CLI `history`
  and the WPF "Web history" page (this PC or another PC's drive; Home's history tile opens it, linked to Images
  viewed). Tier 3: bob's planted Chrome/Firefox/IE history on the fake drive, golden history-oldpc.txt, canary and
  bait-file spy, drive unchanged. Tier 4: smoke.ps1 runs `history` live and offline; History.html is in the Edge
  render check. Verified non-elevated: offline on the fake drive (35 visits, 8 recovered) and live on this PC.
  Tier 4 release run (2026-11-27, elevated): ALL PASSED, 34 checks, 630 s. Live elevated history read this PC's real
  WebCacheV01.dat through the temporary shadow copy (19 visits, no warnings); restore-point search ran and found none
  on this PC. Unverified: restore points on a PC that has some, a real Firefox profile, the manual checklist's Web
  history section (GUI not clicked through yet).
- [x] Work is kept (2026-11-27): pages are cached for the session (NavigationCacheMode="Required"; WPF-UI 4.3.0
  caches by page type and Nav.Navigate(typeof) uses the same menu items, checked in the decompiled source), so a
  running job keeps updating its page after clicking elsewhere. Web history, Images viewed and Health remember their
  folder, options, drive and last result in %AppData%\PCPorter\settings.json (PageMemory; "Last report: ..." shown
  only while the report file exists). Verified by UI Automation non-elevated; checklist section 5b.
- [ ] Timeline.html (+ MFT/USN, USB, network, screen time, compromise verdict)
- [ ] Thumbnails.html (+ carving, dHash, EXIF, map)
- [ ] Passwords.html (+ accounts inventory)
- [ ] Security Audit, Readiness

## Phase 4 - Workbench
## Phase 5 - Backup engine
## Phase 6 - Restore
## Phase 7 - Release
## Phase 8/9 - Tier 2 / Tier 3

## Review
**Phase 1 (2026-11-26):** 30 automated tests pass (Core 19, Security 11) plus 1 admin-only test skipped in normal runs, 0 build warnings.
Deviations from the plan: `Artifact.Artifact` renamed `ArtifactName` (C# forbids a member named like its type);
AlphaVSS fork namespace is `ArxOne.Win32.Vss`; WPF projects need explicit `using System.IO;`; `DllImport` used
instead of `LibraryImport` (avoids unsafe code). Open risk: AlphaVSS loads its native DLL "from the same folder as
AlphaVSS.Common", which may fail inside the single-file EXE - verify when the first VSS feature runs from the
published EXE. Possible later tweak: drop ReadyToRun to shrink the EXE.
