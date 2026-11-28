# Improvement plan from ten reviews (2026-11-27)

Ten read-only reviews: app usability, report readability, wording and trust, accessibility, first-run journey, code
structure, test suite, speed and size, compatibility across PCs, threat model of untrusted input. Items marked
"checked" were confirmed in the code; the rest are reviewer claims to confirm before fixing (as in the gap-closure plan).

## Done already
- CRITICAL (checked, fixed in 3d51988): a crafted `-journal` from an infected old drive could make SQLite delete any
  file with admin rights (super-journal rollback). The journal is no longer copied; a test proves it is never read.

## P0 - correctness, safety, things that break on real PCs (small to medium)
| # | Gap | Fix | Source |
|---|---|---|---|
| 1 | Masking regexes can backtrack for hours on a crafted 1 MB title/URL; time limits are only cancellation tokens, so the scan hangs | Cap input (8-16 KB) before redaction; `matchTimeout` on every regex, mask the whole value on timeout | threat model |
| 2 | Untrusted browser/winget/index databases open with a trusted schema and no limits (views, virtual tables, zeroblob) | `trusted_schema=OFF`, defensive mode, `cell_size_check`, length limit, tables must be real tables, read guard on all readers, progress-handler budget | threat model |
| 3 | Attacker images decoded by any installed WIC codec inside the elevated process | Hash only JPEG/PNG/BMP/GIF chosen by magic bytes with the built-in codecs; later: decode in a non-elevated worker | threat model |
| 4 | LNK/Jump List libraries read whole files outside `SourceFiles`; hive transaction logs uncapped; `.svg` saved into the report folder; gallery CSV escaper weaker than the kit; CR/LF in logged messages | Read bytes through `SourceFiles` with caps; save SVG as `.bin`; use `kit.csvEscape`; strip control characters in the log formatter | threat model |
| 5 | Default save folder is C: of the old PC: USB hard drives/SSDs report as Fixed, only sticks count (checked) | Offer USB-bus fixed drives first, show label + free space, warn when saving on the system drive | first run |
| 6 | Results are locked to the old PC's user (ACL), so they won't open on the new PC | "Open results from another PC" (grants read after confirming, as admin); guides kept outside the locked folder | first run |
| 7 | exFAT/FAT32 backup sticks: setting the private ACL may fail before the warning; `work` copies can exceed 4 GB | Skip ACLs on non-NTFS (keep the warning); put `work` on the NTFS system drive; refuse FAT32 for big copies; test on a real stick | compatibility |
| 8 | Running from inside the zip or with a quarantined DLL fails with a technical error | Startup check for the 6 DLLs and a `%TEMP%\Temp*` zip path; plain message box | first run, compatibility |
| 9 | Reports promise things that don't exist ("installed fresh, never copied", "scan your new PC to compare", Home "without viruses", "PCPorter can help you move"); TPM 1.2 text is wrong; "This is a setting, not broken hardware" pasted under firewall/UAC; Smart App Control counted "Unusual" while saying it is normal | Rewrite those strings (wording review has exact text); regenerate goldens | wording, reports |
| 10 | Elevating with a different admin account at UAC scans the admin's profile, not the person using the PC | Default to the signed-in session user (explorer token / WTS); allow picking a profile | compatibility |
| 11 | The hibernated/dirty-drive safety check exists (`VolumeSafety`) but nothing calls it; the app has a second, weaker drive finder | Use `OfflineVolumeFinder` + `VolumeSafety` behind one shared drive picker; delete `WindowsDrives.Find` | code structure |
| 12 | Window taller than a 1366x768 or 150%-scaled laptop screen; Home has no scrolling | Clamp to the work area, lower MinHeight, wrap/scroll Home and source rows | usability, compatibility, accessibility |

## P1 - clarity and polish the owner will notice
**Reports (Health first; mostly `HealthReport.cs`/`Assessment.cs`):**
- Banner: "N to fix now / N to check / N unusual (no action)"; apps count moves out of the verdict; "not checked" instead of 0.
- Split "Unusual" into "Check this" (has an action: Remote Desktop, admin account, low disk, worn battery) and "FYI".
- Every row: what we found / what to do (visible) / "Why is this here?" (reason); technical details nested.
- Startup advice per reason (hidden task, user-folder program), with safe "how to stop it" steps; never "remove files".
- Show all actionable to-dos (or link the overflow); merge duplicate drive items; consistent urgency.
- Fold OK rows; one-line "Nothing to do"; print CSS without page per section and without the appendix.
- History/Thumbnails: one plain sentence on top, advanced filters folded, "Where found" not "Origin"; printing and narrow
  screens for the virtual table; readable chart text.
- One vocabulary everywhere: "check", "results folder"; US spelling.

**App (`src/PCPorter.App/Views`):**
- "Start here": which PC is this (old / new / old PC's drive plugged in) and the order of checks; a done mark per tile.
- One save folder shared by all pages; determinate progress with rough time; "Next step" after each run.
- "My old PC won't start" visible on Home; the three pages with the same layout, words and buttons (Images viewed
  gains "Open the results folder"); early folder validation next to the field; Enter starts, Escape stops.
- Accessibility: keep keyboard focus when a job starts/ends and announce results; Images viewed announcements.

**Reports accessibility:** virtual table as one ARIA grid with selection announced; charts with "Show as a table";
gallery roving tabindex; forced-colors (High Contrast) styles; 3:1 control borders; reduced motion; focus after nav.

**Compatibility:** user shell folders from the registry (OneDrive folder backup, localized names, Screenshots GUID);
system drive/search-index location from Windows instead of `C:`; Defender status via Security Center when another
antivirus is in charge; crash window anchored to the newest event for old drives; ARM64 build; test Windows 10 ESE
string decompression on a real Windows 10 PC.

## P2 - engineering (before backup/restore lands on top)
- **Refactors, small steps first:** one version/elevation source; folder warnings as one shape; dead code (ReadinessScorer,
  ReadOnlyAttachGuide, unused options) removed or wired; CLI scaffolding; `CaseRun` (one case-folder lifecycle for all
  jobs, incl. reopen for backup); request/setup per job; a page helper for running jobs; one report-template writer;
  narrower public API with InternalsVisibleTo.
- **Tests:** mutation fuzzing of every old-drive parser in a child process with time and memory limits (hives incl. a
  looping key, LNK, Jump Lists, SNSS, LZ4, ESE, thumbcache index, winget index); security tests that can't pass by
  skipping (junction helpers); property checks in existing fuzz tests; negative tests for package.ps1 and baseline.ps1;
  run the report JavaScript in tests; golden hygiene (stable catalog in the fixture, eol, orphan check); shared fake
  drive fixture (fast level about 77 s -> 35 s); bound the two slow live tests (Forensics 4 min -> about 30 s).
- **Speed and size:** composite ReadyToRun off (EXE about 232 -> 150-170 MB); gallery extra sources in parallel with the
  shell walk and several walk threads (save 1-2 min, more matches); signature checks in parallel (cold scan 26 -> about
  7 s with concurrent collectors); memory-mapped carving instead of 512 MB arrays; one open per cache file; parallel
  picture hashing; later drop the Windows SDK projection (about 25+ MB).
- **Isolation (cross-cutting):** run native/third-party parsers (ESE, hives, images, LNK) in a non-elevated worker
  process the app can kill on a real timeout.

## Distribution (decision needed)
Sign the EXE (Smart App Control on new Windows 11 PCs blocks unsigned apps with no override; restore must run there):
paid Azure Artifact Signing (~$120/yr), or a public repo + SignPath Foundation (free). Then: public, current download
with the version in the zip name; plain release notes; a one-page START-HERE guide with screenshots (developer notes
move to README; baseline.ps1 leaves the owner zip); a "make a help file" button that shares counts and redacted logs only;
an About "Check for updates" button.

## Suggested order
1. P0 1-4 (untrusted input) and P0 5-9 (real-PC breakers and false promises): one fix branch each, test-first.
2. P2 small refactors that backup/restore needs (version, folder warnings, CaseRun, drive picker) - then start backup.
3. P1 report and app clarity in parallel with backup milestone 1.
4. Tests and speed items alongside; signing once the route is decided.
