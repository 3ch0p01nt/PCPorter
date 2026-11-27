# Gap-closure plan (2026-11-27)

Source: six read-only flow reviews of the whole app (shell, health scan, web history, gallery, shared safety rules,
docs vs behaviour). About 70 findings, about 45 after merging duplicates. Every item is first confirmed in the code
(reviewers can be wrong; one claim, "the repo is not in git", already was), then fixed test-first where testable.

## Rules for every fix
- Confirm, failing test, fix, test passes, commit. Rejected findings are listed with the reason.
- One owner per file set (below), so groups 2-6 can run in parallel on separate branches and merge cleanly.
- No group edits `tasks/todo.md` (updated once at the end).
- Done = `scripts/regress.ps1` fast ALL PASSED on the branch; after the merge: `-Level full`, then `-Level release`
  (elevated smoke, needs `install-smoke-task.ps1` if smoke.ps1 changed), then the manual checklist, then the zip.

## Group 1 - shared safety rules (in progress; Core + Collectors/Sources)
| # | Gap | Fix | Proof |
|---|---|---|---|
| 1.1 | Mapped drives, `//server/share` pass the network check | Check after GetFullPath; reject `DriveType.Network` and UNC real locations | tests: mapped/UNC/forward-slash refused, `\\?\D:\` allowed |
| 1.2 | Cloud check is name-based: subst into OneDrive, SharePoint/Teams libraries, Google Drive, moved OneDrive pass | Resolve subst + real path; sync roots from SyncRootManager and OneDrive account keys; refuse cloud placeholders | tests with fake registry/sync roots; subst test |
| 1.3 | Folders created through a junction before the link check | Validate the existing ancestor chain first, then create | junction test: nothing created |
| 1.4 | Empty or relative save folder crashes / resolves oddly | Clear "pick a full folder path" refusal | tests |
| 1.5 | No shared "not on the drive being checked" check (CLI scan writes to the old drive) | New Core check by volume identity (catches subst/mount aliases) | tests; used by groups 3 and 4 |
| 1.6 | Bad-input and program-failure errors look the same | `SourceRejectedException` from OfflineSource | used by group 2 for exit 3 / "Can't start" |
| 1.7 | Read confinement switches off for shadow-copy device paths | NT-path resolution; unresolvable = outside | junction-inside-root test |
| 1.8 | A link on the old drive is followed before the location check (NTLM leak to a share) | Refuse reparse points before opening | symlink test |
| 1.9 | Elevated run can fall back to a user-writable log/state folder; journal file ACL; cleanup could delete restore points PCPorter did not make | Fail closed when elevated; re-lock journal file; only delete copies PCPorter created | tests on ACL/journal logic |
| 1.10 | Shadow copy untracked if Create half-succeeds; GUI and CLI runs delete each other's copies | "pending" journal line before Create; owner process id per entry | journal tests |
| 1.11 | Masking misses `/rp`, `-pSecret`, URL-encoded secrets | Redactor patterns + decode | Redactor tests |

## Group 2 - app shell and command line (`src/PCPorter.App/**`, `src/PCPorter.Core/Cli/CliApp.cs`)
- **Elevated "Open report" can run anything** (remembered path from a user-writable settings file; elevated
  ShellExecute uses user-writable handlers): open only `.html` files inside a PCPorter case folder, and open them
  un-elevated through `%windir%\explorer.exe`. Same for "Open case folder". About's "Open log folder" uses the full
  explorer path.
- **Closing the window mid-job skips cleanup:** `Closing` asks "Stop and close?", cancels, waits for the job, then
  closes; also on log-off (`SessionEnding`). At start-up (elevated) remove stale PCPorter shadow copies.
- **Stub commands lie:** `backup` / `report` print "not built yet" and exit 2 (or are hidden).
- **Errors mapped to the wrong outcome:** only `CaseLocationRejectedException` / `SourceRejectedException` are
  "Can't start" / exit 3; everything else is logged, redacted, remembered as Failed, exit 2 - in all three pages and
  all three commands. Images viewed gets the same catch-all and redaction as the other pages.
- **`thumbs` CLI:** Ctrl+C handler and token (exit 6 + cleanup), `--all-users` refused or noted when not elevated,
  JSON wrapped as `{summary, exitCode}` like scan/history; one field name (`caseFolder`) everywhere.
- **Second Ctrl+C** ends the CLI (exit 6) when a step hangs.
- **Misleading or dead text:** title from `IsElevated`; remove "see Help" hint (no Help page); Home tile drops
  "readiness score"; Move tile marked "Coming soon"; non-admin drive picker says "start as administrator to look
  inside other drives" instead of "no drive found"; gallery page says it works on this PC only.
- **Folder warnings** (exFAT/FAT32: anyone with the drive can read the case) shown in the result bar and CLI output.
- **Polish:** crash handler (no dialog from the finalizer thread; "PCPorter has to close" for fatal crashes);
  `Local\` single-instance mutex that brings the open window forward; drive suggestion off the UI thread; stderr
  attached when only stdout is redirected; fix the `start /wait` comment.

## Group 3 - health scan (`src/PCPorter.Collectors/ScanRunner*` + collectors, `src/PCPorter.Reports/ScanJob.cs`,
`ScanSetup.cs`, `HealthReport.cs`, `Assessment.cs`)
- Time-limit hits reported as "cancelled": record TimedOut + warning when the user did not cancel (exit 1, not 6).
- Stopped scan says "Looks good": cancelled counts as incomplete; neutral heading ("Incomplete check") and a
  "stopped early" line; lists from stopped parts marked partial.
- Offline scan "All parts were checked": offline wording and a deliberate exit code (documented).
- Save on the scanned drive refused inside ScanJob (group 1.5), so GUI and CLI agree.
- Failure after the case folder exists: delete it if nothing useful was written, otherwise return its path so the
  page and CLI JSON name it.

## Group 4 - web history (`src/PCPorter.Forensics/BrowserHistory/**`, `HistoryJob.cs`, `HistoryReport.cs`,
`HistorySetup.cs`, `Templates/History.html`, `report-kit.js`)
- **Copy taken while the browser writes can be inconsistent -> live visits shown as "deleted":** `quick_check` the
  copy and re-copy (up to 2 more tries, checking WAL salts) before falling back to carving; the damaged-file label
  says "from a damaged copy", not "deleted".
- **Over-claiming "deleted":** skip WAL frames after the last commit (or label "unsaved change"); wording "recovered
  from leftover data (may be deleted or an older copy)"; notes split by where rows came from.
- **Restore points:** only dedupe-and-claim "no longer listed" for profiles read live; search profiles found inside
  each restore point (deleted profiles); dedupe key includes the profile and uses the raw URL.
- **Work folder not deletable:** retry, then a warning naming it; never keep Web Data / form-history bytes in memory.
- **Time zone:** show the zone in the header and the "When" column; restore-point labels in the same zone.
- **Report:** Origin filter on the bare origin; CSV escape adds `\r` and leading whitespace; search text not written
  to the page address (opt-in).
- **Masking:** download "saved as" paths redacted (incl. Firefox file: URIs).
- **Counts:** folder warnings included in the report or kept separate from "parts not read".
- **IE failures** contained per profile like Chrome/Firefox.
- Save on the scanned drive: use group 1.5 inside HistoryJob.

## Group 5 - gallery (`src/PCPorter.Forensics/Thumbcache|Images|Gallery|BrowserCache|SearchIndex/**`,
`ThumbnailJob.cs`, `GalleryJobFactory.cs`, `DateCorroborator.cs`, `GalleryReport.cs`, `Templates/Thumbnails.html`)
- **Cancel/failure leaves extracted private pictures in an unnamed folder:** delete the whole case folder unless the
  report was written.
- **Read-only promise and OneDrive:** skip cloud-only placeholders (no download) with a note.
- **"Original deleted" over-claims:** missing parent folder = "folder gone (moved, renamed or other drive)"; network
  paths = Unreachable without probing; compare volume serial where possible.
- **Restore points inflate counts:** merge restore-point copies into the live item (extra image + date evidence);
  headline "deleted" counts thumbnails only.
- **Inverted "High" date window:** only tighten when consistent.
- **Image store collisions abort a source:** one shared store; existing same-hash file = already stored.
- **All-users:** warn for each profile skipped and why; report header lists the accounts included.
- **Junction in the user's own Explorer folder pulls another account's thumbnails:** read through `SourceFiles`
  with the real path checked inside the profile.
- **Windows 10 shadow copy:** keep results when only the cleanup fails; cleanup failure is its own note; cancel stays
  a cancel. Note text says "the search-index option", not `--full-index`.
- **Masking:** cached image URLs and all warnings redacted.
- **Report:** keyboard selection doesn't open the viewer, focus kept after selecting, explicit empty-gallery
  message, non-displayable formats shown as "no preview".

## Group 6 - docs and release (`scripts/**`, `packaging/**`, `README.md`, `docs/testing/**`, `Directory.Build.props`)
- **Untested build can be zipped:** `package.ps1` defaults to no publish and refuses unless the dist folder holds
  exactly the published files and `smoke-last.json` is `ok`, newer than the EXE, with a matching EXE SHA-256.
- **Every build says 0.1.0:** stamp `InformationalVersion` (date + commit) at publish; shown in About, reports,
  JSON; baseline's version-change flag then works.
- **regress.ps1 checks that can pass vacuously:** fail on the fixture export's exit code and recreate the fixture;
  gallery render check looks for a marker the page script writes; an unreadable installed smoke.ps1 is a failure.
- **HOW-TO-RUN:** "If Windows blocks it" (Unblock the zip, SmartScreen, Smart App Control has no "Run anyway",
  "Unknown publisher" UAC); CLI examples that wait and show the exit code (`| Out-String`, `$LASTEXITCODE`); `cd`
  into the folder before `baseline.ps1`; old-drive write-protection advice only if it exists.
- **Manual checklist:** drop items that cannot happen with `requireAdministrator`; add Close-during-a-job,
  Open-report-from-memory, cancel cleanup.
- **baseline.ps1:** UTF-8 console decoding in 5.1; fail if the case folder is missing.
- **smoke.ps1:** fix the DryRun comment; add checks for the new behaviours (saving on the scanned drive refused for
  scan and history, cancelled gallery leaves nothing).

## Order and verification
1. Group 1 (running). Its new APIs: the save-folder volume check and `SourceRejectedException`.
2. Groups 2-6 in parallel, each on its own branch, briefed with group 1's API.
3. Merge into `main`; fast + full levels; reinstall the smoke task (UAC) if smoke.ps1 changed; release level;
   manual checklist (GUI items need a person at the screen); package with the new gate; push only when asked.

## Not in this plan
Feature gaps from the research (backup and restore, passwords, timeline, wipe checklist, and the rest:
`docs/research/2026-11-27-capability-research.md`) are separate work; backup and restore already has its own plan
on branch `claude/silly-visvesvaraya-bbf6d8`.
