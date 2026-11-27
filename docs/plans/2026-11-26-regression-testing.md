# Regression testing plan

**Goal:** catch, before a build reaches the target PC, the kinds of bugs that today's real admin run found by hand:
- false alarms (37 leftover tasks rated "worth a look")
- self-contradicting report wording
- duplicate app rows
- lost command-line output
- shortcuts counted as apps

It must also keep the hard guarantees true:
- read-only scans
- no secrets in output
- no writes to a scanned drive

**Constraints:**
- No CI (removed on request), so everything runs from one local script.
- The dev PC is a work virtual desktop, not the target. Real-data checks happen on the target PC, and their output never goes into the repo or OneDrive.
- Admin steps should cost at most one UAC click per run.

## What exists today
- 735 xUnit tests:
  - Collectors 320 (by attribute count; theories expand)
  - Forensics 79
  - Core 35
  - Reports 15
  - Security 8
- TestKit fakes: FakeSystemSource, FakeWmiClient, OffregHiveBuilder for real hive files, AdminFact.
- Gaps:
  - No golden (snapshot) tests of the reports.
  - No end-to-end fixture "old PC".
  - No packaged-EXE smoke test.
  - No GUI automation.
  - Two tests that read this PC's live data take 4 of the 5 minutes (ShellCacheIdResolver 4:00, RealEdgeCache 1:47).

## The tiers

| Tier | What | When | Time | Admin |
|---|---|---|---|---|
| 1 Fast | Unit tests except live/admin/manual | Every change | ~1 min | no |
| 2 Report golden | Synthetic PCs -> HealthReport/Thumbnails text snapshots + wording invariants | Every change to Reports or rule text | <10 s | no |
| 3 Fixture old PC | End-to-end offline scan of a fake Windows folder with planted cases; read-only proof | Every change to collectors/rules; before packaging | ~20 s | no |
| 4 Packaged EXE smoke | Publish, then run the real EXE: selftest, scan (file + pipe), thumbs, offline scan of the tier-3 fixture, bad args, `--fail-on`; check outputs, ACLs, leaks, render | Every package | ~8 min | 1 UAC |
| 5 Real-PC baseline | Scrubbed summary of a real scan compared with the previous one on the same PC | On the target PC, after each new version | ~3 min | 1 UAC |
| 6 Manual GUI | 10-minute checklist (Home, Health page incl. Cancel -> "Stopped", drive picker, gallery, Narrator spot check) | Before handing over a package | 10 min | yes |

One entry point: `scripts/regress.ps1 -Level fast|full|release`.
- **fast** = tiers 1-3, no admin.
- **full** = tiers 1-3 plus the live-data tests.
- **release** = full + tier 4 + the tier-6 checklist prompt.

Each run writes a summary to `C:\PCPorterCases\regress\<timestamp>\`, never the repo.

### Tier 1: fast unit suite
- Tag the live-data tests `[Trait("Category","Live")]`. These are the shell cache, Edge cache, recent files, live app inventory, live posture and live source tests.
- Fast filter: `Category!=Live&Category!=Admin&Category!=Manual`.

### Tier 2: report golden tests
- Five or six synthetic "PCs", built from fakes:
  - clean
  - "looks infected" (hidden task with an action, unsigned Run key in AppData, a secret in a command line)
  - no antivirus + firewall off
  - failing disk + low battery
  - partial scan (a collector fails or times out)
  - offline dead drive
- Each one renders HealthReport.html.
- The test pulls a normalized text view out of the page and compares it with `tests/Golden/<name>.txt`:
  - verdict word
  - banner counts
  - to-do heading and items
  - every row's label and title
  - app rows
- Hand-rolled comparer, no new dependency. When `PCPORTER_ACCEPT=1` is set, the comparer rewrites the golden file, and the diff is reviewed in git.
- **Invariants** checked on every rendered report. Each one comes from a real bug:
  - The banner's "worth a look" count equals the number of "Worth a look" labels, and the same holds for "Unusual". If a count is 0, no row carries that label.
  - The "Do these things" heading appears only when the verdict is "Needs attention" or "Worth a look".
  - Nothing whose advice says "no action needed" (informational) is on the to-do list.
  - No duplicate app rows (same name + maker).
  - Every value is HTML-encoded: no raw `<` from data.
  - A strict CSP is present, there is no `<script>` in HealthReport, and no `http(s)` URL appears as a link.
  - Planted canary secrets never appear.
- The same approach covers Thumbnails.html: its JSON block is checked for shape and counts, with no images snapshotted.

### Tier 3: fixture "old PC" (end to end, offline)
`tests/PCPorter.Regression.Tests` (new project) builds a fake Windows drive in a temp folder:
- `Windows\System32\config\SOFTWARE` and `SYSTEM`, built with OffregHiveBuilder
- `Users\bob\NTUSER.DAT`
- task files plus TaskCache entries
- Start-menu shortcuts
- a small thumbcache
- a mini winget catalog: `Program Files\WindowsApps\Microsoft.Winget.Source_*\Public\index.db`

Planted cases, one or more per past bug or rule:
- leftover task with no action -> Info
- hidden task with an action -> High
- unquoted service path -> Medium
- Run key to an unsigned exe in AppData -> High
- `--password=` canary in a Run command -> redacted everywhere
- 3 versions of one app -> 1 report row
- `.sdb` uninstall entry -> hidden
- shortcut into `AppData\Local\Programs` -> not portable
- winget matches by product code, uninstall key, upgrade code and name + publisher; an ambiguous name -> no match

The test runs `ScanJob` offline against the folder and checks four things:
- a golden `scan-summary.json`: counts per collector, rule-id histogram, posture statuses, match methods
- the report invariants from tier 2
- case.db and `scan/*.json` are valid and agree with each other
- **Read-only proof:** every file in the fixture has the same size, last-write time and SHA-256 after the scan as before, and no file was added. That covers SQLite `-wal`/`-shm` and journal files.

Also, outside the fixture project:
- **Denylist spy:** a recording source wraps every collector and logs every hive, key and value it touches. The test fails on SAM, SECURITY, Winlogon `DefaultPassword`, or any path outside the source root.

### Tier 4: packaged-EXE smoke (`scripts/regress/smoke.ps1`, one elevated run)
1. Publish to `C:\PCPorter-dist\PCPorter` and check the folder: exactly the 7 expected files, no `.pdb`, and the EXE manifest says requireAdministrator.
2. Through PowerShell, which reports real exit codes, run:
   - `selftest` -> 0 and 4 PASS lines.
   - `scan --out X --json`, once redirected through cmd to a file and once piped in PowerShell. Both must give identical, valid JSON, exit 0, and a summary matching the case folder.
   - `scan --offline <tier-3 fixture> --json` -> expected findings, and the fixture is unchanged afterwards.
   - `scan --offline <fixture> --fail-on high` -> exit 5.
   - Bad arguments -> 3. A OneDrive output folder -> 3 with the refusal message.
   - `thumbs --out X --json` -> 0, and the item count is within the baseline range.
3. Check the outputs:
   - The work folder is gone.
   - The case folder ACL is protected (SYSTEM, Administrators and the user only).
   - Logs under `%ProgramData%\PCPorter\logs` contain no canary.
   - No canary appears anywhere in the case folder.
4. **Render check:** headless Edge `--dump-dom` of each HTML report must have no script errors (Thumbnails) and the invariant text. A screenshot goes into the run folder for eyeballing.
5. Record the time per command. More than double the previous run gets flagged.

### Tier 5: real-PC baseline (`scripts/regress/baseline.ps1`, on the target PC)
- After a scan, the script writes a **scrubbed** summary (no names, paths or URLs) to `C:\PCPorterCases\baselines\<date>.json`:
  - collector statuses and counts
  - severity and rule-id histogram
  - posture id -> status
  - app match-method counts
  - report row count
  - run time
- `compare` diffs the newest summary against the previous one and flags:
  - any new High or Risk
  - a posture status change
  - an item count change above 10%
  - a collector going from Ok to anything else
  - run time over 2x
- The user reviews the flags. "Accept" makes the new run the baseline.
- A run on this dev PC is only a dry run of the script. Its numbers (virtual desktop parts, domain join) are not a target.

### Tier 6: manual GUI checklist (`docs/testing/manual-checklist.md`)
- Home tiles, including the Move message.
- Health page:
  - start
  - live cards
  - Cancel -> amber "Stopped"
  - Open report / Open folder
  - inputs disabled while busy
  - a locked BitLocker drive is listed
  - results refused on the drive being checked
- Gallery page end to end.
- One Narrator pass on the Health page.
- Second-instance message.
- Automating this with FlaUI comes later (Phase 7).

## Rule from now on
Every bug fixed gets a regression test at the lowest tier that can catch it, written before the fix when possible. Today's bugs map like this:

| Bug | Caught by |
|---|---|
| 37 leftover tasks rated "worth a look" | tier 3 planted leftover task; tier 5 "new High" flag |
| Banner/labels/heading disagree | tier 2 invariants |
| Duplicate app versions | tier 2 invariant + tier 3 planted versions |
| Python shortcuts as portable apps | tier 3 planted shortcut |
| `.sdb` entry as an app | tier 3 planted entry |
| Redirected CLI output empty | tier 4 file-vs-pipe comparison |
| winget skipped when elevated | tier 3 mini catalog; tier 4 match counts |

## Build order
1. Tag live tests and add `scripts/regress.ps1 -Level fast`. Small.
2. Tier 2: golden comparer, 6 synthetic PCs, invariants. Medium.
3. Tier 3: fixture builder, planted cases, read-only proof, denylist spy. Largest piece.
4. Tier 4: smoke script (reuses the tier-3 fixture). Medium; one UAC per run.
5. Tier 5: baseline + compare scripts. Small.
6. Tier 6 checklist doc. Small.

## Open choices (defaults chosen)
- Golden files: hand-rolled comparer (no dependency) rather than the Verify library.
- Baselines live on each target PC in `C:\PCPorterCases\baselines` and are never copied off it.
- No Win10 VM is available here (virtual desktop). Win10 coverage comes from the tier-3 fixture: hives built with Win10 values, and the ESE search index path, which is already tested. A real Win10 PC runs tier 5 when available.
