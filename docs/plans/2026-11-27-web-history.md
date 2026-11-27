# Web history report Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task.

**Goal:** `History.html`: every account's browsing (visits, searches, downloads, bookmarks, tabs, form entries) from
Chromium browsers, Firefox and IE/legacy Edge, including deleted history, from a live PC or a dead PC's drive.

**Architecture:** Readers in `src/PCPorter.Forensics/BrowserHistory/` read copies of browser files through `SourceFiles`
(live and offline alike) into a `HistoryScan` model. `HistoryJob` (Reports) writes case.db rows and streams the model
into an embedded hand-rolled template that inlines a reusable `report-kit.js`. CLI `history`, WPF "Web history" page.
Design: [2026-11-27-web-history-design.md](2026-11-27-web-history-design.md).

**Tech Stack:** .NET 10, Microsoft.Data.Sqlite 11 (already referenced), ManagedEsent 3.2 (already referenced), xUnit v2,
System.CommandLine, WPF-UI. No new packages.

**Conventions for every task**
- TDD: write the failing test, run it, implement, run, commit (`git add` only the task's files; message ends with the
  Co-Authored-By line). Run tests with `dotnet test tests/<Project> --filter "FullyQualifiedName~<Class>"`.
- `TreatWarningsAsErrors` is on. WPF test projects need `global using System.IO;` (already present).
- Edit files with Edit/Write, never sed/python on text with backslashes (tasks/lessons.md).
- Synthetic fixtures only; never commit data from this PC. Times in tests are fixed UTC values.
- Read files only via `SourceFiles.OpenRead`/`Files`/`Folders` (`src/PCPorter.Collectors/Sources/SystemSource.cs`),
  so the confinement jail and the denylist spy see every access. Forensics may need a project reference to
  Collectors for this; if that creates a cycle, move `SourceFiles` to `PCPorter.Core` (namespace kept) first.

---

## Milestone 1: Chromium core, job, report, CLI

### Task 1: Browser profile finder
**Files:** Create `src/PCPorter.Forensics/BrowserHistory/BrowserProfile.cs`, `BrowserProfileFinder.cs`;
Test `tests/PCPorter.Forensics.Tests/BrowserHistory/BrowserProfileFinderTests.cs`, fixture helpers in
`tests/PCPorter.Forensics.Tests/BrowserHistory/BrowserFixtures.cs`.
- `enum BrowserFamily { Chromium, Firefox, WebCache }`;
  `record BrowserProfile(string User, string Browser, BrowserFamily Family, string Name, string Folder)`.
- `BrowserProfileFinder.Find(string user, string profileFolder, IList<string> warnings)`.
  Chromium roots (relative to the user profile): `AppData\Local\Google\Chrome\User Data`,
  `AppData\Local\Microsoft\Edge\User Data`, `AppData\Local\BraveSoftware\Brave-Browser\User Data`,
  `AppData\Local\Vivaldi\User Data`, `AppData\Local\Chromium\User Data` (profiles `Default` / `Profile N` that contain
  `History`; display name from `Local State` JSON `profile.info_cache.<dir>.name` when present, read with a 1 MB cap);
  `AppData\Roaming\Opera Software\Opera Stable` and `Opera GX Stable` (root itself is the profile when it has `History`).
  Firefox: `AppData\Roaming\Mozilla\Firefox\Profiles\*` containing `places.sqlite` (name = folder after the first dot).
  WebCache: `AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` -> Browser "Internet Explorer / Edge (legacy)".
- Tests: a temp profile tree with Chrome Default + Profile 2 (+ Local State names), Edge Default, Brave, Opera Stable,
  Firefox `abcd.default-release`, a WebCache file, a `Guest Profile` and a `System Profile` (both ignored), a profile
  folder without `History` (ignored). Assert exact list and order (browser, then name).

### Task 2: DbSnapshot (copy + WAL)
**Files:** Create `BrowserHistory/DbSnapshot.cs`; Test `DbSnapshotTests.cs`.
- `DbSnapshot.Take(string dbPath, string workFolder) : DbSnapshot` copies `dbPath`, `-wal`, `-journal` (whichever exist)
  with shared reads into `work\db-<guid8>\` (CreateNew), exposes `Path`, `RawMain` (byte[] of the main file, capped
  512 MB -> warning), `RawWal` (byte[]?), `Open()` -> `SqliteConnection` (`Mode=ReadWrite`, `Pooling=false`) so the WAL
  replays into the copy only. `Dispose` clears pools and deletes the folder.
- Tests: create a WAL-mode DB, keep a writer connection open with uncheckpointed inserts (wal_autocheckpoint=0), take a
  snapshot while the writer holds it: the copy sees the WAL rows; the original's bytes and mtime are unchanged; the
  folder is gone after Dispose.

### Task 3: History model + Chromium visits
**Files:** Create `BrowserHistory/HistoryModel.cs`, `ChromiumHistoryReader.cs`; Test `ChromiumHistoryReaderTests.cs`;
fixture builder `ChromiumFixture` in `BrowserFixtures.cs` (creates the real `History` schema: `urls`, `visits`,
`keyword_search_terms`, `downloads`, `downloads_url_chains`, `meta`).
- Model (records, all times `DateTimeOffset` UTC):
  `Visit(Profile, Url, Title, When, How, DurationSeconds, Origin, OriginNote)`,
  `enum VisitHow { Link, Typed, Bookmark, Redirect, Reload, Generated, FormSubmit, Other }`,
  `enum Origin { Live, Carved, RestorePoint }`,
  `Search(Profile, Terms, Engine, When, Origin)`, `Download(Profile, Url, Referrer, TargetPath, Started, Bytes,
  State, StillOnDisk?)`, `Bookmark(Profile, Title, Url, Folder, Added)`, `OpenTab(Profile, Url, Title, Window, State
  {Open, RecentlyClosed}, LastActive?)`, `FormEntry(Profile, Field, Value, Count, First, Last)`,
  `ProfileCoverage(Profile, Visits, Earliest?, Latest?, Note)`, `HistoryScan(...lists..., Notes, Warnings)`.
- Chromium visits: join `visits` -> `urls`; `visit_time` via `Timestamps.FromWebKit`; core transition
  `transition & 0xFF`: 0 Link, 1 Typed, 2 AutoBookmark->Bookmark, 3/4 subframe -> skipped (not shown), 5 Generated,
  7 FormSubmit, 8 Reload, 9/10 Keyword->Typed; redirect qualifiers `0x40000000|0x80000000` on a chain middle ->
  Redirect. `visit_duration` micros -> seconds. URL and title pass through `Redactor.Redact`.
- Tests: fixture with typed, link, bookmark, redirect chain, reload, subframe (excluded), a URL with
  `?access_token=abc`, a title with `user:pw@`; exact results.

### Task 4: Searches and downloads (Chromium)
**Files:** Create `BrowserHistory/SearchTerms.cs`; extend `ChromiumHistoryReader`; Tests `SearchTermsTests.cs`,
reader tests.
- `SearchTerms.FromUrl(string url) : (string Engine, string Terms)?` for Google (`q`), Bing (`q`), DuckDuckGo (`q`),
  Yahoo (`p`), YouTube (`search_query`), Ecosia (`q`), Startpage (`query`/`q`), Brave Search (`q`), Amazon (`k`),
  Wikipedia (`search`). Host match by registrable suffix (google.* incl. google.co.uk).
- Searches = `keyword_search_terms.term` joined to the URL's last visit time, plus URL-derived ones not already present
  (dedupe on terms + minute).
- Downloads: `downloads` (target_path, start_time, received_bytes, total_bytes, state 0..4 -> InProgress, Complete,
  Cancelled, Interrupted; referrer, tab_url) + first `downloads_url_chains` URL. `StillOnDisk` = `SourceFiles` exists of
  the path mapped with `ISystemSource.MapPath` (passed in as a `Func<string,bool>`).

### Task 5: report kit + History.html template + HistoryReport
**Files:** Create `src/PCPorter.Reports/Templates/report-kit.js`, `Templates/History.html`, `HistoryReport.cs`;
Test `tests/PCPorter.Reports.Tests/HistoryReportTests.cs`. csproj: add `<EmbeddedResource Include="Templates\*.js" />`.
- JSON shape: `{meta, notes, warnings, profiles:[...], coverage:[...], strings:[...], visits:[[profileIdx, urlIdx,
  titleIdx, unixSeconds, how, duration, origin, noteIdx]...], searches, downloads, bookmarks, tabs, forms}`. Strings
  deduped (urls/titles). Same serializer options and escaping as `GalleryReport`; kit inlined at `/*__PCPORTER_KIT__*/`.
- CSP identical to Thumbnails.html (no `img-src` needed beyond `'self'`). No network, no external URLs except as text.
- Kit: `vtable(el, columns, rows, opts)` (virtual scroll of fixed-height rows, sort by column, text + per-column
  filters, keyboard up/down, CSV of the filtered rows), `barChart(svg, data)`, `heatmap(svg, 7x24)`, `hashState`.
- Page sections as in the design doc; links in the table are plain text (copy button), never clickable navigations.
- Tests: hostile URL/title (`</script><script>alert(1)`) stays inside the data block; CSP present; no `http` in any
  `src=`/`href=`; string-table round trip; `WriteFile` refuses overwrite.

### Task 6: HistoryJob + case.db
**Files:** Create `src/PCPorter.Reports/HistoryJob.cs`; Test `tests/PCPorter.Reports.Tests/HistoryJobTests.cs`.
- `HistoryJobOptions(bool AllUsers, bool RestorePoints)`; `HistoryJobResult(ReportPath, CaseFolder, Scan)`.
- `HistoryJob.Run(string outRoot, ISystemSource source, HistoryJobOptions o, IProgress<string>? p, DateTimeOffset? now,
  CancellationToken ct)`: users = live and not AllUsers -> current user only; else `source.Users` that are available.
  `using SourceFiles.Confine(source.ReadRoot)`. `CaseFolder.Create` + private `work`; per profile try/catch (except
  cancel) -> warning; coverage per profile; case.db rows (`WebHistory.Visit|Search|Download|Bookmark|Tab|Form`,
  Source `"{Browser}/{Profile}"`, User); `History.html`; delete `work`.
- Tests with `FakeSystemSource` + a temp drive containing a Chrome profile: report exists, case.db row counts match,
  work folder gone, a profile with a corrupt History gives a warning and the other profile still appears.

### Task 7: CLI `history`
**Files:** Create `src/PCPorter.App/Infrastructure/HistoryCommand.cs`; register in `App.xaml.cs` next to
`ThumbsCommand`. Pattern of `ThumbsCommand.cs` (synchronous `ConsoleProgress`, error mapping, `--json` summary).
Options `--out` (required), `--all-users`, `--offline <drive>`, `--no-restore-points`, `--json`. Exit 0 / 1 (warnings)
/ 2 / 3 / 4 (all-users or live IE without admin is a note, not exit 4). Test via the existing CLI test pattern in
`tests/PCPorter.Core.Tests` / App tests if present; otherwise a parse test of the command.

**Milestone 1 check:** `scripts/regress.ps1` passes; run `pcporter history --out C:\PCPorterCases\dev` on this PC
(non-admin) and open the report in Edge headless (render check like regress.ps1). Commit.

## Milestone 2: the rest of Chromium, Firefox
### Task 8: Chromium bookmarks, autofill, sessions
- `Bookmarks` JSON (`roots.bookmark_bar|other|synced`, recursive, `date_added` WebKit string).
- `Web Data`: ONLY `SELECT name, value, count, date_created, date_last_used FROM autofill`; drop fields matching
  `(?i)pass|pwd|card|cc-?num|cvv|cvc|pin|ssn|iban|account|routing|secret|token|otp`; values via Redactor.
- SNSS (`Sessions\Session_*`, `Sessions\Tabs_*`, older `Current Session`/`Last Session`): header `SNSS` + int32
  version; records `uint16 size, uint8 id, payload`. Id 6 `UpdateTabNavigation` (Pickle: tab id, index, url string,
  title string16) -> latest navigation per tab; ids 16/`TabClosed` and 17/`WindowClosed` mark recently closed. Unknown
  ids skipped; truncated records end parsing with a note.
- Tests with builders for each format, including a truncated SNSS.
### Task 9: Firefox
- `places.sqlite`: `moz_historyvisits` join `moz_places`; `visit_date` PRTime; `visit_type` 1 Link, 2 Typed,
  3 Bookmark, 4 Embed (skip), 5/6 Redirect, 7 Download, 8 FramedLink (skip), 9 Reload.
- Bookmarks: `moz_bookmarks` type 1 join `moz_places`, folder path from parents.
- Downloads: `moz_annos` + `moz_anno_attributes` names `downloads/destinationFileURI` (file:/// URI -> path) and
  `downloads/metaData` (JSON state, endTime, fileSize).
- `formhistory.sqlite` `moz_formhistory(fieldname, value, timesUsed, firstUsed, lastUsed)`, same field filter.
- Sessions: `sessionstore.jsonlz4`, `sessionstore-backups\recovery.jsonlz4`, `previous.jsonlz4`: magic
  `mozLz40\0`, uint32 size, LZ4 block -> JSON `windows[].tabs[].entries[]` (last entry = current), `_closedWindows`,
  `windows[]._closedTabs` -> recently closed. Own `Lz4Block.Decode(ReadOnlySpan<byte>, int size)` with bounds checks.
- Searches from URLs (Firefox keeps no separate table).
- Tests: fixture builder `FirefoxFixture` with real schemas; LZ4 encoder for tests may emit literal-only blocks plus one
  hand-made match sequence; corrupt LZ4 -> note, no exception.

## Milestone 3: deleted history
### Task 10: SqliteCarver
**Files:** `BrowserHistory/SqliteCarver.cs`, tests `SqliteCarverTests.cs`.
- Input: raw main bytes, raw WAL bytes, page size (header offset 16, 1 = 65536), known layouts:
  `urls(id INTEGER, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT, hidden INT)`,
  `visits(id, url INT, visit_time INT, from_visit INT, transition INT, ...)`,
  `moz_places(id, url TEXT, title TEXT, rev_host TEXT, visit_count, hidden, typed, frecency, last_visit_date, ...)`,
  `moz_historyvisits(id, from_visit, place_id, visit_date, visit_type, session)`.
- Scan: freelist trunk + leaf pages, every b-tree table leaf page's freeblock chain and the gap between the cell pointer
  array and the cell content area, and every WAL frame page (frames whose page number + salt are older than the last
  committed frame for that page count as history). Try record decode at each offset: payload-length varint, rowid
  varint, header-length varint, serial types that match the layout (TEXT for url starting `http`/`https`/`ftp`/`file`,
  integer time in the plausible window 2000..now+1 day). Freeblocks overwrite the first 4 bytes: also try with the
  header assumed and the first column(s) lost (rowid unknown).
- Output carved `Visit`s (urls with last_visit_time; visits joined to live or carved urls by id) not present live.
- Tests: Chrome and Firefox fixtures: insert 50 visits, delete 20 (`secure_delete=OFF`, no VACUUM), plus a WAL with
  uncheckpointed delete; at least the deleted rows' URLs come back with correct times; random-bytes page yields zero
  results; `secure_delete=ON` fixture yields zero (documented limit).
### Task 11: Restore points
- `RestorePointHistory.Read(profiles, source, work, now)`: only when `source.IsLive` and elevated; uses
  `VssSnapshotProvider.ListExisting(@"C:\")` (never `Create`); for each restore point, map each profile's History /
  places.sqlite with `VssSnapshotProvider.MapPath`, `DbSnapshot.Take`, read visits, keep those absent from the live set
  (url + time to the second). Origin RestorePoint with note `restore point yyyy-MM-dd`.
- Tests: logic tested with an injected "restore point roots" list pointing at temp folders holding older DB copies;
  one `[AdminFact][Trait("Category","Admin")]` smoke that lists restore points without failing.

## Milestone 4: IE / legacy Edge
### Task 12: WebCacheReader
- Copy `WebCache\*` (`WebCacheV01.dat`, `V01*.log`, `V01.chk`, `V01res*.jrs`) to work; live: files are locked, so
  only when elevated, via a temporary `VssSnapshotProvider.Create(@"C:\")` (disposed in finally; same notes as the
  gallery's Windows 10 index path); offline: direct copy.
- Open with ManagedEsent on the copy (recovery on, logs in the copy folder, read-only after recovery). Table
  `Containers` (`ContainerId`, `Name`, `Directory`): containers named `History` or starting `MSHist` -> table
  `Container_<id>`: columns `Url` (strip `Visited: user@` prefix), `AccessedTime` (FILETIME), `AccessCount`;
  `iedownload` container -> downloads (`Url`, `ResponseHeaders` best effort).
- Tests: build an ESE DB with that subset schema via ManagedEsent in temp; read back; a dirty/corrupt file -> warning.

## Milestone 5: app, offline, regression
### Task 13: WPF page + Home
- `Views/HistoryPage.xaml(.cs)` mirroring `ThumbsPage` (folder, "all accounts" (admin), "include restore points"
  (admin), "another PC's drive" picker reused from `ScanPage` drive logic, Start/Cancel, Open report).
- Nav item "Web history" in `MainWindow.xaml`; Home "Explore my PC's history" opens a small chooser or navigates to
  History with a link to "Images viewed".
### Task 14: Tier 3 plant + spy
- `OldPcDrive`: bob gets a Chrome Default profile (visits incl. typed/redirect/deleted rows, keyword search, a download
  whose target exists and one that doesn't, Bookmarks, a Session file, Web Data with `autofill` rows incl. a field
  named `password` = canary and a `credit_cards` table with a canary) and a Firefox profile (places + formhistory +
  sessionstore.jsonlz4); bait `Login Data`, `Cookies`, `key4.db`, `logins.json` containing the canary.
- `OldPcScanTests`: offline history run finds the planted items, canary appears nowhere, the drive fingerprint is
  unchanged, the spy shows the bait files were never opened and `credit_cards` never queried (check via a
  `SqliteCommand` text log hook or by asserting the reader's SQL constants).
- Golden summary `Golden/history-oldpc.txt` (counts per profile/origin, first/last dates, top 5 sites).
### Task 15: Tier 4 + docs
- `smoke.ps1`: `history --out ... --json` live (exit 0/1, report exists, canary scan) and offline on the fixture
  (findings, unchanged). Re-run `install-smoke-task.ps1` as admin (one UAC prompt).
- `packaging/HOW-TO-RUN.txt`, `README.md`, `tasks/todo.md`, `docs/testing/manual-checklist.md` (History page).
- Full `regress.ps1 -Level release`; package zip.
