# Web history report (History.html) - design

Phase 3, item 1 of [the PCPorter design](2026-11-26-pcporter-design.md) (section E). Approved 2026-11-27.

## Decisions (from Q&A)
| Topic | Decision |
|---|---|
| Purpose | All three equally: look back at browsing, keep a record before the old PC is wiped, check what happened |
| Accounts | Same as the gallery: the current user by default; "all accounts" tick box (admin only, "ask them first"); an offline (dead-PC) drive shows every account |
| Browsers | Chrome, Edge, Brave, Opera (+GX), Vivaldi, Chromium; Firefox; Internet Explorer + legacy Edge (WebCacheV01.dat) |
| Content | Visits, searches, downloads (still on disk?), bookmarks, open + recently closed tabs, form entries |
| Deleted history | All three layers: (1) live DB including the not-yet-saved WAL, (2) deleted rows carved from free space inside the DB and older WAL frames, (3) older copies in existing restore points (admin, live only) |
| Report build | Hand-rolled like Thumbnails.html: one offline HTML file, data embedded, own virtual table + SVG charts, no libraries. Table/chart code kept in one embedded "report kit" so the Timeline report can reuse it |

## Never read (enforced and tested)
`Login Data*`, `Cookies`, `Network\Cookies`, `logins.json`, `key4.db`, `cert9.db`, `Local State`'s `os_crypt` key, and the
`credit_cards`, `masked_credit_cards`, `ibans`, `local_ibans` tables. From `Web Data` only the `autofill` table is read.
Form fields whose name looks like a password, card, CVV, PIN, SSN, IBAN or account number are dropped. URLs, titles and
form values go through `Redactor` (masks `user:pass@`, tokens and `key=secret` query values). Browsers are never started
or injected into; files are read through shared read handles and copied into the case's private `work` folder.

## Architecture
New folder `src/PCPorter.Forensics/BrowserHistory/`:
- `BrowserProfileFinder`: per user profile folder -> `BrowserProfile(Browser, Family, Name, Folder, User)`.
  Chromium roots under `AppData\Local` (Chrome, Edge, Brave, Vivaldi, Chromium) and `AppData\Roaming\Opera Software`
  (Opera Stable, Opera GX Stable: the root is the profile). Profile names come from `Local State`'s `profile.info_cache`
  when readable, otherwise `Default` / `Profile N`. Firefox from `AppData\Roaming\Mozilla\Firefox\Profiles\*` (has
  `places.sqlite`). IE/legacy Edge: `AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`.
- `DbSnapshot`: copies `X`, `X-wal`, `X-journal` with FileShare ReadWrite|Delete into the work folder (CreateNew), opens
  the copy so SQLite replays the WAL. Keeps the raw bytes of the main file and WAL for carving. Pool cleared + copy
  deleted after use (pattern of `SearchIndexPathResolver`).
- `ChromiumHistoryReader`: `urls`+`visits` (transition core type + qualifiers, duration, from_visit),
  `keyword_search_terms`, `downloads`+`downloads_url_chains`; `Bookmarks` JSON; `Web Data` autofill; `Sessions\Session_*`
  and `Tabs_*` (SNSS: tab navigation commands -> URL + title).
- `FirefoxHistoryReader`: `moz_places`+`moz_historyvisits` (visit_type), `moz_bookmarks`, downloads from `moz_annos`
  (`downloads/destinationFileURI`, `downloads/metaData`), `formhistory.sqlite` `moz_formhistory`, session files
  `sessionstore.jsonlz4` / `sessionstore-backups\recovery.jsonlz4` (mozLz4 = magic + LZ4 block; own ~40-line decoder).
- `WebCacheReader`: ESE via the existing ManagedEsent package on a copy (with its logs, recovery run on the copy).
  Live: the file is locked, so it is read from a temporary shadow copy (admin, same pattern as the gallery's Windows.edb
  on Win10); not elevated -> a note. Offline: direct copy. Containers named `History`/`MSHist*`, `iedownload`.
- `SearchTerms`: from Chromium `keyword_search_terms` plus URL parsing for Google, Bing, DuckDuckGo, Yahoo, YouTube,
  Ecosia, Startpage, Brave Search, Amazon, Wikipedia.
- `SqliteCarver` (layer 2): walks the raw bytes of the copied DB (freelist trunk/leaf pages, freeblocks and unallocated
  space in table leaf pages) and the WAL frames that are older than the live page versions. Decodes candidate records by
  varint header against the known column layouts (`urls`, `visits`, `moz_places`, `moz_historyvisits`, `downloads`).
  Keeps only rows that parse cleanly and whose id is not in the live table. Labelled "Recovered from leftover data"
  (may be deleted or an older copy of a page). Frames after the last commit are skipped (unsaved changes).
  Other labels since the gap-closure review: "From a damaged copy" (a copy that still failed `quick_check` after 3
  tries) and "Restore point copy" (a restore-point visit for a profile whose live history could not be read, so it
  cannot be called "no longer listed").
- `RestorePointHistory` (layer 3): `VssSnapshotProvider.ListExisting` (read-only, never creates), maps each profile's
  DB into each restore point, reads it with the same readers, keeps visits absent from the live DB, labelled
  "recovered (restore point <date>)". Live + admin only; otherwise a note.
- `HistoryScan` model: `Visit`, `Search`, `Download`, `Bookmark`, `OpenTab`, `FormEntry`, `ProfileCoverage` (earliest/
  latest visit, counts, retention note: Chrome-family keeps ~90 days, Firefox by size), `Origin` {Live, Wal, Carved,
  RestorePoint}, notes and warnings.

Files are read through `SourceFiles` (`src/PCPorter.Collectors/Sources/SystemSource.cs`) so the same code serves live
and offline sources and the denylist spy can check every path. Users come from `ISystemSource.Users`.

`src/PCPorter.Reports/`:
- `HistoryJob.Run(outRoot, ISystemSource, HistoryJobOptions, IProgress<string>, now, ct)`: `CaseFolder.Create`, private
  `work`, readers per profile (one failing profile = a warning, never the whole run), case.db rows (`Category`
  `WebHistory.Visit|Search|Download|Bookmark|Tab|Form`), `History.html`, delete `work`.
- `HistoryReport`: streams the JSON into `Templates/History.html` at `__PCPORTER_DATA__` (same escaping as
  `GalleryReport`). URLs and titles are stored once in string tables; visits are compact arrays, so 100k visits stay
  around 10-15 MB.
- `Templates/report-kit.js` (embedded, inlined at `/*__PCPORTER_KIT__*/`): virtual table (sort, filter, keyboard,
  CSV export), SVG bar/line chart, heatmap, URL-hash state.

Report sections: summary tiles and coverage (per browser/profile: first/last date, counts, how far back it can go);
charts (visits per day, hour x weekday heatmap, top sites, typed vs clicked); visits table (filters: date range,
user/browser/profile, site, text, how it was opened, origin incl. recovered); searches; downloads (from site, still on
disk); bookmarks; open and recently closed tabs; form entries (collapsed until clicked); recovered history; method and
limits (private browsing leaves almost nothing; Chrome keeps ~90 days).

App: CLI `pcporter history --out X [--all-users] [--offline D:\] [--no-restore-points] [--json]` (exit codes as
`thumbs`), WPF page "Web history" (pattern of `ThumbsPage`), the Home history tile offers both pages.

## Error handling
Locked or unreadable file -> warning naming browser/profile, the rest continues. Corrupt DB (SQLite 11/26) -> carving
still runs on the raw bytes. Not admin -> restore points and live IE skipped with a note. Exit code 1 (partial) when
anything was skipped. Cancel between profiles and inside long loops.

## Testing
- Unit: each reader on synthetic profiles built in tests (SQLite schemas of current Chrome/Firefox; Bookmarks JSON;
  SNSS and mozLz4 builders; an ESE WebCache built with ManagedEsent). Carver: insert, delete without VACUUM, leave WAL
  unchecked-pointed; the deleted rows must come back, no false rows from random bytes. Transition and time conversions.
- Report: escaping of hostile URLs/titles, CSP and no network, golden summary of a synthetic multi-browser PC,
  culture runs (de-DE).
- Tier 3: browser profiles planted in `OldPcDrive` (bob: Chrome + Firefox, deleted rows, a download still on disk and
  one gone, a form field named "password" that must not appear, Login Data/Cookies/key4.db bait files that the spy
  must never see opened). Offline end-to-end + read-only proof.
- Tier 4: `history` CLI added to the smoke run (needs `install-smoke-task.ps1` re-run as admin once).

## Build order
1. Chromium core: finder, DbSnapshot, visits/searches/downloads, job, report + kit, CLI. 
2. Chromium bookmarks, autofill, sessions; Firefox (all parts).
3. Deleted history: carver, restore points.
4. IE / legacy Edge WebCache.
5. GUI page + Home tile, offline tier-3 plant + spy, tier-4 smoke, HOW-TO-RUN and README.
