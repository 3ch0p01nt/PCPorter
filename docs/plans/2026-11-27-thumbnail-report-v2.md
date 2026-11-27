# Thumbnail Report v2 - Improvements from the 10-agent review

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Test first for every task; verify on this PC where marked (V).

Builds on `docs/plans/2026-11-26-thumbnail-report.md` (v1, shipped: parser, collector, gallery, `thumbs` CLI, Win11 index paths).

## Facts verified on this PC (2026-11-26/27)
- Free-space record in every cache file: CacheId 0, data size 0, spans from the first-free offset exactly to end of file; free space is all zeros here (no hidden older entries on this PC, but other PCs may differ).
- 460 "empty" entries in `thumbcache_256.db` carry real cache IDs (evidence a file was displayed; no pixels stored). v1 drops them.
- Case folder `C:\PCPorterDev\PCPorter` inherits `Users: Read` and `Authenticated Users: Modify` - other accounts can read the images.
- Edge and Chrome caches here are Chromium **blockfile** format (`index`, `data_0..3`, `f_*`).
- Folder thumbnails: fixed in v1 (137 "deleted" -> 16 truly gone).

## P0 - Correctness, privacy, safety (do first)
1. **Protected, unique case folders.** Folder name `<Computer>_<yyyyMMddTHHmmssZ>_<6 random hex>`; refuse if any component exists or is a reparse point; DACL protected: SYSTEM + Administrators + the interactive user only; `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on the case folder; images written with `FileMode.CreateNew`; warn on exFAT/FAT (no ACLs). Test: ACL has no Users/Authenticated Users entries (V).
2. **Current user by default.** `--all-users` (admin) is opt-in with a consent line naming the profiles; profile folders labelled from ProfileList; `ExplorerFolder` rejected if it is a reparse point. User file-name prefix = sanitized name + 8 hex of SHA-256(SID or name) so `bob.x` and `bob_x` can't collide.
3. **Honest status values.** `Exists`, `Deleted` (parent folder readable and file/folder absent), `Unreachable` (drive missing, access denied, network path), `Unknown` (no path). Tests: access-denied path, missing drive letter, folder path.
4. **Parser fixes.**
   - Header offsets: versions 0x1C/0x1E/0x1F/0x20 read first/free at 16/20 (0x1C header 28 bytes); 0x14/0x15/0x1A at 12/16. Explicit version table; unknown version => warning.
   - On an entry with CacheId 0 or data size 0, advance by the **header size**, not the entry size, so a free-space record can't hide data behind it.
   - Cap padding (`pad < size`); offsets as `long`.
   - Validate header CRC-64 (table-driven, init 0xFFFF..., over header minus last 8 bytes) for entries found by scanning; expose `HeaderCrcValid`.
   - Rename "Recovered" in the UI to **"Found in free space"** (outside the live chain); it is not a deletion signal by itself.
   - Builder fixed so 0x14/0x1C/0x1E layouts are really different; tests for each.
5. **Keep cache-ID-only entries.** Empty entries become items with `HasImage = false` ("Windows showed this file, but stored no picture"), mapped through the index like the rest. Separate filter + tile.
6. **Dedupe properly.** Per (user, kind, id, size class) keep one image, preferring the live copy; item is "found in free space" only if every copy is.
7. **CLI robustness.** Dedicated `CaseLocationRejectedException`; general catch => `Failed` exit code with a friendly message; synchronous `IProgress` (WPF `Progress<T>` posts to a blocked dispatcher); `--user`, `--all-users`, `--json` tested.
8. **VSS cleanup.** Delete the shadow copy if its lookup fails; record created IDs and remove stale PCPorter-created copies at startup.
9. **CaseLocation.** Also reject folder names `OneDrive` / `OneDrive - *` (env vars are wrong when elevating as another admin).
10. **Report JS bugs.** try/catch around `localStorage`; theme toggle from `dataset.theme ?? matchMedia` with a System option; unknown paths sort last via one `Intl.Collator`; `order[x] ?? 9`; case-insensitive cache-ID search; filenames encoded per segment with `encodeURIComponent`; print shows tiles and renders all cards eagerly; tile clicks reset search/size/user and set `aria-pressed`; guard null `version`.

## P1 - More original paths and dates
11. **Search index incl. recent changes.** Copy `Windows.db` + `-wal` + `-shm` (shared read) into the protected work folder and open the copy normally so the WAL is applied; never touch the originals. Fallback path = `ItemFolderPathDisplay` + `ItemNameDisplay` or `ItemUrl`; log matched-WorkId-without-path count; `DBNull` handled; error messages specific (not always "run as admin").
12. **Ask the shell for existing files' IDs (V first).** For unresolved IDs, walk user folders and fixed/removable drives for image/video/document extensions (skip reparse points) and read `PKEY_ThumbnailCacheId` via `SHCreateItemFromParsingName` + `IShellItem2::GetUInt64` on an STA thread (never generates a thumbnail). Verify on this PC that the shell's ID equals the cache's ID for 20 known files before relying on it.
13. **Existing shadow copies (admin, never create).** Enumerate `Win32_ShadowCopy`; read each copy's thumbcache files (older/deleted thumbnails) and index (historical paths, flagged "path from restore point dated X").
14. **Windows 10 index (Windows.edb).** Copy `Windows.edb` + `MSS*.log` + `MSS.chk` (via an existing shadow copy or shared read), `esentutl /r MSS` on the copy, read with ManagedEsent (read-only attach); table `SystemIndex_PropertyStore` (`SystemIndex_0A` on old builds), columns matched by suffix `-System_ThumbnailCacheId` / `-System_ItemPathDisplay`; handle compressed text columns. Test against a Win10 VM index.
15. **"Displayed between X and Y".** Earliest = max(original file created time, cache file created time, last shadow copy without the entry); latest = min(first shadow copy with the entry, cache file modified time). Corroborate with RecentDocs/LNK/Jump List opens of the same path. Confidence High/Medium/Low with the sources listed. Index `DateModified`/`DateTaken` shown with explicit labels ("file last modified", "photo taken"), never as view times.
16. **thumbcache_idx.db (optional).** Which sizes exist per ID, "no data" flag, orphan detection.

## P2 - More image sources (same gallery, tagged by source and evidence level)
17. Chromium blockfile cache (Edge, Chrome, new Teams WebView2): image entries with URL, created/last-used time; join `History` for page title. Evidence: "loaded by a web page".
18. Firefox `cache2` entries (metadata at end, big-endian offset): URL + fetch times.
19. Screenshots (`Pictures\Screenshots`) and Snipping Tool (`ScreenSketch\TempState`): file times. Evidence: "was on screen".
20. RecentDocs (image extensions), Recent `.lnk`, Jump Lists (Photos/Paint): evidence "opened", with open times.
21. Detect-only notes: Windows Recall present (encrypted, not readable), Photos `MediaDb` (indexed, not viewed).
- Cross-source dedupe by content hash; each item lists all sources.

## P2 - Scale and speed
22. Stream-parse cache files (1 MB buffered, sliding resync window, `long` offsets) - no whole-file arrays; copy image bytes straight to output.
23. Image files named by content hash (`XxHash64`), written once, in parallel via a bounded channel.
24. Existence checks grouped by parent folder (one enumeration per folder).
25. Index: `PRAGMA mmap_size/cache_size`, single pass over both columns, reused 8-byte buffer, progress in rows/bytes, `CancellationToken` everywhere.
26. Stream the JSON into the HTML; drop redundant `best`/`file` fields.

## P2 - Gallery UX
27. True virtualization (fixed row height, recycled nodes) for 100k+ items; debounced search; precomputed lowercase paths.
28. Keyboard: arrows across the grid; Left/Right/Home/End and "3 of 812" in the detail view; focus returns to the card.
29. Filters/sort/selected item in the URL hash (back/forward, bookmarks).
30. Group by folder / status with sticky headers; collapsible folder tree; "No path recorded" bucket.
31. Detail view: all sizes side by side, zoom/pan (pixelated 1:1), copy path (clipboard + execCommand fallback); no "open folder" (paths are the old PC's).
32. Select + tag (Important / Review) + export CSV of filtered/selected; optional ZIP of selected images (inlined fflate).
33. Accessibility: full-word badges with icon + `aria-label`, `role="group"` + `aria-pressed` on size buttons, live region for paging.
34. UTC + local times; contact-sheet print mode with page headers.
35. Near-duplicate groups via dHash computed in C# (`dupGroup`, "+3 similar", collapse toggle).
36. Date views (Year/Month, histogram brush) once item 15 exists.

## Still open from v1
- GUI tile "Explore my PC's history" -> run + open report (after P0).
- Check the report opened straight from disk (file://) in Edge and Chrome.
- Optional encrypted output: recommend BitLocker To Go; "Delete case" command (with SSD caveat).

## Order
P0 (1-10) -> GUI tile + file:// check -> P1 (11, 12, 14, 15, 13, 16) -> P2 sources (17-21) -> P2 scale (22-26) -> P2 UX (27-36).
