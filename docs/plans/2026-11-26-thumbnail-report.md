# Thumbnail Report (pulled forward from Phase 3) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** `pcporter thumbs --out <folder>` and the "Explore my PC's history" tile extract every image thumbnail Windows has cached (including ones whose original was deleted), link them to original paths where Windows still knows them, and produce an offline `Thumbnails.html` gallery.

**Architecture:** New `PCPorter.Forensics` library: a pure `ThumbcacheParser` over a byte buffer (no I/O), a `SearchIndexMapper` (cache ID -> original path from the Windows Search index), and a `ThumbnailCollector` that reads each profile's cache files read-only, writes images into the case folder and rows into case.db. New `PCPorter.Reports` library renders a self-contained HTML gallery (vanilla JS, no external resources) next to a `thumbs\` folder.

**Format facts verified on this PC (Win11 26200, version 0x20):**
- File header 24 bytes: `CMMM`, version (u32), cache type (u32), unknown (u32 = 0), first entry offset (u32 = 24), first free offset (u32).
- Entry header 56 bytes: `CMMM`, entry size, cache ID hash (u64), identifier length (bytes), padding size, data size, width, height, unknown, data CRC (u64), header CRC (u64); then the UTF-16 identifier (hex hash, or a shell path like `::{645FF040-...}`), padding, then image data (PNG seen; JPEG/BMP also occur).
- Entry size can exceed header + identifier + padding + data by a byte or more: always advance by the entry size field.
- Older layouts (from libwtcdb): Win8.0 (0x1E) first entry offset at byte 12; Win7 (0x15) entry header 48 bytes; Vista (0x14) 56 bytes with an 8-byte extension field before the identifier length.

**Privacy:** output goes to the chosen case folder, never a cloud-synced folder (simple guard now; full guard in Phase 2 Task 2). Thumbnails from this work PC go to `C:\PCPorterDev` only.

---

### Task 1: ThumbcacheParser (pure, test-first)
- `ThumbcacheParser.Parse(ReadOnlyMemory<byte> file, string fileName) -> ThumbcacheFile(Version, CacheType, Entries, EmptyEntries, Warnings)`; `ThumbcacheEntry(ulong CacheId, string Identifier, int Width, int Height, long Offset, int DataOffset, int DataLength, ImageFormat Format, bool Recovered)`.
- Walk entries from the first-entry offset by entry size. Validate each entry (signature, sizes fit, identifier length even and < 2 KB). On an invalid entry, resync by searching for the next `CMMM` and mark entries found that way, or located at/after the first-free offset, as `Recovered = true` (freed slots = deleted thumbnails).
- Format from magic bytes: `FF D8 FF` JPEG, `89 50 4E 47` PNG, `42 4D` BMP; otherwise Unknown (kept, flagged).
- Never throws on corrupt data (truncation => warning); throws `InvalidDataException` only when the file signature is wrong.
- Tests with a synthetic `ThumbcacheBuilder`: two entries PNG + JPEG; empty entry counted not listed; garbage gap => resync, Recovered; entry after first-free offset => Recovered; truncated last entry => warning; Win7 0x15 layout; bad signature throws. Plus a local-only test that parses this PC's own `thumbcache_256.db` and decodes every image (skipped if absent).

### Task 2: Search-index mapping (cache ID -> original path)
- Win11: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db` (SQLite). Discover the property ids for `System.ThumbnailCacheId` and `System.ItemPathDisplay` from the metadata table at runtime (schema checked elevated on this PC before coding), join on WorkId. Read through a read-only shared open; if the Search service holds an exclusive lock, read from a VSS snapshot (search database, not a registry hive).
- Win10: `Windows.edb` (ESE) via ManagedEsent on a copy - follow-up task once Win11 works.
- No index or no match => original path "unknown"; mapping failure never blocks the report.

### Task 3: ThumbnailCollector
- For each profile (live: `C:\Users\*`; admin needed for other users) read every `thumbcache_*.db` except `_idx` with `FileShare.ReadWrite | Delete` (Explorer keeps them open).
- Deduplicate by (CacheId, size class); write each image to `<case>\Thumbnails\thumbs\<cacheId>_<size>.<ext>`; keep the largest size as the "best" image per cache ID.
- Original path from Task 2; `OriginalExists` = file exists now; status Existing / Deleted / Unknown.
- Rows into case.db as artifacts (`Category = "Thumbnail"`, Subject = original path or cache ID, Detail = JSON).

### Task 4: Thumbnails.html
- Self-contained HTML + `thumbs\` folder; data embedded as JSON; no network.
- Summary tiles (total, deleted originals, recovered entries, per size class), filters (status, size class, source cache, user, text search on path), sort, lazy-loaded grid with windowed rendering, click for a detail panel (all sizes, path, cache ID, which cache files), dark/light mode, print stylesheet.
- Banner explaining what thumbnails prove and don't prove.

### Task 5: CLI + GUI
- `pcporter thumbs --out <folder> [--user <name>] [--json]` (elevation needed only for other users and the search index).
- "Explore my PC's history" tile -> pick output folder -> run with progress -> open the report.

### Task 6: Verify on this PC
- Run against this PC into `C:\PCPorterDev`; every extracted image decodes; counts per cache file match the parser's entry counts; open the report and check filters; nothing written outside the case folder.
