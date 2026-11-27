# PC Migrate & Forensic Report Tool ("PCPorter") - Design Plan

## Context
The user has a new PC and wants a single EXE that:
1. Backs up the old (personal, self-owned) PC to an external drive and rebuilds the new PC to look and work the same, **without carrying malware over**.
2. Finds the old PC's antivirus (name unknown) and gets it onto the new PC.
3. Produces separate HTML reports: full web history with breakdowns, thumbnail-cache image dump, full machine activity timeline as far back as logs go, and all recoverable saved passwords.

The project folder is empty (greenfield, not a git repo yet).

## Decisions (from Q&A)
| Topic | Decision |
|---|---|
| Ownership | Personal PC, owned by user |
| Restore mode | **Clean rebuild**: apps reinstalled fresh from official sources, then files and settings applied. No disk image, no hive copy |
| Browsers | Chrome, Edge, Firefox, IE/legacy Edge |
| Passwords | Every supported method; **plain-text passwords in the HTML report** (user's choice), behind a mandatory warning dialog, plus an encrypted vault copy |
| Forensic depth | Live data **plus deleted recovery** (SQLite freelist/WAL carving, Volume Shadow Copies, orphaned thumbnails) |
| Audience | Personal/family use: GPL tools may be bundled; code signing optional |
| Stack | **C# / .NET 10 LTS, WPF + WPF-UI (Fluent/Mica)**, single-file self-contained x64 EXE, `requireAdministrator` manifest, no compression in the bundle (fewer AV false positives) |

## Architecture
One EXE with three modes on the start screen: **Backup (old PC)**, **Restore (new PC)**, **Reports (either PC, or offline from a backup)**.

```
PCPorter.sln
  src/PCPorter.App          WPF shell, wizard pages, progress, dry-run preview
  src/PCPorter.Core         manifest, job engine, logging, VSS snapshot, resumable copier
  src/PCPorter.Collectors   one class per item (IBackupItem: Inventory/Backup/Preview/Restore/Undo)
  src/PCPorter.Forensics    browser, thumbcache, timeline, credential parsers -> SQLite evidence.db
  src/PCPorter.Reports      HTML generators (single self-contained .html each, data embedded as JSON)
  src/PCPorter.Security     vault (AES-256-GCM + Argon2id), hashing, Authenticode, scanning
  tests/*                   xUnit per project; fixture DBs/hives in tests/fixtures
```

Key libraries: ArxOne.AlphaVSS (snapshots), Microsoft.Data.Sqlite, Microsoft.Database.ManagedEsent (Windows.edb, WebCacheV01.dat, SRUM, DataStore.edb), EricZimmerman evtx and Registry (MIT), Konscious Argon2, System.Security.Cryptography.AesGcm, a small embedded JS table and timeline library for the reports.

### Backup container on the external drive
```
X:\PCPorter\<PCName>_<date>\
  manifest.json        every item: path, size, mtime, SHA-256, category, status
  inventory\           apps.json (winget export + Uninstall keys + Appx), av.json, drivers\ (optional)
  files\               user data (zstd chunks), resumable
  settings\            allowlisted registry exports + config files per category
  vault.pcpv           encrypted credentials (Argon2id + AES-256-GCM)
  evidence\evidence.db raw forensic copies + parsed SQLite
  reports\*.html       History, Thumbnails, Activity Timeline, Passwords, Migration, Security Audit
  quarantine\report.csv  excluded/suspicious items (hash, path, signature) - NOT restored
```

## Feature set (combined from the 10 research agents)

### A. Backup and restore (clean rebuild)
1. **Pre-flight scan**: disk sizes, user accounts, OS build, CPU arch (x64/ARM64), screen resolution/DPI, cloud-sync folders found, size estimate, time estimate.
2. **Selective tree**: pick users, folders, apps and settings categories; multiple users supported.
3. **VSS snapshot** so locked/open files copy consistently; resumable copier with retry, per-file SHA-256, incremental re-runs.
4. **App inventory and reinstall**: Uninstall keys (HKLM/WOW6432/HKCU) + Appx + `winget export` + choco/scoop. Match order: winget exact, then winget fuzzy (name + publisher), then choco/scoop, then manual vendor link. **Review screen** before installing; skip runtimes/redistributables. After install: first launch, then restore per-app settings from a rules file (like USMT MigApp.xml) with per-app AppData + HKCU\Software\<Vendor> paths.
5. **Settings restored from an allowlist**: wallpaper/theme/accent, desktop icon layout (warn if resolution differs), Explorer options, Quick Access, mouse/keyboard, scaling %, user fonts, mapped drives, env vars (merge, never overwrite PATH), power plans, region/language/keyboards, sound scheme, startup apps (only when the app is installed), non-Microsoft scheduled tasks, hosts (merge), built-in VPN, Wi-Fi, printers (printbrm or Get-Printer), Outlook PST + signatures (never OST), SSH keys, certificates (PFX), Steam/game libraries plus saves.
6. **Best-effort items with a manual checklist**: taskbar pins (generate TaskbarLayoutModification.xml), Start pins (start2.bin copy, fallback to a list), default apps (UCPD blocks writing them: open `ms-settings:defaultapps` with a checklist).
7. **Cloud folders** (OneDrive/Dropbox/Google Drive): never copy synced content or placeholders; record accounts and paths so the user signs in again.
8. **Licenses and deactivation**: Windows/legacy Office key decode, M365/Adobe/iTunes/plugin deactivation checklist run on the OLD PC before wiping, license report.
9. **Dry-run preview, restore journal, rollback**: system restore point + backup of everything overwritten, undone in reverse order.
10. **Final per-item success/fail report** (beats the silent partial failures competitors are criticized for).

### B. Antivirus carry-over
- Detect via `root\SecurityCenter2` (AntiVirus/Firewall/AntiSpyware), decode productState, confirm the signed exe exists, fall back to Uninstall keys + known service names (ekrn, vsserv, mfemms, avp, MBAMService, WRSVC...).
- Output **"Your AV is X"**: vendor portal link, how to deactivate the old device, official download link, and license hints (order emails search tip, in-app keycode location).
- Export Defender exclusions/preferences and Exploit Protection XML; reapply on the new PC.
- Never copy AV files (kernel drivers, tamper protection, licensing all break).

### C. Keep malware out
- Persistence audit of the old PC (Autoruns CSV, WMI subscriptions, IFEO, services, tasks, extensions), shown in Security Audit report.
- Exclude executables/scripts/macro docs/disk images from user data and list them in the quarantine report (user can opt specific signed files back in after Authenticode check).
- Defender `MpCmdRun -Scan -ScanType 3` on the backup folder from the NEW PC before restore; optional KVRT second opinion; VirusTotal **hash-only** lookup for flagged/unsigned files (free API rate limits).
- Browser extensions restored as store-link list only; flag sideloaded and over-permissioned extensions.

### D. Passwords and credentials (vault + plain-text HTML)
- **Chrome/Edge**: App-Bound Encryption (Chrome 127+) blocks safe third-party decryption, so the tool opens each browser's built-in **Export passwords** flow, picks up the CSV, moves it into the vault and deletes the temp file. (No ABE bypass: that is infostealer technique and EDR flags it.)
- **Firefox**: read logins.json + key4.db (works without a primary password; prompt if one is set) or use about:logins export.
- **IE/legacy Edge**: Windows `PasswordVault` (Web Credentials) for the current user.
- **Windows Credential Manager**: enumerate (CredEnumerate) for inventory + guided `.crd` Back up Credentials.
- **Wi-Fi** (`netsh wlan export key=clear`), RDP entries, BitLocker recovery keys (`manage-bde`), certificates (PFX), SSH keys, password manager detection (KeePass .kdbx location, Bitwarden/1Password noted).
- **Passwords.html**: site, username, password (plain text, per user's choice), source, created/last-used/changed dates, reuse and weak-password flags, plus "Why it can't move" notes for Windows Hello/PIN and passkeys. Mandatory warning dialog before writing it; the user can choose to keep it only inside the backup folder.
- Restore: write temp CSV, open the browser import page, delete the CSV; `netsh wlan add profile`; Credential Manager restore wizard; Import-PfxCertificate.

### E. Web history report (History.html)
Sources: Chromium History/Favicons/Top Sites/Shortcuts/Network Action Predictor/SNSS sessions; Firefox places/favicons/formhistory/sessionstore (mozlz4); IE WebCacheV01.dat (ESE). Read from VSS copies with WAL/journal files. Deleted rows recovered from freelist/WAL plus older shadow copies.
Breakdowns: summary per browser/profile, top domains/URLs, hour x weekday heatmap, daily timeline + trends, search terms, typed vs link vs bookmark vs redirect, address-bar typing, downloads (still on disk?), browsing sessions, dwell time, first/last seen, category classification (local list), referral chains, redirect/tracker domains, cross-browser comparison, open/closed tabs, **deleted/orphaned evidence** section, private-browsing traces (honestly limited), data coverage and retention notes (Chrome keeps 90 days).

### F. Thumbnail dump (Thumbnails.html)
- Parse every thumbcache_*.db / iconcache_*.db (CMMM/IMMM formats, version 0x20), Thumbs.db, and image files in Chrome/Edge/Firefox caches.
- Map cache IDs to original paths via Windows Search index (Windows.edb on Win10, Windows.db SQLite on Win11, `System_ThumbnailCacheId`).
- Gallery with filters: size class (96 = browsed, 1280+ = previewed full), **original still exists / deleted**, folder, source, date. Images extracted to `evidence\thumbs\` and referenced by the HTML.
- Reference implementations: Thumbcache Viewer (GPL, OK for personal use), libwtcdb spec.

### G. Activity timeline (Timeline.html)
- Sources: all EVTX (Security logons/locks, System boot/shutdown, installs, crashes, PowerShell, TaskScheduler, WLAN, Defender, USB/PnP, Windows Update, RDP), Prefetch, Amcache, Shimcache, BAM, SRUM (per-app network/CPU), UserAssist, RecentDocs/RunMRU/TypedPaths/WordWheel, ShellBags, LNK + Jump Lists, Recycle Bin, PSReadLine, ActivitiesCache.db, USB history + setupapi log, Wi-Fi history, installs, scheduled tasks, Recall (if present and readable). Older copies from every VSS snapshot.
- Uses Eric Zimmerman parsers (MIT) as libraries or bundled CLIs.
- One schema: ts_utc, type, source, artifact, user, action, subject, detail, confidence (proves it ran / proves it existed). Dedupe within 2 seconds; sessions bracketed by boot/logon/logoff.
- HTML: virtualized table + zoomable timeline, filters (date, user, category, confidence, free text), **coverage panel** showing earliest date per source, gaps flagged where logs rolled over.

### H. Extras from research
- Background run with ETA, pause/resume, sleep prevention.
- Logs to `PCPorter.log`; every report self-contained, works offline.
- Reports can be generated offline from a backup on any PC.
- x64 to ARM64 awareness (different installers, no driver restore).
- Drivers exported optionally, restored only on request (printers/scanners).

## Round 2 research: richness and professional finish

### I. Look and feel (WPF app)
- **WPF-UI 4.x (lepoco, MIT)**: Mica backdrop (solid fallback on Win10), Light/Dark/High-contrast following system accent, Win11 title bar, NavigationView, ContentDialog, Snackbar, InfoBar, Fluent icons.
- Left navigation rail per mode: Welcome > Scan > Select > Backup/Restore > Verify > Report, with done/active/error state per step; "Step 3 of 6" header; fixed Back/Next/Cancel.
- Dry-run TreeView with three-state checkboxes and sizes; live totals vs. target free space.
- Progress: MB/s, files done/total, moving-average ETA, Pause/Resume/Cancel, **taskbar progress**, toast on completion when minimized.
- Summary page: success/skipped/failed counts, filterable failures with reasons, **Retry failed**, Open report.
- Per-monitor DPI v2, full keyboard navigation, Narrator labels + live progress announcements, never color-only status. Segoe UI Variable type ramp. Custom multi-size app icon (PC + arrow + shield).

### J. Professional polish
- About dialog (version + git hash, build date, third-party notices); **Copy diagnostics** and **Open log folder** buttons.
- Serilog rolling logs (14 days) in `%LocalAppData%\PCPorter\logs`; global crash handler with friendly dialog (never raw stack trace).
- First-run onboarding + privacy notice ("everything stays on this PC, no telemetry"); F1 contextual help from embedded Markdown (Markdig).
- Settings JSON in `%AppData%` with atomic save; single-instance guard; UAC shield on admin-only buttons; sleep prevention during jobs.
- **Command-line / unattended mode** (System.CommandLine): `pcporter backup --dest E:\ --quiet`, `pcporter report --from E:\PCPorter\...`, documented exit codes (0 ok, 1 partial, 2 failed, 3 bad args, 4 not elevated).
- Optional scheduled recurring backups (TaskScheduler NuGet) - each run becomes a snapshot for comparison (see K).
- Update check against GitHub Releases (optional, off-able); "Remove all app data" + `--uninstall`.
- Splash screen; ReadyToRun; no trimming (WPF doesn't support it); **no single-file compression** (fewer AV false positives).

### K. Forensic workbench features (borrowed from AXIOM / Autopsy / Timeline Explorer / OSForensics)
1. **Case file**: one SQLite `case.db` per backup that can be reopened later; everything else builds on it.
2. Artifact **category sidebar with counts** (Web History 12,403 / Thumbnails 8,211 / Execution / USB / Logons...).
3. **Global keyword search** across all artifacts (SQLite FTS5).
4. **Unified timeline with pivot**: "show +/- N minutes around this item".
5. **Snapshot compare**: diff apps, files, settings, history between old and new PC, or between two dates. Standout feature for a migration tool.
6. Column filters, grouping, **saved filters**.
7. **Tags** (Bookmark / Important / Review) and notes on any item; "tagged-only" mini report export.
8. Export everywhere: CSV / XLSX / HTML / print-to-PDF, of the filtered view.
9. Evidence hashing manifest (SHA-256, tool version, host, UTC time) + **Verify case** button.
10. Summary dashboard: machine info, collection date, counts, top sites/apps.
11. File signature mismatch detection (~50 magic-byte types), e.g. a .jpg that is really an .exe.
12. Known-good noise reduction via Authenticode (hide validly-signed Microsoft/vendor files) instead of the multi-GB NSRL set.
- Skipped: relationship graphs (high effort, low value on one PC).

### L. Extra data sources (migrate and/or report)
| Source | Migrate | Report |
|---|---|---|
| Classic Outlook PST, signatures | Copy PST, re-attach; skip OST | Folder counts, message headers |
| New Outlook, Teams, Slack, Discord, WhatsApp, Signal | Sign in / re-link (DPAPI-bound, can't copy) | Parse caches on the OLD PC only (Teams LevelDB, Signal decrypt as owning user) |
| Thunderbird | Copy whole profile | mbox headers |
| Telegram `tdata` | Re-login preferred (folder = live session, treat as credential) | - |
| Sticky Notes (plum.sqlite), Notepad unsaved tabs (TabState), Office AutoRecover/UnsavedFiles, OneNote local | Copy (app closed / VSS) | Note text, deleted rows |
| Office MRU, VLC recents, VS Code recent workspaces, clipboard history (if on) | Office MRU re-imported with SID rewrite | Timeline entries |
| Screenshots, Zoom recordings, local music, iTunes library | Copy | - |
| Game saves (Saved Games, My Games, AppData, LocalLow), Steam `steamapps`/`userdata`, Epic manifests | Copy, then launcher "locate" | Installed games list |
| VS Code settings/extensions, .gitconfig, .ssh | Copy | - |
| iPhone backups (MobileSync) | Copy (opt-in, large) | Device name, iOS version, last backup date |
| Phone Link (phone.db: ~1 month SMS/contacts) | Re-pair | Report only |
- Rule: never copy DPAPI-wrapped keys expecting them to work; decrypt on the old PC for the report, re-authenticate on the new PC.

### M. PC comparison and health ("Readiness" report)
- Side-by-side Old vs New: CPU, cores, RAM, GPU (real VRAM from registry), disks (type, size, free), SMART wear/temperature (`Get-StorageReliabilityCounter`), battery health (`powercfg /batteryreport`), monitors (EDID, resolution, scaling), OS edition/build/activation, architecture, TPM 2.0, Secure Boot, BitLocker, devices with errors, reliability index, BSOD history, boot time. Green/amber/red per row.
- **Readiness score 0-100** (any blocker caps at 59): space 25, architecture 15 (x64 to ARM64 warnings), apps with an installer 25, edition features 15 (Pro to Home loses BitLocker/Hyper-V/RDP host), health 10, security 10.
- App availability table: winget / Store / manual-or-license per app.

### N. Photo and media extras
- EXIF/GPS/camera/date-taken via **MetadataExtractor** (Apache-2.0): gallery sort by date, camera column, Year/Month view.
- **Offline photo map**: Leaflet + Natural Earth (public domain) world map with marker clusters. No OSM tile downloading (policy bans it).
- Exact-duplicate finder (size, then hash) and top-N large-file finder: shown in pre-flight to shrink the backup; duplicates stored once.
- Own ~40-line **dHash** perceptual hash: match thumbcache entries to originals ("original confirmed deleted") and find near-duplicates.
- HEIC/RAW/video thumbnails via Windows Imaging Component + Shell (`IShellItemImageFactory`).
- **Carving** JPEG/PNG/BMP from free space inside thumbcache/iconcache files and older VSS copies: recovers thumbnails the index no longer lists.
- Face detection / NSFW classification: left out.

### O. Backup engine (hardened)
- **Format: plain mirrored folder + SQLite manifest/journal**, browsable in Explorer without the tool; optional per-file zstd (ZstdSharp, level 1-3), skipped for already-compressed types. No dedup repository (not worth it for a one-time migration).
- Pipeline: `FindFirstFileEx` large-fetch enumeration, 4-8 parallel readers, 1-2 sequential writers, 1-4 MB buffers; source is a VSS snapshot.
- Each file written as `.partial`, flushed, renamed, then committed to the journal (WAL) with size/mtime/xxHash3. Resume skips committed rows; pause on drive unplug and resume when it's back; quick or full verify pass.
- `BackupRead/BackupWrite` metadata sidecars (ACL as SDDL, ADS like Zone.Identifier); SID remap on restore (default: inherit target ACL, new user as owner); `\\?\` long paths; symlinks/junctions recorded never followed; hard links copied once; sparse files kept; OneDrive placeholders skipped (no hydration); EFS files copied raw with a certificate-export warning; timestamps set last.
- Target drive: refuse FAT32; exFAT allowed with sidecars; recommend NTFS. Free-space precheck +5% and re-check during run; warn on battery.

### P. Securing the tool itself
- DLL hijack protection: `SetDefaultDllDirectories(System32)`, `DefaultDllImportSearchPaths(System32)`, native libs bundled inside the EXE.
- Plaintext staging only in memory or a per-run ACL-restricted folder under `%LocalAppData%` with DeleteOnClose; never on the external drive "temporarily".
- Secrets as pinned `byte[]`/`char[]` wiped with `CryptographicOperations.ZeroMemory`; no SecureString.
- Vault: Argon2id via libsodium/NSec (m=256 MiB-1 GiB, t=3, p=4, ~1 s), chunked **XChaCha20-Poly1305 secretstream** (or chunked AES-GCM with index+final flag in AAD); zxcvbn passphrase meter (score 4 or 5+ words).
- **Plain-text Passwords.html safeguards** (user's choice kept): blocking warning with Cancel as default; check BitLocker on the target drive and offer to turn it on (`manage-bde -on X: -pw`); owner-only NTFS ACL on the file; no external resources; "delete after use" banner. Passwords excluded from print and from "tagged-only" exports unless opted in.
- Never touch LSASS/SAM; no browser injection; read `Login Data` copies by normal file copy only.
- Builds: deterministic, package lock file, pinned SDK (`global.json`), NuGet audit with vulnerable packages treated as errors.

### Q. HTML report engine (all reports share one template)
- Libraries inlined, no network: **ECharts** (custom build) for charts and heatmaps, **uPlot** for big time histograms, **Tabulator** for virtualized tables with filters + CSV/JSON/XLSX download, **sql.js** (SQLite in browser) only when a report exceeds ~500k rows, **fflate** + `DecompressionStream` for compressed embedded data.
- Layout: sticky header (host, generated UTC, tool version, data SHA-256, search, dark/light toggle) > **executive summary tiles** with sparklines > left table of contents with scroll-spy > each section = one-line finding, chart, table > appendix (method, source hashes, processing log, licenses).
- Timeline: histogram brush filters the virtualized table (no millions of items in vis-timeline).
- Gallery: WebP thumbnails in a sibling `report_files\thumbs\` folder, lazy-loaded with windowed rendering past 5k images.
- Print-to-PDF stylesheet, deep links in the URL hash (`#timeline?from=...&row=123`), global search grouped by section.

## Round 3: deeper features, UI and capabilities (tiered)
Tier 1 = high value / fits the core; Tier 2 = strong add-on; Tier 3 = stretch. Everything off-by-default if it changes the system or leaves the PC.

### R1. Migration capabilities
- **[T1] Dead-PC rescue mode**: old PC won't boot? Plug its drive into the new PC (USB enclosure), point the tool at that Windows volume. Offline hives, offline profile, offline logs; BitLocker unlock with recovery key. Same backup/report flow without booting the old Windows (also avoids running any malware on it).
- **[T1] Desktop "photo" for matching**: during backup, capture screenshots of the desktop, taskbar, Start menu and the open Explorer layout. On restore, show Old vs New side by side so manual items (Start pins, icon spots) are easy to match.
- **[T1] Post-restore "Did we miss anything?" checker**: re-scans the new PC, compares against the old inventory item by item (apps, settings, files, Wi-Fi, printers, fonts), green/red list with "Fix" or "Open setting" (ms-settings deep links) per row.
- **[T1] "Before you wipe the old PC" checklist**: deactivations done, browser exports done, vault opened successfully on the new PC, backup verified, then guidance for "Reset this PC > Remove everything > Clean drive".
- **[T2] Direct PC-to-PC over network/Ethernet cable**: no drive needed. Pair with a 6-digit code (PAKE key exchange, encrypted channel), stream straight into the restore pipeline, final delta sync while the old PC is still in use.
- **[T2] Old PC "time capsule" VM**: optional Disk2vhd-style VHDX of the old PC so it can be booted in Hyper-V on the new PC if something was missed. VM network disabled by default (malware isolation). Requires Pro/Enterprise for Hyper-V.
- **[T2] More environments**: WSL distros (`wsl --export`), Docker/Hyper-V VM lists, Python/Node/PowerShell global package lists, browser bookmarks + search engines + autofill addresses (no card numbers).
- **[T2] Express vs Custom mode**: Express picks safe defaults for everything (one-click); Custom shows the full tree.
- **[T3] Family mode**: several PCs backed up to one drive, each in its own folder, compared in one dashboard.

### R2. New forensic capabilities
- **[T1] NTFS change journal + MFT** (MFTECmd, MIT): $UsnJrnl gives file create/rename/delete events for recent weeks; $MFT gives every file record including **deleted files** with "recoverable?" status. Feeds the timeline and an **Undelete** view (also Recycle Bin and VSS copies).
- **[T1] Shadow copy "time travel"**: list every restore point, browse files as they were, restore old versions of deleted/changed files.
- **[T1] Download provenance**: read each file's Zone.Identifier stream (HostUrl, ReferrerUrl) and link it to the browser download record: "this file came from this site on this day".
- **[T1] USB device report**: every device with first/last connect, volume name and serial, plus the files opened from it (LNK/Jump List volume serial match).
- **[T1] Network report**: Wi-Fi networks first/last connected, data used per app per network (SRUM), RDP connections in and out, DNS cache, hosts file changes.
- **[T1] "Screen time" report**: per-app usage hours by day/week from SRUM + UserAssist focus time + Prefetch, shown as stacked charts.
- **[T1] "Was my old PC compromised?" verdict**: rule-based security findings with severity: cleared logs (1102/104), clock changes (4616), new admin accounts (4720/4732), failed-logon bursts, new services (7045), Defender detections, unsigned autoruns, suspicious PowerShell history. Optional **Hayabusa + Sigma rules** bundled (GPL, OK for personal use) and **YARA** scan of the backup with community rules.
- **[T1] Accounts inventory**: every site you have an account with, merged from saved passwords, cookie domain names (names/dates only, values never read), form history and login-page visits. Helps change passwords or close old accounts.
- **[T2] Password health**: weak (zxcvbn), reused, old, and an **opt-in breach check** with Have I Been Pwned's k-anonymity API (only the first 5 characters of a SHA-1 hash leave the PC).
- **[T2] Daily "story" journal**: a plain-English summary per day built from templates (no AI): "Booted 8:02. Chrome 3 h (mostly youtube.com). Plugged in SanDisk USB. Installed Zoom. Shut down 23:40."
- **[T2] Multi-year usage calendar**: GitHub-style heatmap of PC activity across all years of evidence, click a day to open that day in the timeline.
- **[T3] Ask your PC**: natural-language questions turned into case.db queries. Local-only by default; any cloud model use is opt-in and sends only the schema and the question, never the data.

### R3. Keep history from expiring (capability for the NEW PC)
- **[T1] History keeper**: optional scheduled task that archives browser history, event logs, SRUM and thumbcache into case.db every week, so Chrome's 90-day limit and log rollover no longer erase the past.
- **[T2] "Make this PC remember more"** (opt-in, reversible): bigger event logs (`wevtutil sl /ms`), audit policy for logon/lock and process creation with command line (4688), PowerShell script block logging, optionally Microsoft Sysmon with a community config. Shows exactly what will change and has an undo button.

### R4. UI improvements
- **[T1] Home screen with three big tiles**: "Move to my new PC", "Explore my PC's history", "Check my PC's health and security", plus recent cases.
- **[T1] Built-in report viewer**: reports open inside the app via WebView2 (preinstalled on Win11), with the app's sidebar, search and tags; still saved as standalone HTML.
- **[T1] Plain-English "What is this?"**: every artifact, category and finding has a one-line explanation and a "how sure are we" badge (proves it ran / proves it existed). Glossary page.
- **[T1] Live collection feed**: category cards that fill in with counts as data is found ("Found 3 browsers, 41,208 visits..."), so long scans feel alive.
- **[T2] Command palette (Ctrl+K)** in the app and the reports: jump to any section, artifact, setting or action.
- **[T2] Responsive reports** readable on a phone or tablet; compact/comfortable density toggle.
- **[T2] Restore assistant mode**: a checklist sidebar that stays on top while the user finishes manual steps (sign-ins, default apps), ticking items off as the checker detects them done.
- **[T3] Localization** (resx already in place) and custom accent themes.

### R5. Extensibility
- **[T2] Rules as data**: app-migration rules (paths + registry keys per app) and artifact definitions (path, parser, category) in JSON files, like USMT MigApp and KAPE targets. New apps/artifacts added without recompiling; user can add their own.

## Build phases
1. **Foundation**: git init, `docs/plans/2026-11-26-pcporter-design.md`, `tasks/todo.md`; solution skeleton; WPF-UI shell with navigation rail, logging, crash handler, settings, CLI parser; case.db schema; vault; VSS wrapper.
2. **Read-only scanners** (safe to run on any PC first): inventory, AV detection, PC health/readiness, persistence audit.
3. **Report engine + reports**: shared HTML template, then History, Timeline, Thumbnails (+ carving, dHash, EXIF, map), Passwords, Security Audit, Readiness.
4. **Workbench**: category sidebar, FTS search, tags/notes, saved filters, exports, snapshot compare.
5. **Backup engine**: mirrored copier, journal/resume, metadata sidecars, quarantine, Defender scan, extra data sources.
6. **Restore**: app matching + winget install, settings apply, dry-run, journal, rollback, final pass/fail report.
7. **Release**: single-file publish, FlaUI smoke test, optional Azure Artifact Signing, SBOM, release checklist.
Tier 1 items from Round 3 are built inside phases 2-6 where they belong (rescue mode in 2, MFT/USN/USB/network/screen-time/verdict in 3, home screen + viewer + explanations in 1/4, checker + wipe checklist in 6, history keeper in 6). 
8. **Tier 2** add-ons (network transfer, time-capsule VM, password health, story journal, calendar, forensic-readiness, command palette, rules-as-data).
9. **Tier 3** stretch (family mode, Ask your PC, localization).

## Verification
- **Fixtures**: generate our own on Hyper-V VMs with checkpoints (Playwright scripts browse known URLs in Chrome/Edge/Firefox, so tests assert exact URL lists); add small plaso test_data and Eric Zimmerman test files. GPL samples (EVTX-ATTACK-SAMPLES) stay local, not committed.
- **Unit + property tests** (xUnit + FsCheck) for every parser and timestamp converter (WebKit, PRTime, FILETIME); parsers must never throw unhandled, hang or over-allocate on truncated or corrupt input. Time-boxed **SharpFuzz** runs per parser before a release.
- **Golden-file tests** of HTML reports with Verify (timestamps/machine names scrubbed).
- **UI smoke tests** with FlaUI against the published EXE.
- **Cross-checks on this PC** (read-only modes only): counts compared with NirSoft BrowsingHistoryView, Thumbcache Viewer and Event Viewer.
- **Round trip** on two Win11 VMs: old VM seeded with apps, settings, browsers, chat apps, an EICAR test file; check EICAR is quarantined, apps reinstall, settings match, hashes verify, rollback works, and the 15 backup edge cases (long paths, >4 GB to exFAT, ADS, junction loops, hard links, OneDrive placeholders, EFS, sparse, locked PST via VSS, unplug mid-copy, power loss, disk full, different username/SID, timestamps/attributes, injected bit flip).
- Source files never modified (hash before/after); single-file EXE runs on a clean Win10 and Win11 VM with no .NET installed; Defender scan of the EXE is clean.