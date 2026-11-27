# Capability research: what else PCPorter should do (2026-11-27)

15 research agents compared PCPorter (built + designed) with commercial and leading tools in 15 areas. Claims are
mostly from vendor pages and snippets; items marked (U) were not confirmed. Ranked by value to the owner of a PC that
is being moved, reviewed or retired. Effort: S small, M medium, L large.

## Tier 1: high value, small/medium effort (do with the matching phase)
| # | Capability | Where it fits | Effort | Seen in / source |
|---|---|---|---|---|
| 1 | Verify the backup by re-reading it from the drive + a sample test restore; "N files NOT backed up" shown first, never plain "success" if anything was skipped | Backup | S | Macrium verify, restic `check --read-data`; File History silent-skip complaints |
| 2 | Failing disk: check SMART/read errors first; if failing, image the disk (ddrescue-style, good areas first, resumable map) and work from the image | Backup, dead-PC | M | GNU ddrescue, Disk Drill, R-Studio |
| 3 | Restore writes a WinGet Configuration file (apps + allowlisted settings via DSC v3 Registry resources) the user can rerun; `winget configure test` doubles as the post-restore check | Restore | M | learn.microsoft.com/windows/package-manager/winget/configure |
| 4 | Passkey inventory + "re-enroll before wiping" checklist (Windows Hello passkeys are TPM-bound, not exportable); authenticator-app backup warning | Passwords | M | Microsoft Entra passkey docs, Chrome help |
| 5 | "Move to a password manager" wizard: browser's own CSV export -> import into Bitwarden/1Password/Proton/KeePassXC -> secure-delete the CSV | Passwords | S | 1Password/Bitwarden import docs |
| 6 | Before-you-wipe checks that can be automated: BitLocker protector present (point to aka.ms/myrecoverykey), activation channel (OEM key cannot move), Office/AV/Adobe/iTunes seats from installed apps -> portal links, SSD vs HDD erase guidance (NIST 800-88 r2) | Wipe checklist | S | support.microsoft.com 4026181, NIST SP 800-88 r2 |
| 7 | Defender evidence: detections 1116/1117, real-time off 5001, config/exclusion changes 5007, MPLog, quarantine list; current exclusions, PUA, tamper, ASR, Controlled Folder Access | Health + Timeline | S | Defender event docs, KAPE WindowsDefender target |
| 8 | Remote-access tools: LOLRMM catalogue (Apache-2.0) vs services/apps/autoruns; AnyDesk/TeamViewer incoming-session logs ("someone was on this PC") | Health + Timeline | M | github.com/magicsword-io/LOLRMM, Synacktiv RAT forensics |
| 9 | Browser hijack checks: homepage, search engine, new-tab, startup URLs (Chromium Preferences, Firefox prefs.js), shortcut arguments | Health | M | FRST, AdwCleaner |
| 10 | Drive wear + hardware errors: Wear %, temperature, uncorrected read/write errors, power-on hours; WHEA and disk/NTFS error events (7, 51, 55, 129, 153) over 90 days; crash list with bugcheck code (event 1001) | Health | S | CrystalDiskInfo, HWiNFO, WhoCrashed |
| 11 | Commonly missed data to back up: Outlook signatures + AutoComplete, Sticky Notes (whole LocalState), OneNote local notebooks, Office custom dictionary + Normal.dotm, Notepad++ sessions, PowerToys backup, Terminal settings, WSL export, game saves | Backup rules | M | Microsoft support articles; Ludusavi |
| 12 | Game saves from the Ludusavi manifest (10k+ games; data licence CC BY-NC-SA (U), personal use OK) + Steam library re-link (copy `appmanifest_*.acf`) instead of re-download | Backup/Restore | M | github.com/mtkennerly/ludusavi-manifest |
| 13 | "Apps you no longer use" (UserAssist last-run) to untick on the reinstall review; ARM64 / silent-install availability from winget manifests | Restore review | S | Magnet UserAssist profile; winget manifest schema |
| 14 | USMT categories the design may miss: network drives, printers, fonts, personal certificates, EFS files, ODBC DSNs, VPN phonebooks (.pbk), accessibility, Public folders | Restore settings | M | learn.microsoft.com usmt-what-does-usmt-migrate |
| 15 | Detect Windows Backup / OneDrive Known Folder Move: say "restore Windows Backup in setup first", skip KFM folders and online-only placeholders | Backup/Restore | S | support.microsoft.com 5029967 |
| 16 | Start pins via Export-StartLayout (Pro+ can reapply via policy, Home gets a checklist) | Restore | S | learn.microsoft.com/windows/configuration/start/layout |
| 17 | Easy timeline sources: PowerShell PSReadLine history, Mark-of-the-Web download source per file (links to web history), Recycle Bin $I, WER crash reports, Office TrustRecords (macros enabled), Explorer search terms | Timeline | S | EZ tools RBCmd/RECmd (MIT), Velociraptor (reference only, AGPL) |
| 18 | Browser extras: extensions inventory with permissions, per-site permissions (notifications/camera/mic/location), Media History (videos watched, position), engagement scores | History | S | Hindsight blog posts |
| 19 | Compromise verdict as evidence tiers ("strong evidence / suspicious / nothing found in what we could see"), each finding with a plain sentence, benign explanation and the raw event; blind spots listed; never "clean" | Timeline | M | THOR scoring model; Sigma/Hayabusa rules (DRL 1.1) |
| 20 | Old-vs-new side-by-side (CPU, RAM, disk health, boot time from event 100, battery, OS support) with one verdict per red row; 90-day stability strip | Readiness | M | Reliability Monitor, PC Health Check |

## Tier 2: valuable, more effort
- PC-to-PC transfer over the network with a pairing code (the commercial suites' headline; Microsoft's own appears
  discontinued). Already in the design as Tier 2.
- Protect the backup from ransomware: write-once ACLs + read-only + "unplug the drive now" (no filter driver).
- Optional encryption of the backup (BitLocker To Go / container, so the plain mirror stays browsable).
- Incremental re-runs keeping old versions during the overlap weeks.
- Shadow-copy "time travel" for any file, exported to another drive, renamed on clash.
- Undelete view with an honest per-file status (intact / partly overwritten) and SSD TRIM warning ("likely zeroed").
- Text search in screenshots (Windows.Media.Ocr; may need package identity (U), Tesseract fallback) fed into case.db FTS.
- Photo map from EXIF GPS (offline tiles), HEIC/RAW via Windows codecs, Google Takeout sidecar dates, Lightroom
  catalog discovery (with `.lrcat-data` warning), near-duplicate cleanup before backup (Recycle Bin only).
- Find originals of deleted thumbnails in backups/restore points by visual fingerprint.
- Wider startup coverage: Winsock/LSA/print providers, AppInit, KnownDLLs, per-user COM hijacks, hidden scheduled tasks
  (TaskCache without SD); vulnerable-driver blocklist state (+ LOLDrivers, Apache-2.0); Secure Boot 2023 CA rollover.
- Device security detail: TPM, Secure Boot, BitLocker per volume, Credential Guard; Windows 11 upgrade blockers.
- Outdated apps vs winget's latest (skip CVE matching: CPE data too unreliable).
- Known-file filtering (slim NSRL / Authenticode) and file-type mismatch detection; "everything connected to this item"
  pivot across case.db once the timeline exists.
- Password health via Have I Been Pwned k-anonymity (5-char SHA-1 prefix, `Add-Padding: true`).
- Distribution: framework-dependent + Velopack installer and GitHub auto-update (much smaller than 232 MB); Azure
  Artifact Signing (~$120/yr, US/Canada individuals, mainly helps Smart App Control) or SignPath Foundation (free,
  needs a public OSI-licensed repo with CI); VirusTotal check + Defender false-positive submission per release;
  one-click redacted report for asking for help; local crash bundle; Windows Security-style status cards.

## Tier 3 / probably not
Moving apps as-is without an installer (where PCmover/PCTrans break most), universal image restore to new hardware,
WinPE rescue media (the dead-PC drive mode covers most of it), cached web page viewer, Local Storage/IndexedDB,
sync-device decoding, iPhone backup parsing, local photo search by description and face grouping (opt-in only).

## Deliberately not copied
Password cracking or decryption (BitLocker, encrypted backups, App-Bound Encryption, DPAPI scraping), bundling
NirSoft password tools (flagged as HackTool), cloud acquisition with harvested tokens, face recognition across people,
social graphs, NSFW/CSAM classifiers and law-enforcement hash sets, covert or remote collection, device unlocking.

## Decisions needed
1. Accounts inventory from `Login Data`: reading only `origin_url`/`signon_realm`/`date_last_used` (never
   `password_value`) and cookie host names (never values) would list sites with accounts. The current rule is "never
   open Login Data or Cookies". Keep the rule, or allow a guarded column-limited read (the history report's SQLite
   authorizer can enforce it)?
2. Code signing: paid Azure signing, or make the repo public and apply to SignPath Foundation.

## Licences for reuse
Bundle: Eric Zimmerman libraries and KapeFiles/RECmd maps (MIT), LOLRMM and LOLDrivers (Apache-2.0), Sigma /
hayabusa-rules (DRL 1.1, attribution), Plaso logic (Apache-2.0). Separate EXE or reference only: Hayabusa (AGPL-3.0),
Chainsaw/DeepBlueCLI/LOKI (GPL-3.0), Velociraptor (AGPL-3.0). Do not bundle: KAPE, Sysinternals, THOR, TDSSKiller,
PersistenceSniper (Commons Clause), Mackup rules (GPL-3.0; rewrite instead).
