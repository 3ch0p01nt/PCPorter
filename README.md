# PCPorter

A Windows tool for moving to a new PC: it checks the old PC first, so you know what to bring over and what to leave
behind. One self-contained EXE (C# / .NET 10, WPF). Everything stays on the PC: no telemetry, no cloud.

## What works today
All read-only: nothing on the scanned PC is changed.

- **Health and security check** (`HealthReport.html`): antivirus, 21 Windows security settings, programs that start
  automatically (Authenticode-checked, with severity rules), installed apps with where to reinstall them (winget
  matching), disk, battery and crash health.
- **Dead-PC rescue:** scan an old PC's Windows drive connected to another PC, without booting it.
- **Images viewed** (`Thumbnails.html`): Explorer's thumbnail cache (including pictures whose originals were deleted),
  browser caches, screenshots and recently opened images, in an offline gallery.
- **Web history** (`History.html`): visits, searches, downloads, bookmarks, open tabs and form entries from
  Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi), Firefox and Internet Explorer / legacy Edge, including
  deleted visits recovered from the history files' free space and older visits from existing restore points
  (administrator). Saved passwords, cookies and payment cards are never read. Works on this PC or another PC's drive.
- Command line: `PCPorter.exe scan --out E:\`, `PCPorter.exe thumbs --out E:\`, `PCPorter.exe history --out E:\`
  (`--offline D:\`, `--all-users`, `--json`), `PCPorter.exe selftest`.

Not built yet: backup and restore, activity timeline and saved-password reports. See
[docs/plans/2026-11-26-pcporter-design.md](docs/plans/2026-11-26-pcporter-design.md) for the full design and
[tasks/todo.md](tasks/todo.md) for progress.

## Build
Needs the .NET 10 SDK on Windows.

```powershell
dotnet build
.\scripts\regress.ps1                 # unit, golden-file and fixture tests (no admin needed)
.\scripts\package.ps1                 # publishes the single-file EXE and builds the zip
```

Run `PCPorter.exe` as administrator to scan the PC it runs on. Results are written only to the folder you pick;
cloud-synced folders (OneDrive, Dropbox, Google Drive) are refused because reports contain private data.

## Safety rules the code follows
- Scans only read. They never read the SAM or SECURITY hives or saved Windows logon passwords.
- No bypass of browser password encryption.
- Secrets that show up in command lines are masked in every report and log.

## License
MIT. `tests/PCPorter.Collectors.Tests/Apps/TestData/winget-normalization` comes from
[microsoft/winget-cli](https://github.com/microsoft/winget-cli) (MIT); see the NOTICE file there.
