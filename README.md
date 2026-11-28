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
  (`--offline D:\`, `--all-users`, `--json`), `PCPorter.exe selftest`. PCPorter.exe is a windowed program, so
  PowerShell does not wait for it: pipe it to `Out-String` to wait and see its output, then read the exit code, e.g.
  `.\PCPorter.exe scan --out E:\ | Out-String` then `$LASTEXITCODE` (0 ok, 1 partial, 2 failed, 3 bad arguments or a
  refused save folder, 4 not elevated, 5 findings with `--fail-on`, 6 cancelled).

Not built yet: backup and restore, activity timeline and saved-password reports. See
[docs/plans/2026-11-26-pcporter-design.md](docs/plans/2026-11-26-pcporter-design.md) for the full design and
[tasks/todo.md](tasks/todo.md) for progress.

## Build
Needs the .NET 10 SDK on Windows.

```powershell
dotnet build
.\scripts\regress.ps1                 # unit, golden-file and fixture tests (no admin needed)
```

Release (PowerShell 7):

```powershell
.\scripts\regress.ps1 -Level release  # publishes to C:\PCPorter-dist\PCPorter and smoke-tests that EXE (one-time setup:
                                      # scripts\regress\install-smoke-task.ps1 as administrator)
.\scripts\package.ps1                 # zips the dist folder (does not publish)
```

`package.ps1` only zips a build that passed the smoke run: the dist folder must hold exactly the published files,
and `C:\PCPorterCases\regress\smoke-last.json` must say ok, be newer than the EXE and record the same EXE SHA-256.
Otherwise it refuses. `-Publish` publishes first, but that build is untested and is zipped only with
`-AllowUntested`. Builds are stamped `0.1.0+<commit date>.<short commit hash>` (`.dirty` with uncommitted changes),
from `Directory.Build.props`.

Run `PCPorter.exe` as administrator to scan the PC it runs on. Results are written only to the folder you pick;
cloud-synced folders (OneDrive, Dropbox, Google Drive) are refused because reports contain private data.

## Safety rules the code follows
- Scans only read. They never read the SAM or SECURITY hives or saved Windows logon passwords.
- No bypass of browser password encryption.
- Secrets that show up in command lines are masked in every report and log.

## License
MIT. `tests/PCPorter.Collectors.Tests/Apps/TestData/winget-normalization` comes from
[microsoft/winget-cli](https://github.com/microsoft/winget-cli) (MIT); see the NOTICE file there.
