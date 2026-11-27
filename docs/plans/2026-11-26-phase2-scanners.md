# PCPorter Phase 2 (Read-only Scanners) Implementation Plan - v2

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> Every task: write the failing test, run it and see it fail, implement, see it pass, commit. Admin-only tests use `[AdminFact]` + `[Trait("Category","Admin")]` and run with an elevated `dotnet test --filter Category=Admin`.

**Goal:** `pcporter scan` (and the "Check health and security" tile) reads a Windows PC - this running PC, or a dead PC's drive - and records installed apps, antivirus, PC profile/health and startup-program findings in the case. Nothing on the scanned PC is changed, and the scan avoids anything that looks like credential theft to security software.

**Architecture:** Collectors read through `ISystemSource`, which exposes registry data as `IRegKey` and files through a mapped, root-guarded path API.
- **Live source** (this PC): reads the **live registry read-only** (`RegistryKey.OpenBaseKey`, `HKU\<sid>` for loaded users) and parses not-logged-on users' `NTUSER.DAT` **in memory**. No shadow copy, no hive copies on disk.
- **Offline source** (dead PC's drive): parses that drive's hives **in memory** with the `Registry` package; transaction logs replayed in memory.
- A **contract test suite** runs the same assertions against the fake registry, real hives built with `offreg.dll`, and the live registry, so all three behave identically.
- Results go into **typed tables in case.db** (one database per case, many scans); JSON files are exports.

**Tech Stack:** Phase 1 stack + `Registry` 2026.10.1 (EZ, MIT), `Lnk` (EZ, MIT, binary .lnk parsing), `System.Management` (WMI, with per-query timeouts), `Microsoft.Windows.CsWin32` (WinTrust/catalog/offreg/display P/Invoke), WinRT `PackageManager` + `StorageProviderSyncRootManager`, WinGet COM API (`Microsoft.Management.Deployment`) with `winget export` fallback.

Design: `docs/plans/2026-11-26-pcporter-design.md` (A.1, A.4, B, C, M, P, R1).

---

## What the 10-agent review changed

| Area | Finding (verified ones marked V) | Decision |
|---|---|---|
| Security | Copying SYSTEM/SOFTWARE out of VSS = credential-dumping pattern (T1003.002); EDR alert on the work PC | Live = live registry read-only; offline = in-memory parse; **no hive file copies**; VSS only in `selftest` |
| Security | `Hive.Sam` in the enum; SAM/SECURITY must never be touched | Enum is `Software, System, NtUser, UsrClass`; reader refuses any other file name (tested) |
| Security | CLI logs every argument (V: `App.xaml.cs`); BitLocker key on a command line is captured by EDR | Log the command name only; unlock via WMI `UnlockWithNumericalPassword` in-process |
| Security | Elevated process starting `winget` from user-writable WindowsApps = privilege escalation | System tools by full System32 path; WinGet via COM API, `winget.exe` only non-elevated |
| Security | CaseLocation bypasses (junctions, UNC, subst, KFM, "Dropbox (Contoso)"); `C:\PCPorterDev` inherits Users:Modify | Real-path resolution + sync-root API + protected DACL on case folders |
| Security | DLL search hardening from design P missing in `OnStartup` | Added in Task 1 |
| Correctness | `VssSnapshotProvider.Map` builds `device\D:\...` for other volumes (V: `GetRelativePath` returns cross-volume paths unchanged) | Throws for paths outside the snapshot volume (Task 1) |
| Correctness | Registry package: binary = hex text, MULTI_SZ joined with spaces, DWORD=uint | All getters decode `ValueDataRaw` + data type |
| Correctness | Win11 registry `ProductName` says "Windows 10" (V on this PC: "Windows 10 Enterprise", build 26200) | Build >= 22000 => Windows 11 |
| Correctness | Defender WSC path is `windowsdefender://`, displayName "Windows Defender" (V on this PC) | Special-cased; Defender mode from `AMRunningMode` |
| Correctness | .NET recursion follows junctions out of the source into the host's C: | Shared enumeration options skip reparse points + root guard on every open |
| Correctness | Skipping the `\Microsoft\` task tree hides malware (Tarrask); svchost services need `ServiceDll`; LOLBin hosts hide the real payload | Rules rewritten (Task 7) |
| Data model | No scan ids, no migrations, tags break on rescan | Schema v2: `scans`, `collector_runs`, typed tables, stable `item_key` |
| Tests | Fakes would mirror assumptions; `offreg.dll` exists (V: 10.0.26100) | Contract tests over fake + offreg-built + live registry |
| Tests | Tasks too big | Split into 4a/4b/4c, 5a/5b, 7a-7d, 8a-8c, 11a-11c |
| UX | Users would read "High" as "infected" | "Worth a look / Unusual / Normal", fixed "flagged does not mean harmful" banner |

---

### Task 1: Hardening and housekeeping

**Files:** `.gitattributes`; `src/PCPorter.App/App.xaml.cs`; `src/PCPorter.Core/Snapshots/VssSnapshotProvider.cs`; new `tests/PCPorter.TestKit` (shared `AdminFactAttribute`, later fixtures); `src/PCPorter.Core/Cli/SelfTest.cs`; `src/PCPorter.Core/Security/Redactor.cs`; tests in Core.Tests.

1. `.gitattributes`:
   ```
   * text=auto eol=crlf
   *.sh text eol=lf
   *.png *.db *.hive *.dat *.LOG1 *.LOG2 *.lnk *.evtx binary
   tests/fixtures/** -text
   ```
   `git add --renormalize .`; commit.
2. **Map bug:** test `Map(@"D:\x")` on a C:\ snapshot throws `ArgumentException`; fix `Map` to require the path to be under `volumeRoot` (case-insensitive, folder boundary).
3. **DLL hardening:** first line of `OnStartup`: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)` and `SetDllDirectory("")` (DllImport with `DefaultDllImportSearchPaths(System32)`).
4. **No secrets in logs:** CLI log line becomes `Log.Information("CLI command {Command} exited {Code}", e.Args[0], code)`.
5. **Redactor** (pure, TDD): masks values after `password=`, `pwd=`, `token=`, `sig=`, `key=`, `secret=`, `Authorization: Bearer`, URL user-info (`https://user:pass@`), and 48-digit BitLocker keys -> `***`. Keeps `-enc <base64>` (evidence). Tests for each pattern + an unchanged benign command.
6. Move `AdminFactAttribute` into `PCPorter.TestKit` and add `[Trait("Category","Admin")]` usage docs in `tests/README.md`.
7. **`selftest`**: SQLite FTS5, vault round-trip, one WMI query (`Win32_OperatingSystem.Caption`, 15 s timeout), and - elevated only - a VSS snapshot that opens `C:\Windows\win.ini` (a harmless file, not a hive). Prints PASS/FAIL/SKIP; exit Ok/Failed. Test: not elevated => Ok with VSS SKIP.

Commit `chore: hardening, redactor, selftest, Map volume check`.

---

### Task 2: Case location guard v2 and protected case folders

**Files:** `src/PCPorter.Core/Case/CaseLocation.cs`, `Case/CaseFolder.cs`, `Case/ISyncRootProvider.cs`; tests `Case/CaseLocationTests.cs`, `Case/CaseFolderTests.cs`

`CaseLocation.Check(path, ISyncRootProvider)`:
1. Reject `\\` and `\\?\UNC\` and `GLOBALROOT` paths, and drive letters whose `DriveInfo.DriveType == Network` or that are `subst` drives (`QueryDosDevice` result starts with `\??\`).
2. Resolve the **nearest existing ancestor** with `GetFinalPathNameByHandle` (follows junctions/symlinks), append the not-yet-existing remainder.
3. Reject if under any sync root: `StorageProviderSyncRootManager.GetCurrentSyncRoots()` paths, every `HKU\*\Software\Microsoft\OneDrive\Accounts\*\UserFolder`, `%OneDrive*%` env vars, and folder names matching `^(Dropbox|Google Drive|iCloudDrive|Box)( \(.+\))?$`.
4. Returns `CaseLocationResult(IsAllowed, Reason)` with a plain-English reason.

Tests (fake `ISyncRootProvider`): OneDrive root and child rejected; `Dropbox (Contoso)` rejected; prefix-not-boundary allowed; UNC rejected; a junction (created in a temp dir with `mklink /J` via `Directory.CreateSymbolicLink` fallback) pointing into a fake sync root rejected; `E:\PCPorter` allowed.

`CaseFolder.Create(root)`: re-checks `CaseLocation` immediately before creating; refuses an existing folder that is a reparse point or has a non-admin owner; creates `<root>\PCPorter\<Computer>_<yyyyMMddTHHmmZ>_<id6>\` with a **protected DACL** (SYSTEM + Administrators full, inheritance off); warns (does not fail) on exFAT/FAT32 ("this drive can't restrict access to the files"). `CaseFolder.Open(existing)` for adding a scan to an existing case.

Commit `feat(core): case location guard v2 and protected case folders`.

---

### Task 3: Case database schema v2 with migrations

**Files:** `src/PCPorter.Core/Case/CaseDb.cs` (+ `Case/Migrations.cs`), records in `Case/ScanRecords.cs`; tests `Case/CaseDbMigrationTests.cs`

- `user_version` 2. Ordered `MigrateTo(n)` steps run in a transaction; opening a case with a **newer** version throws `CaseTooNewException("This case was made by a newer PCPorter")`. Test: a v1 file (built with the Phase 1 code path) upgrades to v2 and keeps its artifacts.
- New tables:
  - `case_meta(key PRIMARY KEY, value)`
  - `scans(scan_id TEXT PK, started_utc, finished_utc, status, tool_version, git_hash, source_mode /*live|offline*/, machine_id /*SOFTWARE\Microsoft\Cryptography\MachineGuid*/, computer_name, os_build, volume)`
  - `collector_runs(scan_id, collector, status /*ok|partial|failed|skipped_offline|cancelled|timed_out*/, items, ms, error_code, message)`
  - `apps(scan_id, item_key, json)`, `av_products(scan_id, item_key, json)`, `persistence_items(scan_id, item_key, rule_id, severity, json)`, `profile(scan_id, json)`
  - `artifacts` gains `scan_id`, `item_key`; `tags` re-keyed to `(item_key, category, tag)` so tags survive rescans.
- **Stable `item_key`** (pure function, tested): app = lower(normalized name) + publisher + scope + arch; AV = catalog vendor id; persistence = location + name + SHA-256(normalized command).
- `CaseDb.ExportJson(scanId, kind, path)` writes `{schemaVersion, kind, scanId, toolVersion, generatedUtc, source:{mode, machineId, computerName, osBuild}, items:[...]}`.

Commit `feat(core): case schema v2 with scans, collector runs and typed result tables`.

---

### Task 4a: Registry abstraction, raw value decoding, contract tests

**Files:** new `src/PCPorter.Collectors` (classlib, `net10.0-windows10.0.19041.0`, refs Core) and `tests/PCPorter.Collectors.Tests` (refs Collectors, TestKit). `Sources/IRegKey.cs`, `Sources/RegValueDecoder.cs`, TestKit `FakeRegistry.cs`, tests `Sources/RegKeyContractTests.cs`.

```csharp
public enum Hive { Software, System, NtUser, UsrClass }   // SAM/SECURITY intentionally absent

public enum RegType { None, String, ExpandString, Binary, DWord, MultiString, QWord, Other }

public interface IRegKey
{
    string Name { get; }
    DateTimeOffset? LastWrite { get; }
    IEnumerable<IRegKey> SubKeys { get; }
    IEnumerable<string> ValueNames { get; }          // includes "" for the default value
    IRegKey? Open(string relativePath);              // case-insensitive, no hive name in the path
    (RegType Type, byte[] Raw)? GetRaw(string valueName);
}

public static class RegKeyExtensions                  // all decoding lives here, shared by every implementation
{
    public static string? GetString(this IRegKey k, string name) => RegValueDecoder.AsString(k.GetRaw(name));
    public static long? GetNumber(this IRegKey k, string name) => RegValueDecoder.AsNumber(k.GetRaw(name));
    public static IReadOnlyList<string>? GetMulti(this IRegKey k, string name) => RegValueDecoder.AsMulti(k.GetRaw(name));
}
```
`RegValueDecoder` rules (each tested): String/ExpandString = UTF-16LE up to first NUL (ExpandString **not** expanded); MultiString = split on NUL, drop empties; DWord = `uint` from 4 bytes, QWord = `ulong` from 8 bytes; **a String containing digits is accepted by `AsNumber`** (real Uninstall keys store `SystemComponent` as text); wrong-length data => null, never throws.

`RegKeyContractTests` is abstract with a `protected abstract IRegKey Build(RegSpec spec)`; subclasses: `FakeRegKeyContract` (4a), `ParsedRegKeyContract` (4b), `LiveRegKeyContract` (4b, writes the spec under `HKCU\Software\PCPorterTest\<guid>`, deletes it after). Cases: nested open, case-insensitive names, default value, MULTI_SZ, QWORD, ExpandString kept raw, numeric string, missing key => null.

Commit `feat(collectors): IRegKey with shared value decoding and contract tests`.

---

### Task 4b: Hive readers (offline in-memory, live read-only) and offreg fixtures

**Files:** TestKit `OffregHiveBuilder.cs` (P/Invoke `offreg.dll`: `ORCreateHive`, `ORCreateKey`, `ORSetValue`, `ORSaveHive`, `ORCloseKey`, `ORCloseHive`; builds a real hive file from a `RegSpec` without admin); `Sources/ParsedRegKey.cs`, `Sources/HiveParser.cs`, `Sources/LiveRegKey.cs`.

- `HiveParser.Parse(string hivePath, ILogger) -> ParsedHive`:
  - Refuses any file name other than `SOFTWARE`, `SYSTEM`, `NTUSER.DAT`, `UsrClass.dat` (test: `SAM`, `SECURITY` throw).
  - Size limit 1 GB; reads bytes with `FileShare.ReadWrite` (offline volume: no lock), **never writes a copy to disk**.
  - Dirty hive (primary != secondary sequence number) and `.LOG1/.LOG2` present: `ProcessTransactionLogs(logs, true)` in a try/catch; records `Dirty`, `Replayed`. `RecoverDeleted = false`.
  - Parser exceptions (incl. missing root -> `KeyNotFoundException`) => `ParsedHive.Corrupt` with reason; the scan reports that hive as unreadable and continues.
  - Routes the package's Serilog output to the case log at Warning.
- `ParsedRegKey : IRegKey` maps `RegistryKey` (`KeyName`, `LastWriteTime`, `SubKeys`, `Values[].ValueName/ValueDataRaw/VkRecord.DataType`).
- `LiveRegKey : IRegKey` wraps `Microsoft.Win32.RegistryKey` opened **read-only** from `RegistryKey.OpenBaseKey(LocalMachine/Users, RegistryView.Registry64)`; raw bytes via `RegQueryValueEx` (CsWin32) so types and raw data match the offline path; `LastWrite` via `RegQueryInfoKey`.
- Tests: contract suite passes for `ParsedRegKey` (hives built with `OffregHiveBuilder`) and `LiveRegKey`; corrupt file => Corrupt not throw; 1 EZ Registry test hive (MIT, check for personal data, record in `tests/fixtures/THIRD-PARTY.md`) for dirty-log replay.

Commit `feat(collectors): in-memory offline hive parser and live read-only registry adapter`.

---

### Task 4c: System sources

**Files:** `Sources/ISystemSource.cs`, `Sources/OfflineSource.cs`, `Sources/LiveSource.cs`, `Sources/SourcePaths.cs`, `Sources/IWmiClient.cs` + `WmiClient.cs`, `Sources/IProcessRunner.cs` + `ProcessRunner.cs`; tests `Sources/SourcePathsTests.cs`, `Sources/OfflineSourceTests.cs`, `Sources/LiveSourceTests.cs` (Admin)

```csharp
public sealed record UserProfile(string Sid, string UserName, string? ProfilePath, string? Unavailable);

public interface ISystemSource : IDisposable
{
    bool IsLive { get; }
    string ReadRoot { get; }                 // "D:\" offline; "C:\" live
    string OriginalSystemDrive { get; }      // from SOFTWARE\...\Windows NT\CurrentVersion\SystemRoot, e.g. "C:"
    string? MapPath(string pathFromScannedPc);   // expands %SystemDrive%/%SystemRoot%/%ProgramData%/%windir% using the SCANNED PC's values; null if on another volume
    IRegKey? OpenHive(Hive hive, UserProfile? user = null);   // null + logged reason if missing/locked/corrupt
    string? CurrentControlSet();              // SYSTEM\Select\Current -> "ControlSet00N"; fallback Default, then ControlSet001
    IReadOnlyList<UserProfile> Users { get; }
    IEnumerable<string> EnumerateFiles(string mappedDir, string pattern, bool recursive);   // skips reparse points; root-guarded
}
```

- `SourcePaths.Map(path, originalSystemDrive, readRoot, envFromScannedPc)` is pure and tested: `%SystemDrive%\Users\bob` -> `D:\Users\bob`; `c:\windows\x` -> `D:\windows\x`; `E:\Data\x` -> null; quoted paths and arguments handled by the command parser in Task 7, not here.
- **Root guard:** every file open goes through `SourceFile.OpenRead(mappedPath)`, which throws if the resolved final path is outside `ReadRoot`. Enumeration uses `EnumerationOptions { RecurseSubdirectories, AttributesToSkip = ReparsePoint, IgnoreInaccessible = true }`.
- **Users:** ProfileList entries with SIDs `S-1-5-21-*` or `S-1-12-1-*`; skip `.bak` twins; `UserName` = profile folder name; profiles on another volume => `Unavailable = "profile is on another drive"`.
- **OfflineSource(readRoot)**: validates `Windows\System32\config\SOFTWARE`; refuses the running Windows volume; device paths accepted (always with trailing `\`; never passed to `GetFullPath`/`DriveInfo`); hives parsed once and cached (`Lazy<ParsedHive>` per hive/user), disposed with the source.
- **LiveSource**: `OpenHive(Software/System)` -> `LiveRegKey(HKLM\...)`; `OpenHive(NtUser, user)` -> `LiveRegKey(HKU\<sid>)` if loaded, else in-memory parse of `<profile>\NTUSER.DAT` (not locked when the user is signed out; if locked and not loaded, null + reason). UsrClass likewise via `HKU\<sid>_Classes`.
- **IWmiClient.Query(ns, wql, timeout)** returns `IReadOnlyList<IReadOnlyDictionary<string, object?>>`; implementation uses `EnumerationOptions { Timeout, ReturnImmediately = true, Rewindable = false }` on a dedicated thread with `WaitAsync(timeout)`; outcomes `Ok | InvalidNamespace | AccessDenied | TimedOut | Error`. Default 15 s, 45 s for licensing/stability.
- **IProcessRunner** runs only absolute paths under `%SystemRoot%\System32` (powercfg) with working dir System32 and a timeout; any other path throws.
- Tests: offline source over an offreg-built mini Windows tree in a temp folder (SOFTWARE/SYSTEM/NTUSER hives + folders): users, CurrentControlSet, MapPath, reparse point skipped (create a junction pointing outside: not followed), refusing the running Windows drive.

Commit `feat(collectors): live and offline system sources with path mapping and root guard`.

---

### Task 5a: App inventory from the registry

**Files:** `Apps/InstalledApp.cs`, `Apps/AppInventoryCollector.cs`, `Apps/AppNameNormalizer.cs`; tests

```csharp
public enum AppKind { Win32, Store, Runtime, Driver, Game, Portable }
public sealed record InstalledApp(
    string ItemKey, string Name, string? Version, string? Publisher, string Architecture /*x64|x86|arm64|neutral*/,
    DateOnly? InstallDate, bool InstallDateInferred, string Scope /*Machine | User:<name>*/,
    AppKind Kind, bool Hidden, bool ReinstallCandidate,
    string? ProductCode, string? UpgradeCode, bool WindowsInstaller, string? InstallLocation,
    string? UninstallString, string? QuietUninstallString, string? HelpLink, string? UrlInfoAbout,
    string? WingetId, string? WingetSource, string? ChocoId, string? ScoopId, string? PackageFamilyName,
    string? MatchMethod, string SourceKey);
```
Rules (one test each, FakeRegistry):
1. Read `Microsoft\Windows\CurrentVersion\Uninstall` and `WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (paths relative to SOFTWARE; arch x64/x86), and per user NTUSER `Software\Microsoft\...\Uninstall` + `Software\WOW6432Node\...\Uninstall`.
2. No `DisplayName` => skip. `SystemComponent=1` (numeric **or string**) or `ParentKeyName` set => **kept** with `Hidden = true, ReinstallCandidate = false` (Burn bundle children grouped under their parent). `ReleaseType` in {Update, Hotfix, Security Update} => skip.
3. Dedup on (key name, scope, arch) - **not** name+version (x86 and x64 Python both kept).
4. `InstallDate` `yyyyMMdd`; invalid => key `LastWrite` date with `InstallDateInferred = true`.
5. Kind=Runtime regexes (tested individually): VC++ redistributables, `.NET (Runtime|Desktop Runtime|Windows Desktop Runtime)`, `ASP.NET Core`, `Windows Desktop Runtime`, `DirectX`, `Edge WebView2`, `Microsoft Edge( Update)?`, `Update Health Tools`, `GameInput`. Kind=Driver: `^(NVIDIA|AMD|Realtek|Intel\(R\)).*(Driver|Graphics|Audio|Chipset|Management Engine)`. Kind=Game: name `^Steam App \d+$` or InstallLocation under a Steam/Epic library. Runtime/Driver => `ReinstallCandidate = false`.
6. `ProductCode` = key name when it is a GUID; `WindowsInstaller=1` noted.
7. `AppNameNormalizer` (tested): strips `(x64)`, `(64-bit)`, ` - en-us`, trailing version tokens, `®`/`™`, collapses whitespace, lower-case.

Commit `feat(collectors): registry app inventory with hidden/runtime/driver classification`.

---

### Task 5b: Extra app sources and winget matching

**Files:** `Apps/WingetMatcher.cs`, `Apps/AppxInventory.cs`, `Apps/PackageManagersInventory.cs`, `Apps/GameLibraries.cs`, `Apps/PortableAppFinder.cs`; tests with fixture files

- **Winget (live):** WinGet COM API (`Microsoft.Management.Deployment` PackageManager, installed catalog composite with `winget` source) to map Uninstall entries to package ids - join on ProductCode first, then normalized name + publisher. Fallback when COM is unavailable: run `winget export --source winget -o <tmp> --include-versions --disable-interactivity` **non-elevated** (via `CreateProcessAsUser` with the linked token, or skipped with a reason) **without** `--accept-source-agreements`; ids starting `ARP\` = no match. Record `MatchMethod` (ProductCode | NameMatch | ExportFallback | None). Note in the summary when the elevated account differs from the signed-in user.
- **Store apps:** live `PackageManager.FindPackagesForUser("")` minus framework/resource/system-signed, flagging packages that are also provisioned as "came with Windows" (`ReinstallCandidate = false`). Offline: open `ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd` (+ `-wal`/`-shm`) **read-only in memory** via `Microsoft.Data.Sqlite` `Mode=ReadOnly;Immutable` from a byte buffer copied to a `MemoryStream`-backed temp in the protected work folder only if SQLite needs a file (deleted on close); best-effort, schema-tolerant (missing table => skipped with reason).
- **Chocolatey/Scoop (both modes):** `ProgramData\chocolatey\lib\*\*.nuspec` (id, version); each user's `scoop\apps\*\current\manifest.json` + bucket.
- **Games:** Steam `libraryfolders.vdf` + `steamapps\appmanifest_*.acf` (VDF parser, fixture-tested); Epic `ProgramData\Epic\EpicGamesLauncher\Data\Manifests\*.item` (JSON). Kind=Game, reinstall via launcher.
- **Portable:** Start Menu (all users + per user) and Desktop `.lnk` files parsed **binary** with the `Lnk` package (never `IShellLink::Resolve`); a target `.exe` not under any app's `InstallLocation`, Program Files or Windows => `Kind = Portable`, note "copy this folder".
- Deferred to Phase 3 (browser parsers live there): browser extension list.

Commit `feat(collectors): winget matching, store apps, package managers, games, portable apps`.

---

### Task 6: Antivirus detection v2

**Files:** `Security/ProductState.cs`, `Security/AvDetector.cs`, `Security/av-vendors.json`; tests

**ProductState (pure):**
```csharp
public enum WscState { Off, On, Snoozed, Expired, Unknown }
public sealed record ProductStatus(WscState State, bool UpToDate, bool IsMicrosoft);
public static class ProductState
{
    // Undocumented community layout of WSC productState: 0x00F000 state, 0x000F00 owner (0x100 = Windows), 0x0000F0 signatures (0x00 = up to date)
    public static ProductStatus Decode(uint s) => new(
        ((s >> 12) & 0xF) switch { 0 => WscState.Off, 1 => WscState.On, 2 => WscState.Snoozed, 3 => WscState.Expired, _ => WscState.Unknown },
        (s & 0xF0) == 0, (s & 0x0F00) == 0x100);
}
```
Tests: 266240 On/up-to-date/3rd-party; 397568 On/up-to-date/Microsoft (V on this PC); 397584 On/out-of-date; 262160 Off/out-of-date; 393472 Off; 0x52000 Snoozed; 0x53000 Expired.

**Detection:**
1. Live: WSC via WMI `root\SecurityCenter2` (AntiVirus/AntiSpyware/Firewall). `Confirmed` when the expanded `pathToSignedProductExe` exists, **or** it is `windowsdefender://` and service `WinDefend` exists. Store `timestamp` as a staleness hint.
2. Both modes: catalog `displayNamePatterns` vs Task 5a apps; `serviceNames` **regexes** vs `SYSTEM\<CurrentControlSet>\Services`. `WinDefend` presence is never evidence (it exists on every PC).
3. Defender status (live): `root\Microsoft\Windows\Defender:MSFT_MpComputerStatus.AMRunningMode` (`Normal` => active; `Passive`/`EDR Block Mode` noted; else not running) + `RealTimeProtectionEnabled`; wrapped in try/catch.
4. Defender exclusions: **skipped by default on domain- or Entra/Intune-joined PCs** (`Win32_ComputerSystem.PartOfDomain`, `HKLM\SOFTWARE\Microsoft\Enrollments` with a UPN) unless `--include-defender-prefs`; offline from `SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes}`.

**Catalog** (`av-vendors.json`; URLs must each be opened and checked before commit):
| Vendor | Name pattern | Services (regex) | Account URL |
|---|---|---|---|
| Microsoft Defender | `^(Windows|Microsoft) Defender` | (WSC/MpComputerStatus only) | - |
| Norton | `Norton` | `^(NortonSvc|N360|NortonSecurity)$` (verify in VM) | my.norton.com |
| McAfee | `McAfee` | `^(mfemms|mfevtp|mfefire|McAPExe|ModuleCoreService)$` | home.mcafee.com |
| Bitdefender | `Bitdefender` | `^(VSSERV|bdredline)$` | central.bitdefender.com |
| Kaspersky | `Kaspersky` | `^AVP\d+(\.\d+)*$` | my.kaspersky.com (note: US sales ended 2024) |
| UltraAV | `UltraAV` | (find in VM) | (verify) |
| ESET | `ESET` | `^ekrn$` | home.eset.com |
| Avast | `Avast` | `^(avast! Antivirus|AvastWscReporter)$` | id.avast.com |
| AVG | `AVG` | `^(AVG Antivirus|AVGWscReporter)$` | id.avg.com |
| Malwarebytes | `Malwarebytes` | `^MBAMService$` | my.malwarebytes.com (Free does not register in WSC) |
| Webroot | `Webroot` | `^(WRSVC|WRCoreService)$` | my.webrootanywhere.com |
| Trend Micro | `Trend Micro` | `^Amsp$` | account.trendmicro.com |
| Sophos Home | `Sophos Home` | `^(Sophos MCS Agent|Sophos Health Service|hmpalertsvc)$` (verify in VM) | home.sophos.com |

Tests: Defender `windowsdefender://` Confirmed; stale WSC exe => Unconfirmed; Kaspersky via `AVP21.3`; ESET via `ekrn` only; Malwarebytes via service only; Expired third-party AV reported as "license expired"; exclusions skipped on a domain-joined fake.

Commit `feat(collectors): antivirus detection v2`.

---

### Task 7a: Persistence rules (pure)

**Files:** `Security/PersistenceItem.cs`, `Security/CommandLine.cs`, `Security/PersistenceRules.cs`; tests

- `CommandLine.Parse(string)` (tested): quoted and unquoted image paths (unquoted with spaces: longest existing prefix, else first token + `UnquotedPath` flag), arguments, env vars left for `MapPath`. **Effective payload:** for hosts `rundll32` (DLL before the comma), `regsvr32` (last non-switch arg), `wscript`/`cscript`/`mshta` (script path or URL), `powershell`/`pwsh` (`-File` path or inline), `cmd /c` (first command) the signature is checked on the payload, not the host.
- Rules evaluated **top-down, first match wins**; record `RuleId`, `Severity`, plain `Reason`:

| # | RuleId | Condition | Severity |
|---|---|---|---|
| 1 | WMI_CONSUMER | WMI CommandLine/ActiveScript consumer | High |
| 2 | ACCESSIBILITY_REPLACED | sethc/utilman/osk/Magnify/Narrator/DisplaySwitch/AtBroker not Microsoft-signed | High |
| 3 | IFEO_DEBUGGER | IFEO `Debugger` or `SilentProcessExit` MonitorProcess (signed Sysinternals/VS debuggers => Low) | High |
| 4 | WINLOGON_CHANGED | Shell != `explorer.exe` / Userinit != default / BootExecute != `autocheck autochk *` / Notify entries | High |
| 5 | DLL_INJECTION | AppInit_DLLs with `LoadAppInit_DLLs=1`, AppCertDlls, unknown LSA packages | High |
| 6 | COM_HIJACK | HKCU CLSID shadowing an HKLM CLSID | High |
| 7 | SUSPICIOUS_COMMAND | `-enc`/`-EncodedCommand`, `-w hidden`, `-nop`, `iex`, `FromBase64String`, `iwr`/`Invoke-WebRequest`/`curl http`, `mshta http`, `rundll32 javascript:`, `regsvr32 /i:http`, `certutil -urlcache`, `bitsadmin /transfer`, `.js/.vbs/.hta` under `\AppData\` | High |
| 8 | TASK_HIDDEN | TaskCache entry with no XML or no `SD` | High |
| 9 | UNSIGNED_RISKY_PATH | payload unsigned/invalid in `\Temp\`, `\Downloads\`, `\Users\Public\`, or random-looking name in `\AppData\` | High |
| 10 | UNSIGNED_APPDATA | payload unsigned in `\AppData\` (ordinary name) | Medium |
| 11 | UNQUOTED_SERVICE_PATH | service ImagePath unquoted with spaces | Medium |
| 12 | UNSIGNED | payload unsigned elsewhere | Medium |
| 13 | FILE_MISSING | payload file missing (no suspicious pattern) | Low |
| 14 | OEM_KNOWN | signer + path prefix in embedded OEM allowlist (HP, Dell, Lenovo, ASUS, Realtek, Intel, NVIDIA, AMD, Logitech) | Info |
| 15 | SIGNED_THIRD_PARTY | signed non-Microsoft | Info |
| 16 | MICROSOFT | Microsoft-signed payload, no suspicious argument | Hidden by default |
| 17 | NOT_VERIFIABLE | signature `NotChecked` (offline, no catalog match) | Info |

  Modifier: item disabled in `StartupApproved` => severity lowered one level and `Disabled = true`.
- Tests: one per rule, first-match ordering (missing file + `-enc` => SUSPICIOUS_COMMAND High), rundll32 payload extraction, unquoted path, disabled downgrade, OEM allowlist.

Commit `feat(collectors): persistence rule engine`.

### Task 7b: Persistence locations - registry

**Files:** `Security/RegistryPersistence.cs`; tests with FakeRegistry. Read (SOFTWARE, WOW6432Node, each NTUSER, each UsrClass):
- `Run`, `RunOnce`, `RunOnceEx`, `RunServices`, `Policies\Explorer\Run`, including the default (`""`) value and names starting with NUL; `Policies\System\Shell`; per-user `Winlogon\Shell`
- `Winlogon` `Shell`, `Userinit`, `Notify\*`, `GPExtensions` (only those values; never read `DefaultPassword`)
- `Session Manager\BootExecute`; `Control\Lsa` `Authentication Packages`, `Security Packages`, `Notification Packages`; `Session Manager\AppCertDlls`; `Windows\AppInit_DLLs` + `LoadAppInit_DLLs`
- `Image File Execution Options\*\Debugger`, `GlobalFlag` + `SilentProcessExit\*\MonitorProcess`
- `Services\*` Start 0-2: `ImagePath`, and for svchost services `Parameters\ServiceDll`
- `Active Setup\Installed Components\*\StubPath`
- `Control Panel\Desktop\SCRNSAVE.EXE` (non-System32)
- NTUSER `Software\Classes\CLSID\*\InprocServer32|LocalServer32` vs same CLSID in SOFTWARE
- `Explorer\StartupApproved\Run|Run32|StartupFolder` (first byte odd => disabled)
- Netsh helpers (`SOFTWARE\Microsoft\NetSh`), print monitors (`Control\Print\Monitors\*\Driver`)
- Chromium `ExtensionInstallForcelist` policies (Chrome/Edge) - listed, severity via rules
- Deferred (noisy): shell extensions, ShellServiceObjectDelayLoad.

Tests: null-named Run value found; shadowing HKCU CLSID; svchost `ServiceDll` scored; StartupApproved disabled byte; Winlogon default values => no finding.

Commit `feat(collectors): registry persistence locations`.

### Task 7c: Persistence locations - files

**Files:** `Security/TaskPersistence.cs`, `Security/FilePersistence.cs`; fixtures `tests/fixtures/tasks/*.xml` (real UTF-16 LE BOM files)
- Scheduled tasks: all XML under `Windows\System32\Tasks` **including `\Microsoft\`** (Microsoft-signed payload without suspicious args => rule 16 hides it); parse task namespace, multiple `Exec` actions, `ComHandler` (resolve CLSID), `Enabled=false`; cross-check `SOFTWARE\...\Schedule\TaskCache\Tree|Tasks` for registry-only tasks.
- Startup folders (ProgramData + each user): `.lnk` via `Lnk` package, `.bat/.cmd/.vbs/.js` scripts.
- PowerShell profiles (`Documents\WindowsPowerShell\*profile.ps1`, `Documents\PowerShell\*`, `System32\WindowsPowerShell\v1.0\profile.ps1`).
- Office startup: `AppData\Roaming\Microsoft\Word\STARTUP`, `Excel\XLSTART` (files listed).
- Live only: WMI `root\subscription` bindings.
- Tests: fixtures for namespace, multi-action, ComHandler-only, `%windir%` command, quoted path with args, disabled task; non-Microsoft exe hidden in `\Microsoft\` tree is flagged.

Commit `feat(collectors): scheduled task, startup folder and profile persistence`.

### Task 7d: Authenticode verification

**Files:** `Security/Authenticode.cs`, `Security/HResultMapper.cs`, `Security/OfflineCatalogIndex.cs`; CsWin32 `NativeMethods.txt` entries
- Step 1: `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)`, `WTD_CHOICE_FILE`, `dwUIChoice = WTD_UI_NONE`, `fdwRevocationChecks = WTD_REVOKE_NONE`, `dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4`, `dwStateAction = VERIFY`; signer via `WTHelperProvDataFromStateData` -> `WTHelperGetProvSignerFromChain` -> `CertGetNameString(SIMPLE_DISPLAY)`; **always** `dwStateAction = CLOSE` in `finally`.
- Step 2 only on `TRUST_E_NOSIGNATURE` / `TRUST_E_SUBJECT_FORM_UNKNOWN` / `TRUST_E_PROVIDER_UNKNOWN` (an embedded signature that fails never falls back): catalog lookup SHA-256 then SHA-1 (`CryptCATAdminAcquireContext2` -> `CalcHashFromFileHandle2` -> `EnumCatalogFromHash` loop -> `CatalogInfoFromContext`), then `WinVerifyTrust` with `WTD_CHOICE_CATALOG` (`pcwszMemberTag` = uppercase hex hash, `hCatAdmin` set). Catalog found but not verified != Valid.
- Offline: `OfflineCatalogIndex` builds hash -> `.cat` from the scanned drive's `Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}` (`CryptCATOpen` + `CryptCATEnumerateMember`), verified with `WTD_CHOICE_CATALOG` against this PC's roots; no match => `NotChecked`.
- `HResultMapper` (pure, tested): 0 => Valid; NOSIGNATURE/SUBJECT_FORM_UNKNOWN/PROVIDER_UNKNOWN => NotEmbedded; BAD_DIGEST, UNTRUSTEDROOT, REVOKED, EXPLICIT_DISTRUST, EXPIRED, SECURITY_SETTINGS, SUBJECT_NOT_TRUSTED => Invalid.
- Cache by (path, size, LastWriteUtc); `Parallel.ForEach` with `ProcessorCount`; one `hCatAdmin` per thread.
- Tests (Windows integration): `notepad.exe` Valid (Microsoft); a catalog-only System32 binary Valid via catalog; an unsigned temp file Unsigned; a signed copy with one byte flipped Invalid.

Commit `feat(collectors): Authenticode with catalog and offline catalog support`.

---

### Task 8a: PC profile from hives (both modes)

**Files:** `Health/PcProfile.cs`, `Health/HiveProfile.cs`; tests
- OS name: build >= 22000 => "Windows 11 " + edition text, else `ProductName` (test: build 26200 + "Windows 10 Enterprise" => "Windows 11 Enterprise"); `EditionID` `Core*` => Home; `DisplayVersion`, `CurrentBuild`, `UBR`; `InstallDate` labelled **"last feature update"**, original install from the oldest `SYSTEM\Setup\Source OS (Updated on ...)` key.
- Architecture: `SYSTEM\<CCS>\Control\Session Manager\Environment\PROCESSOR_ARCHITECTURE`.
- Computer name, MachineGuid, Secure Boot state, RDP enabled (`fDenyTSConnections == 0`), Hyper-V enabled (service `vmms` exists with Start != 4), domain/Entra joined.
- GPU VRAM: `Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000..` numeric subkeys only, `HardwareInformation.qwMemorySize` else `HardwareInformation.MemorySize` (binary or DWORD).

### Task 8b: PC profile from WMI and display APIs (live)

**Files:** `Health/WmiProfile.cs`, `Health/DisplayInfo.cs`; tests with a fake `IWmiClient`
- Processor, ComputerSystem (RAM, domain), VideoController names/drivers, LogicalDisk, `MSFT_PhysicalDisk` (MediaType 3 HDD / 4 SSD; BusType 7 USB / 11 SATA / 17 NVMe) + `GetRelated("MSFT_StorageReliabilityCounter")` (null stays null, never 0; wear = % of rated life used).
- TPM (`SpecVersion` first token), BitLocker protection status per volume, activation `SELECT LicenseStatus, ProductKeyChannel FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL` (45 s), devices with `ConfigManagerErrorCode <> 0`, newest `Win32_ReliabilityStabilityMetrics` only.
- Access denied => field "unknown (not elevated)", never "absent". Never call `GetKeyProtectorNumericalPassword`.
- Monitors: `QueryDisplayConfig` + `DisplayConfigGetDeviceInfo` (friendly name, resolution) + `GetDpiForMonitor` (scale %); `WmiMonitorID` only for make/serial (UInt16[] decoded, NULs trimmed).
- Tests: InvalidNamespace/TimedOut leave fields null and log; access denied => unknown; TPM "2.0, 0, 1.59" => 2.0.

### Task 8c: Battery and crash history (both modes where possible)

**Files:** `Health/BatteryReport.cs`, `Health/CrashHistory.cs`; fixtures (serials and names scrubbed)
- Battery (live): `%SystemRoot%\System32\powercfg.exe /batteryreport /xml /output <protected work folder>` via `IProcessRunner`; parse namespace `http://schemas.microsoft.com/battery/2012`; multiple batteries; missing/0 cycles => null; full > design clamped to 100%; desktop => null. Fallback WMI `root\wmi` `BatteryStaticData`/`BatteryFullChargedCapacity`.
- Crashes (both modes): `EventLogReader` on the live System log or `PathType.FilePath` on `<source>\Windows\System32\winevt\Logs\System.evtx`, XPath `Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001`, last 90 days, bugcheck code from `Properties[0]`; plus Kernel-Power 41 count and `Windows\Minidump\*.dmp` count/dates.
- Tests: battery fixtures (one, two, none, missing cycles, over-capacity); crash parsing from a small exported evtx fixture.

Commit (8a-8c separately) `feat(collectors): PC profile ...`.

---

### Task 9: Readiness scorer v2 (pure)

**Files:** `Health/ReadinessScorer.cs`; tests
- Space 25: < 1.0x migration size = 0 + **blocker**; 1.0x..1.2x linear; >= 1.2x = 25.
- Architecture 15: same = 15; x64 -> ARM64 = 5 + warning; ARM64 -> x64 = 15 + note.
- Apps 25: share of `ReinstallCandidate` apps with an installer path; zero candidates = 25.
- Edition 15: Pro/Enterprise/Education -> Home (`Core*`) loses 5 each for BitLocker (if used), Hyper-V (if enabled), RDP host (if enabled).
- Health 10 (**new PC only**): devices with errors -3, any disk wear >= 80% -4 (amber) / >= 100% red, bugchecks in 90 days -3.
- Security 10 (**new PC only**): TPM 2.0 = 4, Secure Boot = 3, activated = 3. **Unknown (null) = full points**, never a penalty.
- Any blocker caps the total at 59. Rounding `MidpointRounding.AwayFromZero`.
- Tests: identical healthy PCs = 100; 50% of 10 apps => exactly 13 (12.5 rounds up); exactly 1.0x and 1.2x space; not enough space => <= 59; Pro -> Home with BitLocker used; x64 -> ARM64; ARM64 -> x64; all-null offline profile; zero apps.

Commit `feat(collectors): readiness scorer v2`.

---

### Task 10: Dead-PC mode (offline drive)

**Files:** `Sources/OfflineVolumeFinder.cs`, `Sources/BitLocker.cs`, `Sources/VolumeSafety.cs`; tests
- **Read-only attach wizard (before plugging in the old drive):** explains and, with the user's OK, runs `diskpart` script `san policy=OfflineAll`; after plugging in: `select disk N`, `attributes disk set readonly`, `online disk`; restores the previous SAN policy afterwards. Never `attributes volume` or `gpt attributes` (they write a persistent flag to the old disk).
- `OfflineVolumeFinder.Find()`: volumes from WMI `Win32_Volume` + `Win32_EncryptableVolume` (finds BitLocker-locked ones that `DriveInfo` can't read), excluding the running Windows volume; for unlocked ones, `Windows\System32\config\SOFTWARE` present => candidate with OS name/build from `OfflineSource`.
- `BitLocker.Unlock(volumeId, char[] recoveryKey)` via WMI `Win32_EncryptableVolume.UnlockWithNumericalPassword` in-process; key never on a command line, never logged; `char[]` wiped after use; `Lock()` offered after the scan. Validation (tested): 8 groups of 6 digits, each group divisible by 11 and < 720896. Where to find the key: aka.ms/myrecoverykey.
- `VolumeSafety`: detects hibernation (`hiberfil.sys` header `HIBR`/`hibr`) and the dirty bit (`FSCTL_IS_VOLUME_DIRTY`): warns "this PC was hibernated or not shut down cleanly - do not let it resume after this". Records NTFS USN journal `NextUsn` (`FSCTL_QUERY_USN_JOURNAL`) before and after the scan; a change is reported as a warning in the summary.
- Tests: finder skips the running Windows volume, includes a locked volume, skips volumes without the SOFTWARE hive; recovery-key validation (valid, wrong group count, group not divisible by 11, group >= 720896); hibernation header detection on a fixture file.

Commit `feat(collectors): dead-PC mode with read-only attach, BitLocker unlock and safety checks`.

---

### Task 11a: Scan runner (test-first)

**Files:** `Collectors/ICollector.cs`, `Collectors/ScanRunner.cs`, `Collectors/ActivityLog.cs`; tests
- `ScanRunner(IReadOnlyList<ICollector>, CaseDb, ISystemSource)`; each collector returns results + status; written to `collector_runs`.
- `scan\activity.json` lists every action (WMI namespaces queried, hive paths parsed, processes started with full paths, files opened outside user data) so the scan can be explained to IT.
- Tests: a throwing collector => `failed`, others still run, exit Partial; cancel during collector 2 => remaining `cancelled`, source disposed exactly once (spy), work folder deleted; offline-only-unavailable collector => `skipped_offline` (not failed); progress order (synchronous `IProgress`).

### Task 11b: CLI

- `pcporter scan --out <folder> | --case <existing>` `[--offline D:\]` `[--json]` `[--quiet]` `[--fail-on high]` `[--include-defender-prefs]`.
- `--json`: single summary object on stdout `{scanId, casePath, status, exitCode, collectors[], counts, findings{worthALook, unusual}, av[]}`; progress/log to stderr; not elevated => JSON error + exit 4.
- Dev-only `--allow-device-path` compiled under `#if DEBUG`.
- Tests: `--json` parses and stdout holds nothing else; `--fail-on high` with a High finding => exit 1.

### Task 11c: Health & security page (GUI)

- Before Start: output folder (default: first external drive) with free space and a plain explanation; offline header "Scanning drive D: (old PC BOB-LAPTOP)".
- During: "Step 2 of 4" + elapsed time (typical durations after the first run, no fake ETA); one card per collector; Narrator announces only when a collector finishes.
- After, in this order: verdict line ("Scan finished. 2 things are worth a look."), "Your antivirus is X" (+ account/download/deactivate steps), startup findings, health.
- Wording: **Worth a look / Unusual / Normal** (data keeps High/Medium/Info); fixed banner "Flagged does not mean harmful. Many legitimate programs look like this."; each finding says what it is, why it was flagged, common harmless causes. Never "infected" or "malware".
- Per finding: Open file location, Search the web for this name, "I know this one" (tag; hidden next scan).
- Partial failure: amber card ("Couldn't read battery info - normal on desktops"), Retry this part, Copy diagnostics. Cancel: confirm, keep finished parts.
- Icons always with text; AutomationProperties on every card.

Commit `feat: scan runner, CLI and health & security page`.

---

### Task 12: Verify

1. `dotnet test` (non-admin) green; elevated `dotnet test --filter Category=Admin` green.
2. **Before the first dev-PC scan:** tell IT what it does (read-only registry and WMI queries, no shadow copies) and share `activity.json` afterwards.
3. Publish; elevated `PCPorter.exe selftest` all PASS (closes the Phase 1 single-file VSS question).
4. `PCPorter.exe scan --out C:\PCPorterDev --json` (elevated) on this PC; compare apps with Settings > Apps and `winget list`, AV with Windows Security, startup findings with Task Manager > Startup apps and Task Scheduler, profile with Settings > System > About. Explain every difference in the Review.
5. **Offline mode:** build a VHDX test image (`New-VHD` + format + mount as `T:`) containing an offreg-built mini Windows tree (SOFTWARE/SYSTEM/NTUSER with Run keys, Uninstall entries, a task XML, a startup .lnk) - no real hives copied; scan it with `--offline T:\` after `Mount-DiskImage -Access ReadOnly`; assert expected findings and that `activity.json` shows **no path outside `T:\`**; USN `NextUsn` unchanged.
6. Scan twice; the diff by `item_key` shows no changes.
7. EXE size with/without ReadyToRun + startup time; keep the better.
8. Update `tasks/todo.md` (Phase 2 items + Review) and `tasks/lessons.md`; commit `docs: Phase 2 complete`.
