using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using PCPorter.Collectors;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.TestKit;

namespace PCPorter.Reports.Tests.Regression;

/// <summary>
/// Tier 3 regression: a full offline scan (the real collectors, signature checker and report) of a fake old-PC drive
/// with one planted case per past bug. Checks a golden summary, the report rules, case.db against scan/*.json, that
/// no secret leaks, that the drive is byte-for-byte unchanged, and (spy) that no denied hive or value is ever read.
/// </summary>
public class OldPcScanTests : IDisposable
{
    readonly OldPcDrive _drive = OldPcDrive.Create();
    readonly string _out = Directory.CreateTempSubdirectory("pcporter-regress-out").FullName;

    public void Dispose()
    {
        _drive.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_out, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>Fixed, so date-based checks (Windows 10 support, backups, crashes) give the same answer every year.</summary>
    static readonly DateTimeOffset FixedNow = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);

    ScanJobResult Scan() => ScanSetup.Run(_out, new ScanJobOptions(OfflineRoot: _drive.Root, Now: FixedNow));

    [Fact]
    public void Offline_scan_matches_golden_summary()
    {
        var r = Scan();
        Golden.Check("scan-oldpc", Summary(r));
    }

    [Fact]
    public void Planted_cases_are_found()
    {
        var r = Scan();
        var startup = Items<PersistenceItem>(r);
        (string, Severity) Rule(string where, string name)
        {
            var i = Assert.Single(startup, x => x.Location.Contains(where) && x.Name == name);
            return (i.RuleId, i.Severity);
        }
        Assert.Equal(("TASK_LEFTOVER", Severity.Info), Rule("Task Scheduler", "Leftover"));
        Assert.Equal(("TASK_HIDDEN", Severity.High), Rule("Task Scheduler", "Updater"));
        Assert.Equal(("UNQUOTED_SERVICE_PATH", Severity.Medium), Rule("Services", "BadVendorSvc"));
        Assert.Equal(("UNSIGNED_RISKY_PATH", Severity.High), Rule(@"\Run", "Updater"));     // unsigned + AppData + random name
        Assert.Equal(("UNSIGNED_APPDATA", Severity.Medium), Rule(@"\Run", "Sync"));

        // Locations added after the persistence research (batch 1)
        Assert.Equal(("WINLOGON_CHANGED", Severity.High), Rule("Winlogon", "Taskman"));
        Assert.Equal(("WINLOGON_CHANGED", Severity.High), Rule(@"exefile\shell\open\command", "exefile open command"));
        Assert.Equal(("WINLOGON_CHANGED", Severity.High), Rule(@"ms-settings\shell\open\command", "ms-settings open command"));
        Assert.DoesNotContain(startup, x => x.Name == "batfile open command");                              // default value: nothing
        Assert.Equal(("UNSIGNED_RISKY_PATH", Severity.High), Rule(@"HKLM\SOFTWARE\Microsoft\Command Processor", "AutoRun"));   // Users\Public
        Assert.Equal(("UNSIGNED_APPDATA", Severity.Medium), Rule(@"(bob)\Software\Microsoft\Command Processor", "AutoRun"));
        Assert.Equal(("UNSIGNED_RISKY_PATH", Severity.High), Rule(@"CurrentVersion\Windows", "Load"));        // Temp folder
        Assert.Equal(("SUSPICIOUS_COMMAND", Severity.High), Rule("Environment", "UserInitMprLogonScript"));  // script in AppData
        Assert.Single(startup, x => x.Location == "Startup folder (bob, moved)" && x.Name == "run.bat");
        Assert.Single(startup, x => x.Name == "ExtensionSettings: aaaabbbbccccddddeeeeffffgggghhhh");
        Assert.Single(startup, x => x.Location.EndsWith(@"Google\Chrome\Extensions") && x.Name == "iiiijjjjkkkkllllmmmmnnnnoooopppp");
        Assert.Single(startup, x => x.Location.Contains(@"Mozilla\Firefox\Extensions\Install"));

        var apps = Items<InstalledApp>(r);
        Assert.Single(HealthReport.ReinstallRows(apps), x => x.App.Name == "Family Photos");
        Assert.True(apps.Single(a => a.Name == "Contoso Compatibility Fix").Hidden);
        Assert.DoesNotContain(apps, a => a.Kind == AppKind.Portable && a.Name.StartsWith("Python"));
        Assert.Contains(apps, a => a.Kind == AppKind.Portable && a.Name == "PortaTool");
        Assert.Equal(("7zip.7zip", "ProductCode"), Match(apps, "7-Zip 26.06 (x64 edition)"));
        Assert.Equal(("Hex-Rays.IDA.Free", "ProductCode"), Match(apps, "IDA Freeware 8.4"));
        Assert.Equal(("jqlang.jq", "NameMatch"), Match(apps, "jq"));
        Assert.Equal((null, "None"), Match(apps, "Tool"));                       // two catalog packages: no guess
        // winget batch
        Assert.Equal(("Contoso.Updater", "ProductCode"), Match(apps, "Contoso Updater 7"));                 // upgrade code from packed GUIDs
        Assert.Equal(("JetBrains.PyCharm.Community", "NameMatch"), Match(apps, "PyCharm Community Edition 2025.1"));   // "s.r.o." dropped
        Assert.Equal(("Python.Python.3.12", "NameMatch"), Match(apps, "Python 3.12.4 (64-bit)"));         // version range breaks the tie
        Assert.All(apps.Where(a => a.Name == "Family Photos"), a => Assert.Equal(("SmallShop.FamilyPhotos", "InstalledByWinget"), (a.WingetId, a.MatchMethod)));
    }

    [Fact]
    public void Report_follows_the_rules_and_no_secret_leaks()
    {
        var r = Scan();
        Assert.NotNull(r.ReportPath);
        ReportInvariants.AssertHolds(File.ReadAllText(r.ReportPath!));
        foreach (var file in Directory.EnumerateFiles(r.CaseFolder, "*", SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.False(Contains(bytes, Encoding.UTF8.GetBytes(OldPcDrive.Canary)) || Contains(bytes, Encoding.Unicode.GetBytes(OldPcDrive.Canary)),
                $"The planted secret appears in {Path.GetRelativePath(r.CaseFolder, file)}.");
        }
    }

    [Fact]
    public void Case_db_and_json_exports_agree()
    {
        var r = Scan();
        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        var exports = Directory.GetFiles(Path.Combine(r.CaseFolder, "scan"), "*.json").Where(f => Path.GetFileName(f) != "activity.json").ToList();
        Assert.NotEmpty(exports);
        foreach (var file in exports)
        {
            var json = JsonNode.Parse(File.ReadAllText(file))!;
            var kind = (string)json["kind"]!;
            Assert.Equal(r.ScanId, (string)json["scanId"]!);
            var rows = db.Items(r.ScanId, kind);
            Assert.Equal(rows.Count, json["items"]!.AsArray().Count);
        }
        foreach (var x in r.Run.Runs.Where(x => x.Output is not null))                       // case.db keeps one item per key
            Assert.True(x.Output!.Items.Select(i => i.ItemKey).Distinct(StringComparer.Ordinal).Count() == x.Output.Items.Count,
                $"{x.Collector} produced two items with the same key.");
        var scan = Assert.Single(db.Scans());
        Assert.Equal("offline", scan.Mode);
        Assert.NotEqual("running", scan.Status);
    }

    [Fact]
    public void Scan_does_not_change_the_old_drive()
    {
        var before = _drive.Fingerprint();
        Scan();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        var after = _drive.Fingerprint();
        Assert.Empty(after.Keys.Except(before.Keys));                            // nothing added (no -wal, -shm, journal, temp files)
        Assert.Empty(before.Keys.Except(after.Keys));                            // nothing removed
        Assert.All(before, kv => Assert.True(after[kv.Key] == kv.Value, $"{kv.Key} changed."));
    }

    /// <summary>The read-only proof must notice a temporary file (a SQLite journal, a hive .LOG) created and deleted during a scan.</summary>
    [Fact]
    public void Read_only_proof_catches_a_file_created_and_deleted()
    {
        var before = _drive.Fingerprint();
        var temp = _drive.At(@"C:\Windows\System32\config\SOFTWARE-journal");
        File.WriteAllText(temp, "x");
        File.Delete(temp);
        Assert.NotEqual(before[@"Windows\System32\config\"], _drive.Fingerprint()[@"Windows\System32\config\"]);
    }

    /// <summary>
    /// Denylist spy: every registry key, value, folder and file the real collectors touch is recorded. SAM, SECURITY,
    /// Winlogon DefaultPassword and anything outside the drive must never be read, and an offline scan starts no programs.
    /// </summary>
    [Fact]
    public void Collectors_never_touch_denied_data()
    {
        var files = new ConcurrentQueue<string>();
        var programs = new ConcurrentQueue<string>();
        var checkedSigs = new ConcurrentQueue<string>();
        using var offline = new OfflineSource(_drive.Root);
        using var spy = new SpySource(offline);
        var work = Directory.CreateDirectory(Path.Combine(_out, "work")).FullName;
        var sigs = new RecordingSignatures(ScanSetup.Signatures(spy), checkedSigs);
        var ctx = new CollectorContext(spy, new OfflineWmiClient(),
            new FakeProcessRunner((exe, args) => { programs.Enqueue(exe + " " + string.Join(' ', args)); return new ProcessResult(1, "", false); }),
            sigs, work, new List<string>());

        ScanRunResult run;
        using (SourceFiles.Confine(spy.ReadRoot))
        using (SourceFiles.Observe((_, path) => files.Enqueue(path)))
            run = new ScanRunner(ScanSetup.Collectors(spy)).Run(ctx);
        (sigs.Inner as IDisposable)?.Dispose();

        Assert.All(run.Runs, x => Assert.NotEqual(CollectorStatus.Failed, x.Status));
        Assert.NotEmpty(spy.Log);
        Assert.NotEmpty(files);
        Assert.Contains(spy.Log, k => k.EndsWith(@"\Winlogon:AutoAdminLogon", StringComparison.OrdinalIgnoreCase));   // the spy sees Winlogon...
        Assert.DoesNotContain(spy.Log, k => k.EndsWith(":DefaultPassword", StringComparison.OrdinalIgnoreCase));      // ...but never the password
        Assert.DoesNotContain(spy.Log, k => k.StartsWith("SAM", StringComparison.OrdinalIgnoreCase) || k.StartsWith("SECURITY", StringComparison.OrdinalIgnoreCase));
        var root = Path.GetFullPath(_drive.Root);
        Assert.NotEmpty(spy.Mapped);
        foreach (var f in files.Concat(checkedSigs).Concat(spy.Mapped))
        {
            var full = Path.GetFullPath(f);
            Assert.True(full.StartsWith(root, StringComparison.OrdinalIgnoreCase), $"Read outside the scanned drive: {f}");
            var name = Path.GetFileName(full);
            Assert.False(full.Contains(@"\config\", StringComparison.OrdinalIgnoreCase) && name is "SAM" or "SECURITY", $"Opened a denied hive: {f}");
        }
        Assert.Empty(programs);
    }

    /// <summary>
    /// Tier 4: writes the fake old-PC drive to PCPORTER_FIXTURE_OUT so the packaged EXE can scan it (scripts\regress.ps1
    /// -Level release sets it). Tagged Manual, so the fast and full levels never run it; does nothing without the variable.
    /// </summary>
    [Fact, Trait("Category", "Manual")]
    public void Export_fixture_drive_for_the_smoke_run()
    {
        var target = Environment.GetEnvironmentVariable("PCPORTER_FIXTURE_OUT");
        if (string.IsNullOrWhiteSpace(target)) return;
        if (Directory.Exists(target)) Directory.Delete(target, true);
        foreach (var dir in Directory.EnumerateDirectories(_drive.Root, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(target, Path.GetRelativePath(_drive.Root, dir)));
        foreach (var file in Directory.EnumerateFiles(_drive.Root, "*", SearchOption.AllDirectories))
            File.Copy(file, Path.Combine(target, Path.GetRelativePath(_drive.Root, file)));   // keeps last-write times
        Assert.True(File.Exists(Path.Combine(target, "Windows", "System32", "config", "SOFTWARE")));
    }

    // ---- helpers ----

    static List<T> Items<T>(ScanJobResult r) => r.Run.Runs.Where(x => x.Output is not null).SelectMany(x => x.Output!.Items).OfType<T>().ToList();

    static (string? Id, string? Method) Match(List<InstalledApp> apps, string name)
    {
        var a = apps.Single(x => x.Name == name);
        return (a.WingetId, a.MatchMethod);
    }

    static bool Contains(byte[] hay, byte[] needle) => hay.AsSpan().IndexOf(needle) >= 0;

    /// <summary>Stable text summary for the golden file: no times, paths or ids.</summary>
    static string Summary(ScanJobResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"computer: {r.ScannedComputer}; offline: {r.Offline}");
        foreach (var x in r.Run.Runs) sb.AppendLine($"collector {x.Collector}: {x.Status}, {x.Items} items");
        foreach (var p in Items<PersistenceItem>(r).OrderBy(p => p.Location).ThenBy(p => p.Name))
            sb.AppendLine($"startup [{p.Severity}] {p.RuleId}{(p.Disabled ? " (off)" : "")}: {p.Location} | {p.Name} | {PCPorter.Core.Security.Redactor.Redact(p.Command)}");
        foreach (var p in Items<PostureCheck>(r).OrderBy(p => p.Id)) sb.AppendLine($"posture {p.Id}: {p.Status}");
        foreach (var a in Items<InstalledApp>(r).OrderBy(a => a.Name).ThenBy(a => a.Version).ThenBy(a => a.Architecture))
            sb.AppendLine($"app {a.Name} | {a.Version} | {a.Architecture} | {a.Kind}{(a.Hidden ? " hidden" : "")} | {a.MatchMethod ?? "-"} {a.WingetId}".TrimEnd());
        var c = ScanSetup.CountFindings(r);
        sb.AppendLine($"banner: {c.WorthALook} worth a look ({c.FixThis} fix this), {c.Unusual} unusual");
        return sb.ToString().Replace("\r\n", "\n");
    }

    sealed class RecordingSignatures(ISignatureChecker inner, ConcurrentQueue<string> log) : ISignatureChecker
    {
        public ISignatureChecker Inner => inner;
        public SignatureInfo Check(string path) { log.Enqueue(path); return inner.Check(path); }
    }
}
