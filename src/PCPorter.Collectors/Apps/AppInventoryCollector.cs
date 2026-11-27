using System.Globalization;
using System.Text.RegularExpressions;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Apps;

/// <summary>What the app collector reads besides the registry (all on by default).</summary>
public sealed record AppInventoryOptions(bool Games = true, bool PackageManagers = true, bool StoreApps = true, bool Portable = true, bool Winget = true)
{
    public static readonly AppInventoryOptions RegistryOnly = new(false, false, false, false, false);
}

/// <summary>Installed programs: Uninstall keys (machine and per user, 64- and 32-bit), games, Chocolatey/Scoop, Store, portable apps.</summary>
public sealed partial class AppInventoryCollector(AppInventoryOptions? options = null) : ICollector
{
    readonly AppInventoryOptions _options = options ?? new AppInventoryOptions();

    public string Name => "Installed apps";
    public const string Kind = "apps";

    public static readonly (string Path, string Arch)[] MachineUninstallPaths =
    [
        (@"Microsoft\Windows\CurrentVersion\Uninstall", "x64"),
        (@"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "x86"),
    ];

    public static readonly (string Path, string Arch)[] UserUninstallPaths =
    [
        (@"Software\Microsoft\Windows\CurrentVersion\Uninstall", "x64"),
        (@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "x86"),
    ];

    static readonly HashSet<string> SkippedReleaseTypes = new(StringComparer.OrdinalIgnoreCase) { "Update", "Hotfix", "Security Update" };

    [GeneratedRegex(@"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")] private static partial Regex GuidKey();

    public CollectorOutput Run(CollectorContext context, CancellationToken ct)
    {
        var src = context.Source;
        var notes = new List<string>();
        var apps = new List<InstalledApp>();
        bool partial = false;

        void Step(string what, Action action)
        {
            if (ct.IsCancellationRequested) return;
            context.Progress?.Report(what);
            try { action(); }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                partial = true;
                context.Warnings.Add($"{what}: could not be completed ({e.GetType().Name}).");
            }
        }

        var games = new GameLibraries();
        if (_options.Games) Step("Reading game libraries", () => games = GameLibraries.Read(src, notes, context.Warnings));
        Step("Reading installed programs", () => apps.AddRange(ReadRegistry(src, games.LibraryFolders, notes, context.Warnings)));
        if (_options.Games) Step("Merging games", () => MergeGames(apps, games.Games));
        if (_options.PackageManagers) Step("Reading Chocolatey and Scoop packages", () => PackageManagersInventory.Merge(apps, PackageManagersInventory.Read(src, context.Warnings)));
        if (_options.StoreApps) Step("Reading Store apps", () => apps.AddRange(AppxInventory.Read(src, notes, context.Warnings)));
        if (_options.Portable) Step("Looking for portable apps", () =>
        {
            var portable = PortableAppFinder.Find(src, apps, notes);
            apps.AddRange(portable);
            if (portable.Count > 0) notes.Add($"{portable.Count} portable app(s) found: copy their folders to the new PC.");
        });
        if (_options.Winget) Step("Matching apps to winget packages", () => WingetMatcher.Apply(context, apps, notes, ct));
        MakeKeysUnique(apps);

        var status = ct.IsCancellationRequested ? CollectorStatus.Cancelled : partial ? CollectorStatus.Partial : CollectorStatus.Ok;
        return new CollectorOutput(Kind, apps.Cast<IScanItem>().ToList(), notes, status);
    }

    /// <summary>Task 5a rules 1-6: Uninstall keys from SOFTWARE and every user's NTUSER.</summary>
    /// <summary>
    /// Two installs with the same name, maker, scope and architecture (Family Photos 2.0 and 3.0 side by side) would share
    /// one key, and case.db keeps one item per key. Those get their source entry appended, which is stable across scans.
    /// </summary>
    public static void MakeKeysUnique(List<InstalledApp> apps)
    {
        foreach (var group in apps.Select((a, i) => (App: a, Index: i)).GroupBy(x => x.App.ItemKey, StringComparer.Ordinal).Where(g => g.Count() > 1))
            foreach (var (app, index) in group)
                apps[index] = app with { ItemKey = app.ItemKey + "|" + app.SourceKey.ToLowerInvariant() };
    }

    /// <summary>Where Windows Installer keeps upgrade codes (packed GUIDs). Readable from an offline SOFTWARE / NTUSER hive.</summary>
    public static readonly string[] MachineUpgradeCodePaths = [@"Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes", @"Classes\Installer\UpgradeCodes"];
    public const string UserUpgradeCodePath = @"Software\Microsoft\Installer\UpgradeCodes";

    /// <summary>UpgradeCodes\&lt;packed upgrade code&gt; has one value per packed product code of that product family.</summary>
    static void ReadUpgradeCodes(IRegKey? root, Dictionary<string, string> into)
    {
        if (root is null) return;
        foreach (var k in root.SubKeys)
        {
            if (UnpackGuid(k.Name) is not { } upgrade) continue;
            foreach (var v in k.ValueNames)
                if (UnpackGuid(v) is { } product) into.TryAdd(product, upgrade);
        }
    }

    /// <summary>
    /// Windows Installer's "packed" GUID (32 hex digits, no punctuation) to "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}":
    /// the first three groups are reversed, the last 16 digits have each pair swapped. Null if it is not one.
    /// </summary>
    public static string? UnpackGuid(string? packed)
    {
        if (packed is not { Length: 32 } p || !p.All(Uri.IsHexDigit)) return null;
        static string Rev(string s) => new(s.Reverse().ToArray());
        var tail = string.Concat(Enumerable.Range(0, 8).Select(i => $"{p[16 + i * 2 + 1]}{p[16 + i * 2]}"));
        return $"{{{Rev(p[..8])}-{Rev(p[8..12])}-{Rev(p[12..16])}-{tail[..4]}-{tail[4..]}}}".ToUpperInvariant();
    }

    public static List<InstalledApp> ReadRegistry(ISystemSource src, IReadOnlyList<string> gameLibraries, IList<string> notes, IList<string> warnings)
    {
        var list = new List<InstalledApp>();
        var seen = new HashSet<(string Key, string Scope, string Arch)>();
        var upgrades = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // product code -> upgrade code
        int bad = 0;

        var software = src.OpenHive(Hive.Software);
        if (software is null) notes.Add("The SOFTWARE registry hive could not be read; machine-wide apps are missing.");
        else
        {
            bool is64 = software.Open("WOW6432Node") is { } wow && Dispose(wow);
            foreach (var (path, arch) in MachineUninstallPaths)
                ReadUninstall(software, path, is64 ? arch : "x86", "Machine", @"HKLM\SOFTWARE\" + path);
            foreach (var path in MachineUpgradeCodePaths) ReadUpgradeCodes(software.Open(path), upgrades);
        }
        foreach (var u in src.Users)
        {
            var hive = u.Unavailable is null ? src.OpenHive(Hive.NtUser, u) : null;
            if (hive is null) { notes.Add($"Apps installed only for {u.UserName} could not be read."); continue; }
            foreach (var (path, arch) in UserUninstallPaths)
                ReadUninstall(hive, path, arch, "User:" + u.UserName, $@"HKU\{u.Sid}\{path}");
            ReadUpgradeCodes(hive.Open(UserUpgradeCodePath), upgrades);
            Dispose(hive);
        }
        Dispose(software ?? (object)"");
        if (bad > 0) warnings.Add($"{bad} installed-program entr{(bad == 1 ? "y" : "ies")} could not be read.");
        for (int i = 0; i < list.Count; i++)
            if (list[i].ProductCode is { } pc && list[i].UpgradeCode is null && upgrades.TryGetValue(pc, out var uc)) list[i] = list[i] with { UpgradeCode = uc };
        return list;

        void ReadUninstall(IRegKey root, string path, string arch, string scope, string sourcePrefix)
        {
            var uninstall = root.Open(path);
            if (uninstall is null) return;
            foreach (var k in uninstall.SubKeys)
            {
                try
                {
                    if (!seen.Contains((k.Name.ToLowerInvariant(), scope, arch)) && FromKey(k, arch, scope, sourcePrefix + "\\" + k.Name, gameLibraries) is { } app)
                    {
                        seen.Add((k.Name.ToLowerInvariant(), scope, arch));
                        list.Add(app);
                    }
                }
                catch (Exception e) when (e is not OperationCanceledException) { bad++; }
                finally { Dispose(k); }
            }
            Dispose(uninstall);
        }
    }

    /// <summary>One Uninstall subkey -> app, or null when it is not an app (no DisplayName, or an update).</summary>
    public static InstalledApp? FromKey(IRegKey k, string arch, string scope, string sourceKey, IReadOnlyList<string> gameLibraries)
    {
        var name = Clean(k.GetString("DisplayName"));
        if (name is null) return null;                                                     // rule 2
        if (Clean(k.GetString("ReleaseType")) is { } rt && SkippedReleaseTypes.Contains(rt)) return null;
        bool hidden = k.GetNumber("SystemComponent") == 1 || Clean(k.GetString("ParentKeyName")) is not null
            || k.Name.EndsWith(".sdb", StringComparison.OrdinalIgnoreCase);   // compatibility-fix (shim) database, not an app

        var (date, inferred) = InstallDateOf(k.GetString("InstallDate"), k.LastWrite);      // rule 4
        var location = Clean(k.GetString("InstallLocation"))?.Trim('"');
        if (location?.Length == 0) location = null;
        var kind = AppClassifier.Classify(name, location, gameLibraries);                    // rule 5
        var publisher = Clean(k.GetString("Publisher"));
        bool reinstall = !hidden && kind is not (AppKind.Runtime or AppKind.Driver);

        return new InstalledApp(
            InstalledApp.KeyFor(name, publisher, scope, arch), name, Clean(k.GetString("DisplayVersion")), publisher, arch,
            date, inferred, scope, kind, hidden, reinstall,
            GuidKey().IsMatch(k.Name) ? k.Name : null, null, k.GetNumber("WindowsInstaller") == 1, location,   // rule 6
            Clean(k.GetString("UninstallString")), Clean(k.GetString("QuietUninstallString")),
            Clean(k.GetString("HelpLink")), Clean(k.GetString("URLInfoAbout")),
            null, null, null, null, null, null, sourceKey);
    }

    /// <summary>Rule 4: yyyyMMdd, otherwise the key's last-write date (marked inferred).</summary>
    public static (DateOnly? Date, bool Inferred) InstallDateOf(string? raw, DateTimeOffset? lastWrite)
    {
        if (raw is not null && DateOnly.TryParseExact(raw.Trim(), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) && d.Year >= 1980)
            return (d, false);
        return lastWrite is { } lw ? (DateOnly.FromDateTime(lw.UtcDateTime), true) : (null, false);
    }

    /// <summary>Steam/Epic games: "Steam App N" registry entries take the manifest's name; other games are added.</summary>
    public static void MergeGames(List<InstalledApp> apps, IEnumerable<InstalledApp> games)
    {
        foreach (var g in games)
        {
            int idx = -1;
            if (g.SourceKey.StartsWith("steam:", StringComparison.Ordinal))
            {
                var keyName = "Steam App " + g.SourceKey["steam:".Length..];
                idx = apps.FindIndex(a => a.SourceKey.EndsWith("\\" + keyName, StringComparison.OrdinalIgnoreCase));
            }
            if (idx < 0 && g.InstallLocation is { } loc)
                idx = apps.FindIndex(a => a.InstallLocation is { } l && PathUtil.Clean(l).Equals(PathUtil.Clean(loc), StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                var a = apps[idx];
                apps[idx] = (a with { Name = g.Name, Kind = AppKind.Game, ReinstallCandidate = !a.Hidden, InstallLocation = a.InstallLocation ?? g.InstallLocation }).Rekey();
            }
            else apps.Add(g);
        }
    }

    static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    static bool Dispose(object o) { (o as IDisposable)?.Dispose(); return true; }
}
