using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Apps;

/// <summary>
/// A winget package catalog read as data: the published catalog (Microsoft.Winget.Source, Public\index.db, schema 2.x)
/// or a per-user tracking catalog of what winget itself installed (LocalState\...\installed.db, schema 1.x).
/// Nothing is started, so it is safe in an elevated run and works on another PC's drive. Files are opened read-only and
/// immutable (no lock or journal files next to them) and closed once loaded.
/// Match order per app: package family name (Store apps), MSI product code, uninstall key name, upgrade code (exact),
/// then winget's normalized name + publisher, trying the architecture-tagged name first and the installed version
/// against each package's version range to break ties. Ambiguous names are never guessed.
/// </summary>
public sealed class WingetIndex : IDisposable
{
    public const string ExactMethod = "ProductCode";
    public const string NameMethod = "NameMatch";
    public const string TrackedMethod = "InstalledByWinget";

    readonly Dictionary<long, string> _ids = [];
    readonly Dictionary<string, HashSet<long>> _codes = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, HashSet<long>> _upgrades = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, HashSet<long>> _pfns = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, HashSet<long>> _names = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<long, HashSet<string>> _publishersOf = [];
    readonly Dictionary<long, (string? Min, string? Max)> _ranges = [];

    public string Path { get; }
    public int PackageCount => _ids.Count;
    /// <summary>"winget" or "msstore": the source the ids belong to.</summary>
    public string Source { get; }
    /// <summary>True for a tracking catalog (apps winget itself installed): its matches use <see cref="TrackedMethod"/>.</summary>
    public bool Tracking { get; }
    /// <summary>The catalog's schema version from its metadata table ("2.0", "1.7"...).</summary>
    public string SchemaVersion { get; }

    WingetIndex(string path, string source, bool tracking)
    {
        Path = path;
        Source = source;
        Tracking = tracking;
        var uri = new Uri(path).AbsoluteUri + "?mode=ro&immutable=1";
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = uri, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        db.Open();
        var tables = Rows(db, "SELECT 0, name FROM sqlite_master WHERE type = 'table'").Select(r => r.Text).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var meta = tables.Contains("metadata")
            ? Rows(db, "SELECT 0, name || '=' || value FROM metadata").Select(r => r.Text.Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1])
            : [];
        SchemaVersion = $"{meta.GetValueOrDefault("majorVersion", "?")}.{meta.GetValueOrDefault("minorVersion", "?")}";

        if (tables.Contains("packages") && tables.Contains("norm_names2")) LoadV2(db, tables);
        else if (tables.Contains("manifest") && tables.Contains("ids")) LoadV1(db, tables);
        else throw new InvalidDataException($"Unknown winget catalog layout (schema {SchemaVersion}).");
    }

    /// <summary>Schema 2.x (published index): one row per package, value tables keyed by package.</summary>
    void LoadV2(SqliteConnection db, HashSet<string> tables)
    {
        foreach (var (id, text) in Rows(db, "SELECT rowid, id FROM packages")) _ids[id] = text;
        bool hasRange = Rows(db, "SELECT 0, name FROM pragma_table_info('packages')").Any(r => r.Text == "arp_min_version");
        if (hasRange)
            foreach (var (pkg, range) in Rows(db, "SELECT rowid, IFNULL(arp_min_version, '') || '|' || IFNULL(arp_max_version, '') FROM packages")) AddRange(pkg, range);
        foreach (var (pkg, v) in Rows(db, "SELECT package, productcode FROM productcodes2")) Add(_codes, Code(v), pkg);
        foreach (var (pkg, v) in Rows(db, "SELECT package, upgradecode FROM upgradecodes2")) Add(_upgrades, Code(v), pkg);
        if (tables.Contains("pfns2")) foreach (var (pkg, v) in Rows(db, "SELECT package, pfn FROM pfns2")) Add(_pfns, v.Trim(), pkg);
        foreach (var (pkg, v) in Rows(db, "SELECT package, norm_name FROM norm_names2")) Add(_names, v, pkg);
        foreach (var (pkg, v) in Rows(db, "SELECT package, norm_publisher FROM norm_publishers2")) AddPublisher(pkg, v);
    }

    /// <summary>Schema 1.x (tracking catalogs, older published index): values reach a manifest through *_map tables.</summary>
    void LoadV1(SqliteConnection db, HashSet<string> tables)
    {
        foreach (var (m, id) in Rows(db, "SELECT m.rowid, i.id FROM manifest m JOIN ids i ON i.rowid = m.id")) _ids[m] = id;
        if (tables.Contains("versions"))
            foreach (var (m, range) in Rows(db, "SELECT m.rowid, IFNULL(a.version, '') || '|' || IFNULL(b.version, '') FROM manifest m " +
                                              "LEFT JOIN versions a ON a.rowid = m.arp_min_version LEFT JOIN versions b ON b.rowid = m.arp_max_version"))
                AddRange(m, range);
        IEnumerable<(long, string)> Mapped(string table, string column) => tables.Contains(table) && tables.Contains(table + "_map")
            ? Rows(db, $"SELECT x.manifest, v.{column} FROM {table}_map x JOIN {table} v ON v.rowid = x.{column}")
            : [];
        foreach (var (m, v) in Mapped("productcodes", "productcode")) Add(_codes, Code(v), m);
        foreach (var (m, v) in Mapped("upgradecodes", "upgradecode")) Add(_upgrades, Code(v), m);
        foreach (var (m, v) in Mapped("pfns", "pfn")) Add(_pfns, v.Trim(), m);
        foreach (var (m, v) in Mapped("norm_names", "norm_name")) Add(_names, v, m);
        foreach (var (m, v) in Mapped("norm_publishers", "norm_publisher")) AddPublisher(m, v);
    }

    /// <summary>Product and upgrade codes compare without braces and padding ("  {ABC}" = "abc").</summary>
    static string Code(string v) => v.Trim().Trim('{', '}').ToLowerInvariant();

    static void Add(Dictionary<string, HashSet<long>> map, string key, long pkg)
    {
        if (key.Length == 0) return;
        (map.TryGetValue(key, out var s) ? s : map[key] = []).Add(pkg);
    }

    void AddPublisher(long pkg, string pub)
    {
        if (pub.Length > 0) (_publishersOf.TryGetValue(pkg, out var s) ? s : _publishersOf[pkg] = new(StringComparer.OrdinalIgnoreCase)).Add(pub);
    }

    void AddRange(long pkg, string range)
    {
        var p = range.Split('|');
        if (p.Length == 2 && (p[0].Length > 0 || p[1].Length > 0)) _ranges[pkg] = (p[0].Length > 0 ? p[0] : null, p[1].Length > 0 ? p[1] : null);
    }

    static IEnumerable<(long Key, string Text)> Rows(SqliteConnection db, string sql)
    {
        using var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        using var r = cmd.ExecuteReader();
        var list = new List<(long, string)>();
        while (r.Read()) list.Add((r.IsDBNull(0) ? 0 : r.GetInt64(0), r.IsDBNull(1) ? "" : r.GetString(1)));
        return list;
    }

    /// <summary>
    /// Finds the newest catalog on the scanned PC (<c>&lt;root&gt;\Program Files\WindowsApps\Microsoft.Winget.Source_*</c>).
    /// Null with a reason when there is none or it can't be read (listing WindowsApps needs admin on the running PC).
    /// </summary>
    public static WingetIndex? Open(ISystemSource source, out string? why)
    {
        why = null;
        var apps = System.IO.Path.Combine(source.ReadRoot, "Program Files", "WindowsApps");
        switch (SourcePresence.Of(apps))   // never through a link (it may point at a network share)
        {
            case Presence.Missing: why = "winget's package list was not found on this PC."; return null;
            case Presence.NotFollowed: why = "winget's package list leads outside the scanned drive; it was not read."; return null;
        }
        if (!Directory.Exists(apps)) { why = "winget's package list was not found on this PC."; return null; }
        try
        {
            var newest = Directory.EnumerateDirectories(apps, "Microsoft.Winget.Source_*")
                .Select(d => (Dir: d, Version: VersionOf(System.IO.Path.GetFileName(d))))
                .Where(x => x.Version is not null && SourcePresence.IsFile(System.IO.Path.Combine(x.Dir, "Public", "index.db")))
                .OrderByDescending(x => x.Version).FirstOrDefault();
            if (newest.Dir is null) { why = "winget's package list was not found on this PC."; return null; }
            var file = System.IO.Path.Combine(newest.Dir, "Public", "index.db");
            if (!SourceFiles.IsInside(file)) { why = "winget's package list leads outside the scanned drive; it was not read."; return null; }
            return new WingetIndex(file, "winget", tracking: false);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or DirectoryNotFoundException)
        { why = "winget's package list could not be read (run as administrator to include it)."; return null; }
        catch (Exception e) when (e is IOException or SqliteException or InvalidDataException)
        { why = $"winget's package list could not be read ({e.GetType().Name})."; return null; }
    }

    const string AppInstallerState = @"AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState";

    /// <summary>
    /// The per-user records of what winget installed (winget ids, and Store ids from StoreEdgeFD), for every user on the
    /// scanned PC. They are the strongest evidence of where an app came from. Unreadable ones are noted and skipped.
    /// </summary>
    public static List<WingetIndex> OpenTracking(ISystemSource source, IList<string> notes)
    {
        var list = new List<WingetIndex>();
        IReadOnlyList<UserProfile> users;
        try { users = source.Users; } catch (Exception e) when (e is not OperationCanceledException) { return list; }
        foreach (var u in users)
        {
            if (u.ProfilePath is not { } home || u.Unavailable is not null) continue;
            foreach (var (folder, src) in new[] { ("Microsoft.Winget.Source_8wekyb3d8bbwe", "winget"), ("StoreEdgeFD", "msstore") })
            {
                var file = System.IO.Path.Combine(home, AppInstallerState, folder, "installed.db");
                try
                {
                    if (!SourcePresence.IsFile(file)) continue;   // inside the drive, no link on the way, then exists
                    list.Add(new WingetIndex(file, src, tracking: true));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or SqliteException or InvalidDataException)
                { notes.Add($"winget's record of installed {(src == "msstore" ? "Store " : "")}apps for {u.UserName} could not be read ({e.GetType().Name})."); }
            }
        }
        return list;
    }

    /// <summary>Opens a specific catalog file (read-only, immutable).</summary>
    public static WingetIndex OpenFile(string indexDb, string source = "winget", bool tracking = false) => new(indexDb, source, tracking);

    static Version? VersionOf(string folderName)
    {
        var parts = folderName.Split('_');
        return parts.Length > 1 && Version.TryParse(parts[1], out var v) ? v : null;
    }

    /// <summary>Fills WingetId for apps that have none. Returns how many apps were matched.</summary>
    public int Match(List<InstalledApp> apps)
    {
        int matched = 0;
        for (int i = 0; i < apps.Count; i++)
        {
            var a = apps[i];
            if (a.WingetId is not null || a.Kind is AppKind.Portable or AppKind.Runtime or AppKind.Driver) continue;
            var (id, method) = Find(a);
            if (id is null) continue;
            apps[i] = a with { WingetId = id, WingetSource = Source, MatchMethod = Tracking ? TrackedMethod : method };
            matched++;
        }
        return matched;
    }

    public (string? Id, string? Method) Find(InstalledApp a)
    {
        // Store / MSIX apps: only their package family name identifies them.
        if (a.Kind == AppKind.Store)
            return a.PackageFamilyName is { Length: > 0 } pfn && _pfns.TryGetValue(pfn.Trim(), out var byPfn) && Single(byPfn) is { } sid ? (sid, ExactMethod) : (null, null);

        foreach (var code in ExactKeys(a))
            if (_codes.TryGetValue(code, out var p) && Single(p) is { } id) return (id, ExactMethod);
        if (a.UpgradeCode is { Length: > 0 } uc && _upgrades.TryGetValue(Code(uc), out var up) && Single(up) is { } uid) return (uid, ExactMethod);

        var norm = WingetNormalizer.Name(a.Name);
        var name = norm.Name.ToLowerInvariant();
        var pub = NormalizePublisher(a.Publisher);
        if (name.Length < 2 || pub.Length == 0) return (null, null);
        // winget stores each name twice, plain and architecture-tagged ("python(X64)"), and looks for the tagged one first.
        var arch = norm.Architecture ?? a.Architecture switch { "x64" => "X64", "x86" => "X86", "arm64" => "Arm64", _ => null };
        foreach (var key in arch is null ? [name] : new[] { $"{name}({arch})", name })
        {
            if (!_names.TryGetValue(key, out var byName)) continue;
            var withPub = byName.Where(q => _publishersOf.TryGetValue(q, out var s) && s.Contains(pub)).ToHashSet();
            if (Single(withPub) is { } nid) return (nid, NameMethod);
            // Several packages share the name (Python 3.11 / 3.12): the installed version picks one if only one range fits.
            if (a.Version is { Length: > 0 } v && Single(withPub.Where(q => InRange(q, v))) is { } vid) return (vid, NameMethod);
        }
        return (null, null);
    }

    bool InRange(long pkg, string version) =>
        _ranges.TryGetValue(pkg, out var r) && (r.Min is null || CompareVersions(version, r.Min) >= 0) && (r.Max is null || CompareVersions(version, r.Max) <= 0);

    /// <summary>Compares dotted versions number by number ("3.12.4" &gt; "3.12"); text parts compare as text.</summary>
    public static int CompareVersions(string a, string b)
    {
        var x = a.Split('.', '-', '_', '+', ' '); var y = b.Split('.', '-', '_', '+', ' ');
        for (int i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            var p = i < x.Length ? x[i] : "0"; var q = i < y.Length ? y[i] : "0";
            int c = long.TryParse(p, out var pn) && long.TryParse(q, out var qn) ? pn.CompareTo(qn) : string.Compare(p, q, StringComparison.OrdinalIgnoreCase);
            if (c != 0) return c;
        }
        return 0;
    }

    /// <summary>MSI product code and the uninstall key's own name (winget stores both in its product codes).</summary>
    static IEnumerable<string> ExactKeys(InstalledApp a)
    {
        if (a.ProductCode is { Length: > 0 } pc) yield return Code(pc);
        const string Uninstall = @"\Uninstall\";
        var k = a.SourceKey.LastIndexOf(Uninstall, StringComparison.OrdinalIgnoreCase);
        if (k >= 0 && a.SourceKey[(k + Uninstall.Length)..] is { Length: > 0 } key && !key.Contains('\\')) yield return Code(key);
    }

    /// <summary>
    /// One package id, or null when there are none or several unrelated ones (never guess). Variants of one product are
    /// accepted: when one id is the parent of all others ("Google.Chrome" vs "Google.Chrome.EXE") the parent wins.
    /// </summary>
    string? Single(IEnumerable<long> packages)
    {
        var ids = packages.Select(p => _ids.GetValueOrDefault(p)).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (ids.Count <= 1) return ids.FirstOrDefault();
        var parent = ids.MinBy(i => i.Length)!;
        return ids.All(i => i.Equals(parent, StringComparison.OrdinalIgnoreCase) || i.StartsWith(parent + ".", StringComparison.OrdinalIgnoreCase)) ? parent : null;
    }

    /// <summary>winget's own name normalization (<see cref="WingetNormalizer"/>), lower-case. Empty when nothing is left.</summary>
    public static string NormalizeName(string? name) => WingetNormalizer.Name(name).Name.ToLowerInvariant();

    /// <summary>winget's own publisher normalization: the words before the first legal suffix (Inc, LLC, s.r.o...).</summary>
    public static string NormalizePublisher(string? publisher) => WingetNormalizer.Publisher(publisher).ToLowerInvariant();

    public void Dispose() { }   // the file is closed once loaded; kept for callers that use 'using'
}
