using PCPorter.Collectors.Health;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Security;

/// <summary>Defender exclusion lists. <see cref="Unknown"/> explains entries that could not be read (e.g. not elevated).</summary>
public sealed record DefenderExclusions(IReadOnlyList<string> Paths, IReadOnlyList<string> Extensions, IReadOnlyList<string> Processes,
    string Source, string? Unknown = null);

/// <summary>One antivirus / security product. ItemKey = catalog vendor id (or "other:&lt;name&gt;" for unknown WSC products).</summary>
public sealed record AvProduct(
    string ItemKey,
    string Vendor,
    string? WscDisplayName,
    IReadOnlyList<string> Roles,              // antivirus, antispyware, firewall (from WSC)
    bool Confirmed,
    IReadOnlyList<string> Evidence,
    WscState? State,
    bool? UpToDate,
    bool? IsMicrosoft,
    uint? ProductStateRaw,
    string? Status,                           // plain words: "on", "license expired", "passive"...
    string? WscTimestamp,                     // staleness hint
    string? ProductExe,
    string? AccountUrl,
    string? VendorNote,
    string? DefenderMode,
    bool? RealTimeProtection,
    DefenderExclusions? Exclusions) : IScanItem;

/// <summary>
/// Finds antivirus products: Windows Security Center (live), installed-app names and service names (both modes),
/// Defender status (live) and Defender exclusions (only when allowed). Read-only; never throws for bad data.
/// </summary>
public sealed class AvDetector : ICollector
{
    public const string Kind = "av";
    public const string SecurityCenterNs = @"root\SecurityCenter2";
    public const string DefenderNs = @"root\Microsoft\Windows\Defender";
    public const string DefenderUri = "windowsdefender://";

    static readonly (string Class, string Role)[] WscClasses =
        [("AntiVirusProduct", "antivirus"), ("AntiSpywareProduct", "antispyware"), ("FirewallProduct", "firewall")];

    static readonly string[] UninstallPaths =
        [@"Microsoft\Windows\CurrentVersion\Uninstall", @"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"];

    public string Name => "Antivirus";

    sealed class Builder(string key, string vendor, AvVendor? catalog)
    {
        public string Key = key, Vendor = vendor;
        public AvVendor? Catalog = catalog;
        public string? WscName, Status, Timestamp, Exe, DefenderMode;
        public readonly SortedSet<string> Roles = new(StringComparer.Ordinal);
        public readonly List<string> Evidence = [];
        public bool Confirmed;
        public ProductStatus? Wsc;
        public uint? Raw;
        public bool? RealTime;
        public DefenderExclusions? Exclusions;

        public void AddEvidence(string e) { if (!Evidence.Contains(e, StringComparer.OrdinalIgnoreCase)) Evidence.Add(e); }

        public AvProduct Build() => new(Key, Vendor, WscName, Roles.ToList(), Confirmed, Evidence.ToList(), Wsc?.State, Wsc?.UpToDate,
            Wsc?.IsMicrosoft, Raw, Status, Timestamp, Exe, Catalog?.AccountUrl, Catalog?.Note, DefenderMode, RealTime, Exclusions);
    }

    public CollectorOutput Run(CollectorContext ctx, CancellationToken ct)
    {
        var notes = new List<string>();
        var found = new Dictionary<string, Builder>(StringComparer.OrdinalIgnoreCase);
        bool failed = false;
        var src = ctx.Source;

        IRegKey? software = Safe(() => src.OpenHive(Hive.Software), ctx, "SOFTWARE hive", ref failed);
        IRegKey? system = Safe(() => src.OpenHive(Hive.System), ctx, "SYSTEM hive", ref failed);
        string? ccs = Safe(() => src.CurrentControlSet(), ctx, "control set", ref failed);
        var services = system is not null && ccs is not null ? system.Open($@"{ccs}\Services") : null;
        bool winDefendExists = services?.Open("WinDefend") is not null;

        Builder For(AvVendor? v, string? displayName)
        {
            var key = v?.Id ?? "other:" + (displayName ?? "unknown").Trim().ToLowerInvariant();
            if (!found.TryGetValue(key, out var b)) found[key] = b = new Builder(key, v?.Name ?? displayName?.Trim() ?? "Unknown product", v);
            return b;
        }

        // 1. Windows Security Center (live only).
        if (src.IsLive)
        {
            foreach (var (cls, role) in WscClasses)
            {
                if (ct.IsCancellationRequested) return Cancelled(found, notes);
                try
                {
                    var r = ctx.Wmi.Query(SecurityCenterNs, $"SELECT * FROM {cls}");
                    if (r.Outcome != WmiOutcome.Ok)
                    {
                        if (cls == "AntiVirusProduct") notes.Add($"Windows Security Center did not answer ({r.Outcome}).");
                        continue;
                    }
                    foreach (var row in r.Rows)
                    {
                        var name = WmiValue.Str(row, "displayName");
                        if (name is null) continue;
                        var b = For(AvVendors.ByName(name), name);
                        b.WscName ??= name;
                        b.Roles.Add(role);
                        b.AddEvidence("Listed in Windows Security Center");
                        b.Timestamp ??= WmiValue.Str(row, "timestamp");
                        var exe = WmiValue.Str(row, "pathToSignedProductExe");
                        b.Exe ??= exe;
                        if (WmiValue.Long(row, "productState") is { } ps and >= 0 and <= uint.MaxValue && (b.Raw is null || role == "antivirus"))
                        {
                            b.Raw = (uint)ps;
                            b.Wsc = ProductState.Decode((uint)ps);
                            b.Status = ProductState.Describe(b.Wsc);
                        }
                        if (IsConfirmed(exe, src, winDefendExists)) b.Confirmed = true;
                    }
                }
                catch (Exception e) { failed = true; ctx.Warnings.Add($"Antivirus: Security Center query {cls} failed: {e.Message}"); }
            }
        }

        // 2a. Installed-app names (both modes). WinDefend is never evidence.
        if (software is not null)
        {
            try
            {
                foreach (var path in UninstallPaths)
                    foreach (var k in software.Open(path)?.SubKeys ?? [])
                    {
                        var dn = k.GetString("DisplayName");
                        if (AvVendors.ByName(dn) is { } v) For(v, dn).AddEvidence($"Installed app: {dn}");
                    }
            }
            catch (Exception e) { failed = true; ctx.Warnings.Add($"Antivirus: reading installed apps failed: {e.Message}"); }
        }

        // 2b. Service names (both modes).
        if (services is not null)
        {
            try
            {
                foreach (var k in services.SubKeys)
                {
                    if (string.Equals(k.Name, "WinDefend", StringComparison.OrdinalIgnoreCase)) continue;
                    if (AvVendors.ByService(k.Name) is { } v) For(v, null).AddEvidence($"Service: {k.Name}");
                }
            }
            catch (Exception e) { failed = true; ctx.Warnings.Add($"Antivirus: reading services failed: {e.Message}"); }
        }
        else notes.Add("Services could not be read; antivirus detection by service name was skipped.");

        if (ct.IsCancellationRequested) return Cancelled(found, notes);

        // 3. Defender status (live).
        var defender = AvVendors.All.First(v => v.Id == AvVendors.DefenderId);
        if (src.IsLive)
        {
            try
            {
                var r = ctx.Wmi.Query(DefenderNs, "SELECT AMRunningMode, RealTimeProtectionEnabled FROM MSFT_MpComputerStatus");
                if (r.Outcome == WmiOutcome.Ok && r.Rows.Count > 0)
                {
                    var b = For(defender, null);
                    var mode = WmiValue.Str(r.Rows[0], "AMRunningMode");
                    b.DefenderMode = mode;
                    b.RealTime = WmiValue.Bool(r.Rows[0], "RealTimeProtectionEnabled");
                    b.AddEvidence("Defender status reported by Defender");
                    b.Status = DefenderStatus(mode);
                    if (string.Equals(mode, "Normal", StringComparison.OrdinalIgnoreCase) && winDefendExists) b.Confirmed = true;
                }
                else if (r.Outcome == WmiOutcome.AccessDenied) notes.Add("Defender status: unknown (not elevated).");
                else if (r.Outcome != WmiOutcome.Ok) notes.Add($"Defender status could not be read ({r.Outcome}).");
            }
            catch (Exception e) { failed = true; ctx.Warnings.Add($"Antivirus: Defender status failed: {e.Message}"); }
        }

        // 4. Defender exclusions: only when asked, or on a PC that no organization manages.
        try
        {
            bool? domain = src.IsLive ? JoinState.DomainJoinedFromWmi(ctx.Wmi) ?? JoinState.DomainJoinedFromHive(system, ccs) : JoinState.DomainJoinedFromHive(system, ccs);
            bool? entra = JoinState.EntraJoinedFromHive(software, system, ccs);
            bool managed = domain == true || entra == true;
            if (managed && !ctx.IncludeDefenderPreferences)
                notes.Add("Defender exclusions were not read because this PC is joined to a work domain or Entra ID (use --include-defender-prefs to read them).");
            else
            {
                var ex = src.IsLive ? LiveExclusions(ctx.Wmi, notes) : OfflineExclusions(software);
                if (ex is not null)
                {
                    if (found.TryGetValue(AvVendors.DefenderId, out var b)) b.Exclusions = ex;
                    else if (ex.Paths.Count + ex.Extensions.Count + ex.Processes.Count > 0)
                    {
                        b = For(defender, null);
                        b.Exclusions = ex;
                        b.AddEvidence("Defender exclusion list present");
                    }
                }
            }
        }
        catch (Exception e) { failed = true; ctx.Warnings.Add($"Antivirus: Defender exclusions failed: {e.Message}"); }

        var items = found.Values.OrderBy(b => b.Key, StringComparer.Ordinal).Select(b => (IScanItem)b.Build()).ToList();
        return new CollectorOutput(Kind, items, notes, failed ? CollectorStatus.Partial : CollectorStatus.Ok);
    }

    static CollectorOutput Cancelled(Dictionary<string, Builder> found, List<string> notes) =>
        new(Kind, found.Values.Select(b => (IScanItem)b.Build()).ToList(), notes, CollectorStatus.Cancelled);

    static T? Safe<T>(Func<T?> f, CollectorContext ctx, string what, ref bool failed)
    {
        try { return f(); }
        catch (Exception e) { failed = true; ctx.Warnings.Add($"Antivirus: could not read {what}: {e.Message}"); return default; }
    }

    /// <summary>WSC entry is real when its product exe exists, or it is Defender's URI and the WinDefend service exists.</summary>
    public static bool IsConfirmed(string? pathToSignedProductExe, ISystemSource src, bool winDefendExists)
    {
        if (string.IsNullOrWhiteSpace(pathToSignedProductExe)) return false;
        if (pathToSignedProductExe.Trim().StartsWith(DefenderUri, StringComparison.OrdinalIgnoreCase)) return winDefendExists;
        try { return src.MapPath(pathToSignedProductExe) is { } p && SourcePresence.IsFile(p); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    public static string DefenderStatus(string? mode) => mode switch
    {
        _ when string.Equals(mode, "Normal", StringComparison.OrdinalIgnoreCase) => "active",
        _ when mode?.Contains("Passive", StringComparison.OrdinalIgnoreCase) == true => "passive (another antivirus is in charge)",
        _ when mode?.Contains("EDR Block", StringComparison.OrdinalIgnoreCase) == true => "EDR block mode (passive, blocks what the EDR finds)",
        _ => "not running",
    };

    static DefenderExclusions? LiveExclusions(IWmiClient wmi, List<string> notes)
    {
        var r = wmi.Query(DefenderNs, "SELECT ExclusionPath, ExclusionExtension, ExclusionProcess FROM MSFT_MpPreference");
        if (r.Outcome == WmiOutcome.AccessDenied) { notes.Add("Defender exclusions: unknown (not elevated)."); return null; }
        if (r.Outcome != WmiOutcome.Ok || r.Rows.Count == 0) { notes.Add($"Defender exclusions could not be read ({r.Outcome})."); return null; }
        var row = r.Rows[0];
        string? unknown = null;
        IReadOnlyList<string> Clean(string name)
        {
            var all = WmiValue.Strings(row, name);
            // Newer Defender returns "N/A: Must be an administrator to view exclusions" to standard users.
            if (all.Any(s => s.StartsWith("N/A", StringComparison.OrdinalIgnoreCase))) unknown = "unknown (not elevated)";
            return all.Where(s => !s.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        var ex = new DefenderExclusions(Clean("ExclusionPath"), Clean("ExclusionExtension"), Clean("ExclusionProcess"), "live", null);
        return ex with { Unknown = unknown };
    }

    static DefenderExclusions? OfflineExclusions(IRegKey? software)
    {
        var root = software?.Open(@"Microsoft\Windows Defender\Exclusions");
        if (root is null) return null;
        IReadOnlyList<string> Names(string sub) => root.Open(sub)?.ValueNames.Where(n => n.Length > 0).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList() ?? [];
        return new DefenderExclusions(Names("Paths"), Names("Extensions"), Names("Processes"), "offline registry");
    }
}
