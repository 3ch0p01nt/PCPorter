using System.Globalization;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Posture;

/// <summary>A TCP port something is listening on (live only).</summary>
public sealed record PortListener(string Address, int Port, int ProcessId, string? ProcessName)
{
    public bool AllInterfaces => Address is "0.0.0.0" or "::";
}

/// <summary>Test seams for the posture collector. Defaults read the real clock, TCP table and drive.</summary>
public sealed record PostureOptions(
    DateTimeOffset? Now = null,
    Func<IReadOnlyList<PortListener>>? Listeners = null,
    Func<string, (long Free, long Total)?>? DriveSpace = null);

/// <summary>Hives opened once per run, plus small helpers shared by the checks. Everything is read-only.</summary>
internal sealed class PostureScan : IDisposable
{
    public ISystemSource Source { get; }
    public IWmiClient Wmi { get; }
    public PostureOptions Options { get; }
    public DateTimeOffset Now { get; }
    public DateOnly Today => DateOnly.FromDateTime(Now.UtcDateTime);
    public IRegKey? Software { get; }
    public IRegKey? System { get; }
    public IRegKey? ControlSet { get; }
    public string? ControlSetName { get; }
    public IReadOnlyList<(UserProfile User, IRegKey Hive)> UserHives { get; }
    public int UsersWithoutHive { get; }
    public IList<string> Warnings { get; }

    public PostureScan(CollectorContext ctx, PostureOptions options)
    {
        Source = ctx.Source;
        Wmi = ctx.Wmi;
        Options = options;
        Warnings = ctx.Warnings;
        Now = options.Now ?? DateTimeOffset.UtcNow;
        Software = Source.OpenHive(Hive.Software);
        System = Source.OpenHive(Hive.System);
        ControlSetName = System is null ? null : Source.CurrentControlSet();
        ControlSet = ControlSetName is null ? null : System?.Open(ControlSetName);
        var hives = new List<(UserProfile, IRegKey)>();
        int missing = 0;
        foreach (var u in Source.Users)
        {
            IRegKey? h = null;
            try { h = u.Unavailable is null ? Source.OpenHive(Hive.NtUser, u) : null; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException) { }
            if (h is null) missing++; else hives.Add((u, h));
        }
        UserHives = hives;
        UsersWithoutHive = missing;
    }

    public bool IsLive => Source.IsLive;

    /// <summary>Opens a path under a root; null when the root or the key is missing.</summary>
    public static IRegKey? Open(IRegKey? root, string path) => root?.Open(path);

    /// <summary>Runs <paramref name="read"/> on a key and disposes it afterwards.</summary>
    public static T With<T>(IRegKey? root, string path, Func<IRegKey?, T> read)
    {
        var k = root?.Open(path);
        try { return read(k); }
        finally { (k as IDisposable)?.Dispose(); }
    }

    public static void Dispose(object? o) => (o as IDisposable)?.Dispose();

    /// <summary>The scanned PC's build number (CurrentBuild, else CurrentBuildNumber).</summary>
    public int? Build() => With(Software, @"Microsoft\Windows NT\CurrentVersion", k =>
        int.TryParse(k?.GetString("CurrentBuild") ?? k?.GetString("CurrentBuildNumber"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var b) ? b : (int?)null);

    public WmiResult Query(string ns, string wql) => Wmi.Query(ns, wql);

    public void Dispose()
    {
        foreach (var (_, h) in UserHives) Dispose(h);
        Dispose(ControlSet);
        Dispose(System);
        Dispose(Software);
    }
}

/// <summary>Converts WMI property values safely (they arrive as bool, numbers or strings).</summary>
internal static class WmiValue
{
    public static bool? Bool(IReadOnlyDictionary<string, object?> row, string name) =>
        row.TryGetValue(name, out var v) ? v switch
        {
            bool b => b,
            string s when bool.TryParse(s, out var b) => b,
            string s when s == "1" => true,
            string s when s == "0" => false,
            null => null,
            _ => Long(row, name) is { } n ? n != 0 : null,
        } : null;

    public static long? Long(IReadOnlyDictionary<string, object?> row, string name)
    {
        if (!row.TryGetValue(name, out var v) || v is null) return null;
        try
        {
            return v switch
            {
                string s => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null,
                ulong u => u > long.MaxValue ? null : (long)u,
                IConvertible c => c.ToInt64(CultureInfo.InvariantCulture),
                _ => null,
            };
        }
        catch (Exception e) when (e is FormatException or InvalidCastException or OverflowException) { return null; }
    }

    public static string? Str(IReadOnlyDictionary<string, object?> row, string name) =>
        row.TryGetValue(name, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
}
