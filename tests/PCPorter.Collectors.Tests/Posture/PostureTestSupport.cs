using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Posture;

public static class PT
{
    public static readonly DateTimeOffset Now = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
    public static readonly UserProfile Bob = new("S-1-5-21-1-2-3-1001", "bob", null, null);
    public static readonly UserProfile Ann = new("S-1-5-21-1-2-3-1002", "ann", null, null);
    public const string Ccs = "ControlSet001";

    /// <summary>A SYSTEM hive whose current control set is ControlSet001, configured by <paramref name="ccs"/>.</summary>
    public static RegSpec System(Action<RegSpec>? ccs = null) =>
        RegSpec.Root().Key("Select", k => k.Num("Current", 1)).Key(Ccs, k => ccs?.Invoke(k));

    public static (List<PostureCheck> Checks, CollectorOutput Output, List<string> Warnings) Run(
        ISystemSource src, IWmiClient? wmi = null, PostureOptions? options = null)
    {
        var warnings = new List<string>();
        var ctx = new CollectorContext(src, wmi ?? new FakeWmiClient(), new FakeProcessRunner((_, _) => new ProcessResult(0, "", false)),
            new NoSignatureChecker(), Path.GetTempPath(), warnings);
        var output = new SecurityPostureCollector(options ?? new PostureOptions(Now: Now, Listeners: () => [], DriveSpace: _ => (50, 100))).Run(ctx, CancellationToken.None);
        return (output.Items.Cast<PostureCheck>().ToList(), output, warnings);
    }

    public static PostureCheck Check(ISystemSource src, string id, IWmiClient? wmi = null, PostureOptions? options = null) =>
        Run(src, wmi, options).Checks.Single(c => c.Id == id);

    public static FakeSystemSource Offline(RegSpec? software = null, RegSpec? system = null,
        Dictionary<string, RegSpec>? users = null, string? root = null) =>
        new(root ?? Path.GetTempPath(), software, system, users, users?.Keys.Select(sid => sid == Ann.Sid ? Ann : Bob).ToList());

    public static FakeSystemSource Live(RegSpec? software = null, RegSpec? system = null, Dictionary<string, RegSpec>? users = null) =>
        new(Path.GetTempPath(), software, system, users, users?.Keys.Select(sid => sid == Ann.Sid ? Ann : Bob).ToList(), live: true);

    public static Dictionary<string, object?> Row(params (string Name, object? Value)[] values) =>
        values.ToDictionary(v => v.Name, v => v.Value, StringComparer.OrdinalIgnoreCase);
}

/// <summary>Wraps a key tree, records every value read (as "path|value") and can override LastWrite per key name.</summary>
public sealed class SpyRegKey(IRegKey inner, List<string> reads, string path = "", Func<string, DateTimeOffset?>? lastWrite = null) : IRegKey
{
    public string Name => inner.Name;
    public DateTimeOffset? LastWrite => lastWrite?.Invoke(inner.Name) ?? inner.LastWrite;
    public IEnumerable<IRegKey> SubKeys => inner.SubKeys.Select(k => (IRegKey)new SpyRegKey(k, reads, path + "\\" + k.Name, lastWrite));
    public IEnumerable<string> ValueNames => inner.ValueNames;
    public IRegKey? Open(string relativePath) =>
        inner.Open(relativePath) is { } k ? new SpyRegKey(k, reads, path + "\\" + relativePath.Trim('\\'), lastWrite) : null;
    public (RegType Type, byte[] Raw)? GetRaw(string valueName)
    {
        reads.Add(path + "|" + valueName);
        return inner.GetRaw(valueName);
    }
}

/// <summary>A source whose hives are wrapped in <see cref="SpyRegKey"/>.</summary>
public sealed class SpySource(FakeSystemSource inner, List<string> reads, Func<string, DateTimeOffset?>? lastWrite = null) : ISystemSource
{
    public bool IsLive => inner.IsLive;
    public string ReadRoot => inner.ReadRoot;
    public string OriginalSystemDrive => inner.OriginalSystemDrive;
    public string? MapPath(string p) => inner.MapPath(p);
    public IRegKey? OpenHive(Hive hive, UserProfile? user = null) =>
        inner.OpenHive(hive, user) is { } k ? new SpyRegKey(k, reads, hive.ToString(), lastWrite) : null;
    public string? CurrentControlSet() => inner.CurrentControlSet();
    public IReadOnlyList<UserProfile> Users => inner.Users;
    public IReadOnlyList<string> Notes => inner.Notes;
    public void Dispose() => inner.Dispose();
}
