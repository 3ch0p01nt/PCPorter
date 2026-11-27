using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Health;

/// <summary>Shared helpers for collector tests.</summary>
public static class TestContexts
{
    public static CollectorContext For(ISystemSource src, IWmiClient? wmi = null, IProcessRunner? processes = null, string? work = null, bool includeDefenderPrefs = false) =>
        new(src, wmi ?? new FakeWmiClient(), processes ?? new FakeProcessRunner((_, _) => new ProcessResult(1, "", false)),
            new NoSignatureChecker(), work ?? Path.Combine(Path.GetTempPath(), "pcporter-test-work-" + Guid.NewGuid().ToString("N")),
            new List<string>(), null, includeDefenderPrefs);

    public static Dictionary<string, object?> Row(params (string Key, object? Value)[] values)
    {
        var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in values) d[k] = v;
        return d;
    }

    /// <summary>SYSTEM hive with Select\Current=1 and ControlSet001 configured by <paramref name="cs"/>.</summary>
    public static RegSpec SystemHive(Action<RegSpec>? cs = null) =>
        RegSpec.Root().Key("Select", k => k.Num("Current", 1)).Key("ControlSet001", k => { k.Key("Services"); cs?.Invoke(k); });
}

/// <summary>Records namespace, query and timeout of every call; answers like <see cref="FakeWmiClient"/>.</summary>
public sealed class RecordingWmiClient(IWmiClient inner) : IWmiClient
{
    public List<(string Ns, string Wql, TimeSpan? Timeout)> Calls { get; } = [];
    public WmiResult Query(string ns, string wql, TimeSpan? timeout = null)
    {
        Calls.Add((ns, wql, timeout));
        return inner.Query(ns, wql, timeout);
    }
}
