using System.Collections.Concurrent;
using PCPorter.Collectors.Sources;

namespace PCPorter.TestKit;

/// <summary>
/// Wraps a source and records every registry key opened and every value read, as "SOFTWARE\path" and
/// "SOFTWARE\path:Value" (user hives as "NTUSER(bob)\..."). The denylist regression test checks the log.
/// </summary>
public sealed class SpySource(ISystemSource inner) : ISystemSource
{
    public ConcurrentQueue<string> Log { get; } = new();

    public bool IsLive => inner.IsLive;
    public string ReadRoot => inner.ReadRoot;
    public string OriginalSystemDrive => inner.OriginalSystemDrive;
    /// <summary>Every path MapPath returned (collectors then call File.Exists and friends on these directly).</summary>
    public ConcurrentQueue<string> Mapped { get; } = new();

    public string? MapPath(string p)
    {
        var mapped = inner.MapPath(p);
        if (mapped is not null) Mapped.Enqueue(mapped);
        return mapped;
    }
    public string? CurrentControlSet() => inner.CurrentControlSet();
    public IReadOnlyList<UserProfile> Users => inner.Users;
    public IReadOnlyList<string> Notes => inner.Notes;
    public void Dispose() => inner.Dispose();

    public IRegKey? OpenHive(Hive hive, UserProfile? user = null)
    {
        var name = hive switch { Hive.Software => "SOFTWARE", Hive.System => "SYSTEM", _ => $"{hive.ToString().ToUpperInvariant()}({user?.UserName})" };
        Log.Enqueue(name);
        return inner.OpenHive(hive, user) is { } k ? new SpyKey(k, name, Log) : null;
    }

    sealed class SpyKey(IRegKey inner, string path, ConcurrentQueue<string> log) : IRegKey
    {
        public string Name => inner.Name;
        public DateTimeOffset? LastWrite => inner.LastWrite;
        public IEnumerable<string> ValueNames => inner.ValueNames;
        public IEnumerable<IRegKey> SubKeys => inner.SubKeys.Select(k => (IRegKey)new SpyKey(k, path + "\\" + k.Name, log));

        public IRegKey? Open(string relativePath)
        {
            var p = path + "\\" + relativePath.Trim('\\');
            log.Enqueue(p);
            return inner.Open(relativePath) is { } k ? new SpyKey(k, p, log) : null;
        }

        public (RegType Type, byte[] Raw)? GetRaw(string valueName)
        {
            log.Enqueue(path + ":" + valueName);
            return inner.GetRaw(valueName);
        }
    }
}
