using PCPorter.Collectors.Sources;

namespace PCPorter.TestKit;

/// <summary>A registry tree described once, then materialised as a fake key, a real hive file (offreg) or live HKCU keys.</summary>
public sealed class RegSpec
{
    public string Name { get; }
    public Dictionary<string, RegSpec> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, (RegType Type, byte[] Raw)> Values { get; } = new(StringComparer.OrdinalIgnoreCase);

    public RegSpec(string name = "") => Name = name;
    public static RegSpec Root() => new();

    /// <summary>Gets or creates a nested key and optionally configures it.</summary>
    public RegSpec Key(string path, Action<RegSpec>? configure = null)
    {
        var node = this;
        foreach (var part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!node.Keys.TryGetValue(part, out var child)) node.Keys[part] = child = new RegSpec(part);
            node = child;
        }
        configure?.Invoke(node);
        return this;
    }

    public RegSpec Str(string name, string value) { Values[name] = (RegType.String, RegValueDecoder.EncodeString(value)); return this; }
    public RegSpec Exp(string name, string value) { Values[name] = (RegType.ExpandString, RegValueDecoder.EncodeString(value)); return this; }
    public RegSpec Num(string name, uint value) { Values[name] = (RegType.DWord, RegValueDecoder.EncodeDWord(value)); return this; }
    public RegSpec QNum(string name, ulong value) { Values[name] = (RegType.QWord, RegValueDecoder.EncodeQWord(value)); return this; }
    public RegSpec Multi(string name, params string[] values) { Values[name] = (RegType.MultiString, RegValueDecoder.EncodeMulti(values)); return this; }
    public RegSpec Bin(string name, params byte[] value) { Values[name] = (RegType.Binary, value); return this; }
    /// <summary>Exact type + bytes, for odd cases (REG_NONE, big-endian DWORD, over-long DWORD).</summary>
    public RegSpec Raw(string name, RegType type, params byte[] value) { Values[name] = (type, value); return this; }

    public static uint Win32Type(RegType t) => t switch
    {
        RegType.None => 0, RegType.String => 1, RegType.ExpandString => 2, RegType.Binary => 3, RegType.DWord => 4,
        RegType.DWordBigEndian => 5, RegType.MultiString => 7, RegType.QWord => 11, _ => 3,
    };

    public IRegKey ToFake(DateTimeOffset? lastWrite = null) => new FakeRegKey(this, lastWrite ?? new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
}

public sealed class FakeRegKey(RegSpec spec, DateTimeOffset lastWrite) : IRegKey
{
    public string Name => spec.Name;
    public DateTimeOffset? LastWrite => lastWrite;
    public IEnumerable<IRegKey> SubKeys => spec.Keys.Values.Select(k => (IRegKey)new FakeRegKey(k, lastWrite));
    public IEnumerable<string> ValueNames => spec.Values.Keys;

    public IRegKey? Open(string relativePath)
    {
        var node = spec;
        foreach (var part in relativePath.Split('\\', StringSplitOptions.RemoveEmptyEntries))
            if (!node.Keys.TryGetValue(part, out node!)) return null;
        return new FakeRegKey(node, lastWrite);
    }

    public (RegType Type, byte[] Raw)? GetRaw(string valueName) => spec.Values.TryGetValue(valueName, out var v) ? v : null;
}
