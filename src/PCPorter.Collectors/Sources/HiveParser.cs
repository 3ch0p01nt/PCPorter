using Registry;
using Registry.Abstractions;
using Registry.Cells;

namespace PCPorter.Collectors.Sources;

public sealed record ParsedHive(IRegKey? Root, bool Dirty, bool Replayed, string? Problem);

/// <summary>
/// Parses offline hive files (a dead PC's drive, or a not-signed-in user's NTUSER.DAT) entirely in memory.
/// Never writes a copy to disk; replays transaction logs in memory when the hive is dirty; refuses SAM/SECURITY.
/// </summary>
public static class HiveParser
{
    static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase) { "SOFTWARE", "SYSTEM", "NTUSER.DAT", "UsrClass.dat" };
    public const long MaxHiveBytes = 1L << 30;

    public static ParsedHive Parse(string hivePath)
    {
        var name = Path.GetFileName(hivePath);
        if (!Allowed.Contains(name))
            throw new UnauthorizedAccessException($"PCPorter does not read the {name} hive.");

        byte[] bytes;
        try
        {
            using var fs = SourceFiles.OpenRead(hivePath);   // confined to the scanned drive
            if (fs.Length == 0) return new ParsedHive(null, false, false, $"{name} is empty.");
            if (fs.Length > MaxHiveBytes) return new ParsedHive(null, false, false, $"{name} is larger than 1 GB; skipped.");
            bytes = new byte[fs.Length];
            fs.ReadExactly(bytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new ParsedHive(null, false, false, $"{name} could not be read: {e.Message}");
        }

        bool dirty = false;
        try
        {
            var hive = new RegistryHive(bytes, hivePath) { RecoverDeleted = false };
            dirty = hive.Header.PrimarySequenceNumber != hive.Header.SecondarySequenceNumber;
            bool replayed = false;
            if (dirty)
            {
                var logs = new[] { hivePath + ".LOG1", hivePath + ".LOG2" }.Where(File.Exists).ToList();
                if (logs.Count > 0)
                {
                    // updateExistingData: true applies the recovered bytes IN MEMORY (verified in the package source:
                    // it sets FileBytes and re-initialises; nothing is written to disk). false would discard them.
                    try { hive.ProcessTransactionLogs(logs, true); replayed = true; }
                    catch (Exception) { /* keep the original bytes; results flagged as from a dirty hive */ }
                }
            }
            if (!hive.ParseHive() || hive.Root is null) return new ParsedHive(null, dirty, replayed, $"{name} could not be parsed.");
            return new ParsedHive(new ParsedRegKey(hive.Root), dirty, replayed, dirty && !replayed ? $"{name} was not closed cleanly; some recent changes may be missing." : null);
        }
        catch (Exception e)
        {
            return new ParsedHive(null, dirty, false, $"{name} is damaged and could not be read ({e.GetType().Name}).");
        }
    }
}

/// <summary>IRegKey over the Registry package's parsed key. Paths are relative to this key, without the hive name.</summary>
public sealed class ParsedRegKey(RegistryKey key) : IRegKey
{
    public string Name => key.KeyName;
    public DateTimeOffset? LastWrite => key.LastWriteTime;
    public IEnumerable<IRegKey> SubKeys => key.SubKeys.Select(k => (IRegKey)new ParsedRegKey(k));
    public IEnumerable<string> ValueNames => key.Values.Select(v => IsDefault(v) ? "" : v.ValueName);

    /// <summary>The package names the unnamed value "(default)"; a value really called "(default)" has a name length.</summary>
    static bool IsDefault(Registry.Abstractions.KeyValue v) => v.VkRecord.NameLength == 0;

    public IRegKey? Open(string relativePath)
    {
        var current = key;
        foreach (var part in relativePath.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            current = current.SubKeys.FirstOrDefault(k => string.Equals(k.KeyName, part, StringComparison.OrdinalIgnoreCase));
            if (current is null) return null;
        }
        return new ParsedRegKey(current);
    }

    public (RegType Type, byte[] Raw)? GetRaw(string valueName)
    {
        var v = valueName.Length == 0
            ? key.Values.FirstOrDefault(IsDefault)
            : key.Values.FirstOrDefault(x => !IsDefault(x) && string.Equals(x.ValueName, valueName, StringComparison.OrdinalIgnoreCase));
        if (v is null) return null;
        return (Map(v.VkRecord.DataType), v.ValueDataRaw ?? []);
    }

    static RegType Map(VkCellRecord.DataTypeEnum t) => t switch
    {
        VkCellRecord.DataTypeEnum.RegNone => RegType.None,
        VkCellRecord.DataTypeEnum.RegSz => RegType.String,
        VkCellRecord.DataTypeEnum.RegExpandSz => RegType.ExpandString,
        VkCellRecord.DataTypeEnum.RegBinary => RegType.Binary,
        VkCellRecord.DataTypeEnum.RegDword => RegType.DWord,
        VkCellRecord.DataTypeEnum.RegMultiSz => RegType.MultiString,
        VkCellRecord.DataTypeEnum.RegQword => RegType.QWord,
        VkCellRecord.DataTypeEnum.RegDwordBigEndian => RegType.DWordBigEndian,
        _ => RegType.Other,
    };
}
