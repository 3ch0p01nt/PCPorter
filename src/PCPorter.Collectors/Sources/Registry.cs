using System.Buffers.Binary;
using System.Text;

namespace PCPorter.Collectors.Sources;

/// <summary>Registry hives PCPorter reads. SAM and SECURITY are deliberately absent: they hold password hashes and are never touched.</summary>
public enum Hive { Software, System, NtUser, UsrClass }

public enum RegType { None, String, ExpandString, Binary, DWord, MultiString, QWord, Other, DWordBigEndian }

/// <summary>Read-only view of a registry key, the same for the live registry, an offline hive and test fakes.</summary>
public interface IRegKey
{
    string Name { get; }
    DateTimeOffset? LastWrite { get; }
    IEnumerable<IRegKey> SubKeys { get; }
    IEnumerable<string> ValueNames { get; }               // includes "" for the default value when set
    IRegKey? Open(string relativePath);                   // case-insensitive, no hive name in the path
    (RegType Type, byte[] Raw)? GetRaw(string valueName);
}

/// <summary>All value decoding lives here, so live, offline and fake keys behave identically.</summary>
public static class RegValueDecoder
{
    public static string? AsString((RegType Type, byte[] Raw)? v)
    {
        if (v is not { } x) return null;
        switch (x.Type)
        {
            case RegType.String or RegType.ExpandString:
                return Utf16UntilNul(x.Raw);
            case RegType.MultiString:
                return string.Join("\n", Multi(x.Raw));
            case RegType.DWord or RegType.DWordBigEndian or RegType.QWord:
                return AsNumber(x)?.ToString(System.Globalization.CultureInfo.InvariantCulture);
            default:
                return null;
        }
    }

    /// <summary>
    /// Numbers, including numbers stored as text (real Uninstall keys often store SystemComponent as a string).
    /// DWORDs longer than 4 bytes use their first 4 bytes (Windows itself tolerates this).
    /// </summary>
    public static long? AsNumber((RegType Type, byte[] Raw)? v)
    {
        if (v is not { } x) return null;
        return x.Type switch
        {
            RegType.DWord when x.Raw.Length >= 4 => BinaryPrimitives.ReadUInt32LittleEndian(x.Raw),
            RegType.DWordBigEndian when x.Raw.Length >= 4 => BinaryPrimitives.ReadUInt32BigEndian(x.Raw),
            RegType.QWord when x.Raw.Length >= 8 => unchecked((long)BinaryPrimitives.ReadUInt64LittleEndian(x.Raw)),
            RegType.String or RegType.ExpandString => long.TryParse(Utf16UntilNul(x.Raw).Trim(),
                System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : null,
            RegType.Binary when x.Raw.Length == 4 => BinaryPrimitives.ReadUInt32LittleEndian(x.Raw),
            _ => null,
        };
    }

    public static IReadOnlyList<string>? AsMulti((RegType Type, byte[] Raw)? v) => v is { Type: RegType.MultiString } x ? Multi(x.Raw)
        : v is { Type: RegType.String or RegType.ExpandString } s ? [Utf16UntilNul(s.Raw)] : null;

    static string Utf16UntilNul(byte[] raw)
    {
        var s = Encoding.Unicode.GetString(raw, 0, raw.Length & ~1);
        int nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }

    /// <summary>Keeps empty entries in the middle (Windows does); only the terminating NULs are dropped.</summary>
    static string[] Multi(byte[] raw)
    {
        var s = Encoding.Unicode.GetString(raw, 0, raw.Length & ~1).TrimEnd('\0');
        return s.Length == 0 ? [] : s.Split('\0');
    }

    // Encoders (used by live keys and fakes to produce the same raw form Windows stores).
    public static byte[] EncodeString(string s) => Encoding.Unicode.GetBytes(s + "\0");
    public static byte[] EncodeMulti(IEnumerable<string> items) => Encoding.Unicode.GetBytes(string.Concat(items.Select(i => i + "\0")) + "\0");
    public static byte[] EncodeDWord(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); return b; }
    public static byte[] EncodeQWord(ulong v) { var b = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); return b; }
}

public static class RegKeyExtensions
{
    public static string? GetString(this IRegKey k, string name) => RegValueDecoder.AsString(k.GetRaw(name));
    public static long? GetNumber(this IRegKey k, string name) => RegValueDecoder.AsNumber(k.GetRaw(name));
    public static IReadOnlyList<string>? GetMulti(this IRegKey k, string name) => RegValueDecoder.AsMulti(k.GetRaw(name));
    public static byte[]? GetBytes(this IRegKey k, string name) => k.GetRaw(name)?.Raw;
}
