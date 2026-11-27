using System.Globalization;

namespace PCPorter.Collectors.Health;

/// <summary>Tolerant conversions for WMI property values (real WMI gives uint/ulong/ushort[]..., fakes give int/long/string).</summary>
public static class WmiValue
{
    public static object? Get(IReadOnlyDictionary<string, object?> row, string name) => row.TryGetValue(name, out var v) ? v : null;

    public static string? Str(IReadOnlyDictionary<string, object?> row, string name) => Get(row, name) switch
    {
        null => null,
        string s => string.IsNullOrWhiteSpace(s) ? null : s.Trim(),
        ushort[] u => Chars(u),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        var o => o.ToString(),
    };

    public static long? Long(IReadOnlyDictionary<string, object?> row, string name)
    {
        var v = Get(row, name);
        try
        {
            return v switch
            {
                null => null,
                string s => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null,
                ulong u => u > long.MaxValue ? null : (long)u,
                IConvertible c => c.ToInt64(CultureInfo.InvariantCulture),
                _ => null,
            };
        }
        catch (Exception e) when (e is FormatException or InvalidCastException or OverflowException) { return null; }
    }

    public static double? Double(IReadOnlyDictionary<string, object?> row, string name)
    {
        var v = Get(row, name);
        try { return v is IConvertible c and not string ? c.ToDouble(CultureInfo.InvariantCulture) : v is string s && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null; }
        catch (Exception e) when (e is FormatException or InvalidCastException or OverflowException) { return null; }
    }

    public static bool? Bool(IReadOnlyDictionary<string, object?> row, string name) => Get(row, name) switch
    {
        bool b => b,
        string s when bool.TryParse(s, out var b) => b,
        null => null,
        _ => Long(row, name) is { } n ? n != 0 : null,
    };

    public static IReadOnlyList<string> Strings(IReadOnlyDictionary<string, object?> row, string name) => Get(row, name) switch
    {
        string[] a => a.Where(s => !string.IsNullOrWhiteSpace(s)).ToList(),
        string s when !string.IsNullOrWhiteSpace(s) => [s],
        object[] o => o.OfType<string>().Where(s => !string.IsNullOrWhiteSpace(s)).ToList(),
        _ => [],
    };

    /// <summary>WmiMonitorID stores text as UInt16[] padded with NULs.</summary>
    public static string? Chars(IEnumerable<ushort>? codes)
    {
        if (codes is null) return null;
        var s = new string(codes.TakeWhile(c => c != 0).Select(c => (char)c).ToArray()).Trim();
        return s.Length == 0 ? null : s;
    }

    /// <summary>DMTF datetime (yyyyMMddHHmmss.ffffff+UUU) or a DateTime.</summary>
    public static DateTimeOffset? Time(IReadOnlyDictionary<string, object?> row, string name)
    {
        switch (Get(row, name))
        {
            case DateTime dt: return new DateTimeOffset(dt.ToUniversalTime(), TimeSpan.Zero);
            case DateTimeOffset dto: return dto;
            case string s when s.Length >= 14 && DateTime.TryParseExact(s[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var local):
                var offsetMinutes = s.Length >= 25 && int.TryParse(s[21..25], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var m) ? m : 0;
                return new DateTimeOffset(local, TimeSpan.FromMinutes(offsetMinutes)).ToUniversalTime();
            default: return null;
        }
    }
}
