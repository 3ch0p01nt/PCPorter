namespace PCPorter.Core.Time;

/// <summary>Converts raw forensic timestamps to UTC. Returns null for empty or corrupt values instead of throwing.</summary>
public static class Timestamps
{
    static readonly DateTimeOffset Epoch1601 = new(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Epoch1970 = DateTimeOffset.UnixEpoch;
    static readonly DateTimeOffset Min = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Max = new(2200, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Chromium: microseconds since 1601-01-01 UTC.</summary>
    public static DateTimeOffset? FromWebKit(long micros) => FromTicks(Epoch1601, micros, 10);

    /// <summary>Firefox PRTime: microseconds since 1970-01-01 UTC.</summary>
    public static DateTimeOffset? FromPRTime(long micros) => FromTicks(Epoch1970, micros, 10);

    /// <summary>Windows FILETIME: 100-nanosecond ticks since 1601-01-01 UTC.</summary>
    public static DateTimeOffset? FromFileTime(long ticks) => FromTicks(Epoch1601, ticks, 1);

    static DateTimeOffset? FromTicks(DateTimeOffset epoch, long value, long ticksPerUnit)
    {
        if (value <= 0) return null;
        try
        {
            var result = epoch.AddTicks(checked(value * ticksPerUnit));
            return result < Min || result > Max ? null : result;
        }
        catch (Exception e) when (e is OverflowException or ArgumentOutOfRangeException) { return null; }
    }
}
